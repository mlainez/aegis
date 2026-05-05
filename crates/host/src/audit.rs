//! Append-only audit log. Slice 1: stdlib JSON Lines writer (file or
//! stderr) plus a NullAuditSink for tests. Slice 2 work: tamper-evident
//! signing, Merkle chaining, OpenTelemetry adapter.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub ts: String,
    pub task_id: String,
    pub step: u32,
    pub capability: String,
    pub status: AuditStatus,
    /// Free-form structured detail. Capability-specific shape.
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Allowed,
    Denied,
    Errored,
}

impl AuditEvent {
    pub fn fs(
        task_id: &str,
        step: u32,
        cap: &str,
        path: &Path,
        ok: bool,
        err: Option<String>,
    ) -> Self {
        Self {
            ts: now_iso(),
            task_id: task_id.into(),
            step,
            capability: cap.into(),
            status: if ok {
                AuditStatus::Allowed
            } else {
                AuditStatus::Errored
            },
            detail: serde_json::json!({
                "path": path.display().to_string(),
                "error": err,
            }),
        }
    }

    pub fn http(
        task_id: &str,
        step: u32,
        cap: &str,
        url: &str,
        ok: bool,
        err: Option<String>,
    ) -> Self {
        Self {
            ts: now_iso(),
            task_id: task_id.into(),
            step,
            capability: cap.into(),
            status: if ok {
                AuditStatus::Allowed
            } else {
                AuditStatus::Errored
            },
            detail: serde_json::json!({
                "url": url,
                "error": err,
            }),
        }
    }

    pub fn subprocess(
        task_id: &str,
        step: u32,
        argv: &[String],
        exit: Option<i32>,
        ok: bool,
        err: Option<String>,
    ) -> Self {
        Self {
            ts: now_iso(),
            task_id: task_id.into(),
            step,
            capability: "subprocess.exec".into(),
            status: if ok {
                AuditStatus::Allowed
            } else {
                AuditStatus::Errored
            },
            detail: serde_json::json!({
                "argv": argv,
                "exit": exit,
                "error": err,
            }),
        }
    }

    pub fn env(
        task_id: &str,
        step: u32,
        var_name: &str,
        ok: bool,
        err: Option<String>,
    ) -> Self {
        Self {
            ts: now_iso(),
            task_id: task_id.into(),
            step,
            capability: "env.read".into(),
            status: if ok {
                AuditStatus::Allowed
            } else {
                AuditStatus::Errored
            },
            detail: serde_json::json!({
                "name": var_name,
                "error": err,
            }),
        }
    }

    pub fn denied(task_id: &str, step: u32, cap: &str, target: &str, reason: &str) -> Self {
        Self {
            ts: now_iso(),
            task_id: task_id.into(),
            step,
            capability: cap.into(),
            status: AuditStatus::Denied,
            detail: serde_json::json!({
                "target": target,
                "reason": reason,
            }),
        }
    }
}

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

/// Sink trait. Implementations are expected to be cheap (or async-batched
/// internally) since they're called inline with capability evaluation.
pub trait AuditSink: Send + Sync {
    fn emit(&self, event: AuditEvent);
}

pub struct NullAuditSink;
impl AuditSink for NullAuditSink {
    fn emit(&self, _event: AuditEvent) {}
}

/// Genesis hash for the chain: a 64-character zero string (the
/// hex SHA-256 of "no previous line"). All real-line hashes are
/// 64 hex chars too.
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Hex SHA-256 of a string. Used both when emitting a chained line
/// (to compute its hash for the NEXT line) and when verifying.
fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(s.as_bytes());
    let mut out = String::with_capacity(h.len() * 2);
    for b in h.iter() {
        use std::fmt::Write;
        write!(&mut out, "{:02x}", b).expect("write to String");
    }
    out
}

pub struct JsonlAuditSink {
    path: Option<PathBuf>,
    inner: Mutex<ChainState>,
}

/// Per-sink chain state: writer + monotonic seq + the SHA-256 of
/// the last line written. The next line embeds `aegis_prev_hash =
/// last_hash`; after writing, last_hash advances to SHA-256 of the
/// line we just wrote. Same logic across run boundaries — see
/// `resume_from_tail`.
struct ChainState {
    writer: Box<dyn Write + Send>,
    next_seq: u64,
    last_hash: String,
}

impl JsonlAuditSink {
    /// Append to a file (creating if needed), opening in append
    /// mode. If the file already exists and contains a prior chain,
    /// the chain is resumed: `aegis_seq` continues from the
    /// existing tail's next value and `aegis_prev_hash` of the next
    /// emit chains to the SHA-256 of the existing last line.
    pub fn file(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let (next_seq, last_hash) = resume_from_tail(&path);
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        Ok(Self {
            path: Some(path),
            inner: Mutex::new(ChainState {
                writer: Box::new(f),
                next_seq,
                last_hash,
            }),
        })
    }

    /// Stream to stderr. Stderr is not a persistent log so the
    /// chain doesn't survive across runs, but per-run integrity
    /// still applies — a tampered re-arrangement of stderr lines
    /// is detectable.
    pub fn stderr() -> Self {
        Self {
            path: None,
            inner: Mutex::new(ChainState {
                writer: Box::new(std::io::stderr()),
                next_seq: 1,
                last_hash: GENESIS_PREV_HASH.to_string(),
            }),
        }
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

impl AuditSink for JsonlAuditSink {
    fn emit(&self, event: AuditEvent) {
        let mut state = self.inner.lock().expect("audit lock");
        // Build the line by serializing the event JSON, then
        // splicing in the chain fields (`aegis_seq`,
        // `aegis_prev_hash`). The two fields are part of the
        // hashed line so a verifier sees them as load-bearing data,
        // not provenance metadata it can ignore.
        let Ok(value) = serde_json::to_value(&event) else {
            return;
        };
        let serde_json::Value::Object(mut obj) = value else {
            return;
        };
        obj.insert("aegis_seq".into(), serde_json::json!(state.next_seq));
        obj.insert(
            "aegis_prev_hash".into(),
            serde_json::json!(state.last_hash),
        );
        let Ok(line) = serde_json::to_string(&serde_json::Value::Object(obj)) else {
            return;
        };
        // We swallow IO errors on purpose: an audit-write failure
        // must not be allowed to influence the visible run outcome.
        let _ = writeln!(state.writer, "{}", line);
        let _ = state.writer.flush();
        // Advance chain state. SHA-256 the line we just wrote so
        // the next emit can chain to it.
        state.last_hash = sha256_hex(&line);
        state.next_seq = state.next_seq.saturating_add(1);
    }
}

/// Inspect an existing file's tail to recover the chain state.
/// Returns `(next_seq, last_hash)`. If the file doesn't exist or is
/// empty, returns `(1, GENESIS_PREV_HASH)`.
///
/// A tampered tail (e.g. truncation) shifts the resume point; the
/// continuation hash will mismatch what a future verifier expects,
/// which IS the detection signal — verify will flag it.
fn resume_from_tail(path: &Path) -> (u64, String) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return (1, GENESIS_PREV_HASH.to_string());
    };
    let Some(last_line) = content.lines().rev().find(|l| !l.trim().is_empty()) else {
        return (1, GENESIS_PREV_HASH.to_string());
    };
    let last_seq = serde_json::from_str::<serde_json::Value>(last_line)
        .ok()
        .and_then(|v| v.get("aegis_seq").and_then(|s| s.as_u64()))
        .unwrap_or(0);
    (last_seq.saturating_add(1), sha256_hex(last_line))
}

/// Outcome of `verify_chain`: per-line OK / FAIL with the kind of
/// mismatch.
#[derive(Debug)]
pub struct VerifyReport {
    pub total_lines: usize,
    pub last_seq: u64,
    pub failures: Vec<VerifyFailure>,
}

#[derive(Debug)]
pub struct VerifyFailure {
    pub line_number: usize,
    pub seq: Option<u64>,
    pub reason: String,
}

impl VerifyReport {
    pub fn ok(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Walk a JSONL audit log, recompute the SHA-256 chain, and report
/// any line whose `aegis_prev_hash` doesn't match the SHA-256 of
/// the previous line (or whose `aegis_seq` isn't monotonic +1).
///
/// What this catches:
/// - In-place mutation of any line ⇒ chain breaks at the next line.
/// - Insertion of a line in the middle ⇒ subsequent prev_hashes mismatch.
/// - Removal of a line in the middle ⇒ subsequent prev_hashes mismatch.
/// - Truncation past a sequence number ⇒ if the operator has an
///   external reference for the expected last seq (or the
///   resume_from_tail behavior on a later run produces a
///   detectable jump), tamper is observable.
///
/// What this does NOT catch:
/// - Wholesale replacement with a fresh, internally-consistent
///   chain. Defense: forward to syslog / immutable storage; or
///   store the expected last seq externally.
/// - An attacker with read access who can compute valid hash-chain
///   prev_hash values for fake appends. Defense: ensure the agent
///   can't read the audit log (the protected-path guard refuses
///   any policy that grants read access).
pub fn verify_chain(path: &Path) -> std::io::Result<VerifyReport> {
    let content = std::fs::read_to_string(path)?;
    let mut failures = Vec::new();
    let mut prev_hash = GENESIS_PREV_HASH.to_string();
    let mut expected_seq: u64 = 1;
    let mut total_lines = 0usize;
    let mut last_seq: u64 = 0;
    for (i, raw_line) in content.lines().enumerate() {
        if raw_line.trim().is_empty() {
            continue;
        }
        total_lines += 1;
        let line_number = i + 1;
        let value: serde_json::Value = match serde_json::from_str(raw_line) {
            Ok(v) => v,
            Err(e) => {
                failures.push(VerifyFailure {
                    line_number,
                    seq: None,
                    reason: format!("malformed JSON: {e}"),
                });
                continue;
            }
        };
        let seq = value
            .get("aegis_seq")
            .and_then(|s| s.as_u64())
            .unwrap_or(0);
        let claimed_prev = value
            .get("aegis_prev_hash")
            .and_then(|s| s.as_str())
            .unwrap_or("");
        if seq != expected_seq {
            failures.push(VerifyFailure {
                line_number,
                seq: Some(seq),
                reason: format!(
                    "aegis_seq jump: expected {expected_seq}, got {seq}"
                ),
            });
        }
        if claimed_prev != prev_hash {
            failures.push(VerifyFailure {
                line_number,
                seq: Some(seq),
                reason: format!(
                    "aegis_prev_hash mismatch: chain expected {prev_hash}, line declared {claimed_prev}"
                ),
            });
        }
        prev_hash = sha256_hex(raw_line);
        expected_seq = seq.saturating_add(1);
        last_seq = seq;
    }
    Ok(VerifyReport {
        total_lines,
        last_seq,
        failures,
    })
}
