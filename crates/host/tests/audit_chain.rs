//! Tests for the SHA-256-chained audit log + verify_chain helper.
//! Exercises the JsonlAuditSink emit path, the resume-from-tail
//! behavior across runs, and tamper detection in `verify_chain`.

use std::path::PathBuf;
use std::sync::Arc;

use aegis_host::{
    verify_chain, AuditEvent, AuditSink, JsonlAuditSink, Runner, GENESIS_PREV_HASH,
};
use aegis_policy::{Policy, PolicyFile};

fn fresh_log(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aegis_audit_chain_{}_{}_{}",
        prefix,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("audit.jsonl")
}

fn read_lines(path: &PathBuf) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(String::from)
        .collect()
}

#[test]
fn first_emit_uses_genesis_prev_hash_and_seq_one() {
    let path = fresh_log("first");
    let sink = JsonlAuditSink::file(&path).unwrap();
    sink.emit(AuditEvent::env("t", 1, "PATH", true, None));

    let lines = read_lines(&path);
    assert_eq!(lines.len(), 1);
    let v: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    assert_eq!(v["aegis_seq"].as_u64(), Some(1));
    assert_eq!(
        v["aegis_prev_hash"].as_str(),
        Some(GENESIS_PREV_HASH)
    );
}

#[test]
fn each_subsequent_emit_chains_to_previous_line_hash() {
    let path = fresh_log("chain");
    let sink = JsonlAuditSink::file(&path).unwrap();
    for i in 0..5 {
        sink.emit(AuditEvent::env("t", i + 1, "PATH", true, None));
    }
    drop(sink);

    let report = verify_chain(&path).unwrap();
    assert_eq!(report.total_lines, 5);
    assert_eq!(report.last_seq, 5);
    assert!(report.ok(), "fresh chain should verify clean: {:?}", report.failures);
}

#[test]
fn verify_detects_in_place_mutation() {
    let path = fresh_log("mutate");
    let sink = JsonlAuditSink::file(&path).unwrap();
    for i in 0..3 {
        sink.emit(AuditEvent::env("t", i + 1, "PATH", true, None));
    }
    drop(sink);

    // Tamper: rewrite line 2 with a different (still parseable)
    // event. The chain breaks at the mutated line because its
    // SHA-256 (used by line 3 as prev_hash) changed.
    let lines = read_lines(&path);
    let mut mutated = lines.clone();
    let mut v: serde_json::Value = serde_json::from_str(&mutated[1]).unwrap();
    v.as_object_mut().unwrap().insert("ts".into(), serde_json::json!("TAMPERED"));
    mutated[1] = serde_json::to_string(&v).unwrap();
    std::fs::write(&path, mutated.join("\n") + "\n").unwrap();

    let report = verify_chain(&path).unwrap();
    assert!(!report.ok(), "verify should flag the mutation");
    let any_hash_failure = report
        .failures
        .iter()
        .any(|f| f.reason.contains("aegis_prev_hash mismatch"));
    assert!(
        any_hash_failure,
        "expected a prev_hash mismatch in failures: {:?}",
        report.failures
    );
}

#[test]
fn verify_detects_line_removal() {
    let path = fresh_log("remove");
    let sink = JsonlAuditSink::file(&path).unwrap();
    for i in 0..4 {
        sink.emit(AuditEvent::env("t", i + 1, "PATH", true, None));
    }
    drop(sink);

    // Delete line 2.
    let lines = read_lines(&path);
    let mut shortened = lines.clone();
    shortened.remove(1);
    std::fs::write(&path, shortened.join("\n") + "\n").unwrap();

    let report = verify_chain(&path).unwrap();
    assert!(!report.ok(), "verify should flag the removal");
}

#[test]
fn verify_detects_seq_jump() {
    let path = fresh_log("jump");
    // Hand-craft a log where the seqs aren't monotonic.
    let l1 = serde_json::json!({
        "ts": "2026-05-05T00:00:00Z",
        "task_id": "t",
        "step": 1,
        "capability": "fs.read",
        "status": "allowed",
        "detail": {},
        "aegis_seq": 1,
        "aegis_prev_hash": GENESIS_PREV_HASH,
    });
    let l1_str = serde_json::to_string(&l1).unwrap();
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(l1_str.as_bytes());
    let l1_hash = hasher.finalize();
    let l1_hex: String = l1_hash.iter().map(|b| format!("{:02x}", b)).collect();
    // Jump from seq 1 to seq 5 (skipping 2, 3, 4) but with a
    // prev_hash that DOES match — this isolates the seq check.
    let l2 = serde_json::json!({
        "ts": "2026-05-05T00:00:01Z",
        "task_id": "t",
        "step": 2,
        "capability": "fs.read",
        "status": "allowed",
        "detail": {},
        "aegis_seq": 5,
        "aegis_prev_hash": l1_hex,
    });
    let l2_str = serde_json::to_string(&l2).unwrap();
    std::fs::write(&path, format!("{l1_str}\n{l2_str}\n")).unwrap();

    let report = verify_chain(&path).unwrap();
    assert!(!report.ok(), "verify should flag the seq jump");
    let any_seq_failure = report
        .failures
        .iter()
        .any(|f| f.reason.contains("aegis_seq jump"));
    assert!(any_seq_failure, "got: {:?}", report.failures);
}

#[test]
fn resume_across_runs_continues_chain() {
    let path = fresh_log("resume");
    {
        let sink = JsonlAuditSink::file(&path).unwrap();
        sink.emit(AuditEvent::env("t1", 1, "PATH", true, None));
        sink.emit(AuditEvent::env("t1", 2, "USER", true, None));
    }
    // Open a fresh sink against the same file. Should pick up the
    // chain at seq=3 with prev_hash = SHA-256 of the previous
    // last line.
    {
        let sink = JsonlAuditSink::file(&path).unwrap();
        sink.emit(AuditEvent::env("t2", 1, "HOME", true, None));
    }

    let report = verify_chain(&path).unwrap();
    assert!(
        report.ok(),
        "chain should be intact across runs: {:?}",
        report.failures
    );
    assert_eq!(report.total_lines, 3);
    assert_eq!(report.last_seq, 3);
}

#[test]
fn full_runner_emits_chained_log() {
    // End-to-end: drive a Runner against a real policy that does a
    // few effecting calls, point its audit at a chained file, then
    // verify.
    let log_path = fresh_log("e2e");
    let workdir = log_path.parent().unwrap().to_path_buf();
    let target_dir = workdir.join("scratch");
    std::fs::create_dir_all(&target_dir).unwrap();
    let scratch_str = target_dir.to_string_lossy().replace('\\', "/");

    let toml = format!(
        r#"
[filesystem]
write_allow = ["{scratch_str}/**"]
"#
    );
    let file = PolicyFile::from_toml_str(&toml).unwrap();
    let policy = Policy::from_file(file, workdir.clone()).unwrap();
    let audit: Arc<dyn AuditSink> = Arc::new(JsonlAuditSink::file(&log_path).unwrap());
    let runner = Runner::new(policy).with_audit(audit);

    let src = format!(
        r#"fs.write("{scratch_str}/a.txt", "1")
fs.write("{scratch_str}/b.txt", "2")
fs.write("{scratch_str}/c.txt", "3")
"#
    );
    runner.run("e2e", &src, "test.star").unwrap();

    let report = verify_chain(&log_path).unwrap();
    assert!(
        report.ok(),
        "full Runner audit chain should verify clean: {:?}",
        report.failures
    );
    // 3 emit events expected (one per fs.write).
    assert_eq!(report.total_lines, 3, "expected 3 audit lines");
}
