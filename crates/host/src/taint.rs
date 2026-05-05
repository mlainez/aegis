//! Output-boundary redaction for local-only reads.
//!
//! When the policy marks a resource as local-only (`local_only_read`,
//! `local_only_hosts`, `local_only_commands`, `local_only_vars`), the
//! script may read its value, but the value must never leave the
//! runtime back to the calling host. This module owns the taint
//! registry kept in `HostCtx` and the substring-scan redaction routine
//! applied at every output boundary:
//!
//! - `outcome.printed` — captured `print()` lines that the caller sees
//! - audit-event payload fields (path, host, error message) before
//!   they're forwarded to the audit sink
//! - the MCP server's tool-result text (it joins `outcome.printed`)
//!
//! The redaction is deliberately substring-based and conservative: any
//! exact occurrence of a registered tainted value in an output string
//! is replaced with `[REDACTED]`. This catches the common accidental
//! and naive-extraction cases (printing the value, embedding it in a
//! larger string, returning it as a tool result). It does not prevent
//! deliberate exfiltration via XOR / encoding / chunking — defending
//! against that requires real information-flow tracking through every
//! string operation, which is out of scope for the MVP.
//!
//! Even so, the rule is enforced by the *runtime*, not by asking the
//! model nicely: a prompt cannot bypass the substring scan by
//! rephrasing the script. To exfiltrate, the model must construct an
//! output string that does not contain the secret as a substring,
//! which is a deliberate adversarial step beyond simple "prompt
//! engineering" against the policy.

use std::cell::RefCell;

/// Sentinel inserted in place of a tainted value at output boundaries.
/// Picked to be visually obvious and unlikely to collide with any
/// legitimate token in audit logs.
pub const REDACTED: &str = "[REDACTED]";

/// Minimum tainted-value length we'll register. Below this threshold
/// the substring scan is too noisy (think `"x"` or `""`) and the false
/// positive rate would obscure real outputs without meaningfully
/// improving security.
const MIN_TAINT_LEN: usize = 4;

/// In-context taint store. One per `HostCtx`. Cleared when the
/// evaluation ends because the registry is moved into the redaction
/// pass.
#[derive(Default, Debug)]
pub struct TaintRegistry {
    inner: RefCell<Vec<String>>,
}

impl TaintRegistry {
    /// Register a value as tainted. No-ops if the value is empty,
    /// shorter than the minimum length, or already present (we keep
    /// the registry deduped to keep the per-output scan O(taints *
    /// output_len) bounded).
    pub fn add(&self, value: &str) {
        let trimmed = value.trim();
        if trimmed.len() < MIN_TAINT_LEN {
            return;
        }
        let mut store = self.inner.borrow_mut();
        if !store.iter().any(|s| s == trimmed) {
            store.push(trimmed.to_string());
        }
    }

    pub fn snapshot(&self) -> Vec<String> {
        self.inner.borrow().clone()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.borrow().is_empty()
    }
}

/// Walk a JSON value and redact every string leaf in place. Used to
/// scrub audit-event payload fields before they reach the sink.
pub fn redact_json(value: &mut serde_json::Value, taints: &[String]) {
    if taints.is_empty() {
        return;
    }
    match value {
        serde_json::Value::String(s) => {
            let scrubbed = redact(s, taints);
            if scrubbed != *s {
                *s = scrubbed;
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                redact_json(v, taints);
            }
        }
        serde_json::Value::Object(obj) => {
            for (_k, v) in obj.iter_mut() {
                redact_json(v, taints);
            }
        }
        _ => {}
    }
}

/// Replace every occurrence of every taint in `input` with
/// `[REDACTED]`. Linear in `taints.len() * input.len()` — the registry
/// is kept small so this is cheap in practice. Sorting taints longest-
/// first prevents short-substring redactions from clobbering a longer
/// substring that contained them.
pub fn redact(input: &str, taints: &[String]) -> String {
    if taints.is_empty() {
        return input.to_string();
    }
    let mut sorted: Vec<&String> = taints.iter().collect();
    sorted.sort_by_key(|s| std::cmp::Reverse(s.len()));
    let mut out = input.to_string();
    for t in sorted {
        if t.is_empty() {
            continue;
        }
        if out.contains(t.as_str()) {
            out = out.replace(t.as_str(), REDACTED);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_replaces_full_match() {
        let s = redact("token=sk-abc123secret", &["sk-abc123secret".into()]);
        assert_eq!(s, "token=[REDACTED]");
    }

    #[test]
    fn redact_replaces_each_occurrence() {
        let s = redact("a sk-abc b sk-abc c", &["sk-abc".into()]);
        assert_eq!(s, "a [REDACTED] b [REDACTED] c");
    }

    #[test]
    fn redact_handles_overlapping_taints_longest_first() {
        // If both "secret" and "supersecret" are taints, replacing
        // "secret" first would leave "super[REDACTED]". Longest-first
        // ensures the full "supersecret" is matched.
        let s = redact("found supersecret here", &["secret".into(), "supersecret".into()]);
        assert_eq!(s, "found [REDACTED] here");
    }

    #[test]
    fn redact_noop_when_no_taints_present() {
        let s = redact("nothing tainted", &["sk-abc".into()]);
        assert_eq!(s, "nothing tainted");
    }

    #[test]
    fn registry_skips_too_short() {
        let r = TaintRegistry::default();
        r.add("");
        r.add("ab");
        r.add("abc");
        assert!(r.is_empty());
        r.add("abcd");
        assert_eq!(r.snapshot(), vec!["abcd".to_string()]);
    }

    #[test]
    fn registry_dedups() {
        let r = TaintRegistry::default();
        r.add("aaaa");
        r.add("aaaa");
        assert_eq!(r.snapshot().len(), 1);
    }
}
