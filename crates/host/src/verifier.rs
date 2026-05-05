//! Pre-execution verifier. Walks the script source for any reference to
//! a known Aegis capability name and rejects the script before evaluation
//! if the capability is not in `policy.functions.allow`.
//!
//! This is the "compile-time" line of defense. The runtime interceptor
//! is the second line — both must agree before a capability fires. The
//! verifier strips comments and string literals first so capability names
//! quoted as data don't cause false positives.

use std::collections::BTreeSet;

use aegis_policy::Policy;

use crate::CAPABILITIES;

#[derive(Debug, thiserror::Error)]
#[error("verifier: capability {capability:?} called by script but not allowed by policy")]
pub struct VerifierRejection {
    pub capability: String,
}

pub fn verify(source: &str, policy: &Policy) -> Result<(), VerifierRejection> {
    let stripped = strip_strings_and_comments(source);
    let used = scan_capabilities(&stripped);
    for cap in used {
        if policy.check_function(&cap).is_err() {
            return Err(VerifierRejection { capability: cap });
        }
    }
    Ok(())
}

fn scan_capabilities(source: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for cap in CAPABILITIES {
        if contains_word(source, cap.name) || contains_word(source, cap.raw) {
            out.insert(cap.name.to_string());
        }
    }
    out
}

fn contains_word(haystack: &str, word: &str) -> bool {
    let bytes = haystack.as_bytes();
    let needle = word.as_bytes();
    if needle.is_empty() {
        return false;
    }
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let before_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
            let after_ok =
                i + needle.len() == bytes.len() || !is_ident_byte(bytes[i + needle.len()]);
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// "Capability identifier" boundary: alphanumeric, underscore, or dot.
/// Treating `.` as part of the token prevents false matches like
/// `obj.fs.read` matching `fs.read` — the leading `.` is now part of
/// the identifier context, so the boundary check fails.
fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'.'
}

/// Strip Starlark `# line comments`, `"..."`, `'...'`, `"""..."""`,
/// `'''...'''`. Replaces stripped regions with a single space so word
/// boundaries are preserved. Operates on bytes; safe because Starlark
/// identifiers and keywords are ASCII (only stripped regions can contain
/// multibyte UTF-8).
fn strip_strings_and_comments(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'#' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            out.push(b' ');
        } else if c == b'"' || c == b'\'' {
            let q = c;
            let triple = i + 2 < bytes.len() && bytes[i + 1] == q && bytes[i + 2] == q;
            if triple {
                i += 3;
                while i + 2 < bytes.len() {
                    if bytes[i] == q && bytes[i + 1] == q && bytes[i + 2] == q {
                        i += 3;
                        break;
                    }
                    i += 1;
                }
            } else {
                i += 1;
                while i < bytes.len() && bytes[i] != q && bytes[i] != b'\n' {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                if i < bytes.len() && bytes[i] == q {
                    i += 1;
                }
            }
            out.push(b' ');
        } else {
            out.push(c);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

