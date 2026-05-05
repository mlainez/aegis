//! Integration tests for the `aegis init` policy generator.
//!
//! Spawns the compiled `aegis` binary, asks it to generate a policy
//! for each supported language, and verifies that:
//!   - exit is 0
//!   - stdout is a non-empty TOML body
//!   - the body parses as a valid `PolicyFile` (and resolves
//!     inheritance against `secure-defaults` cleanly)
//!   - the resulting `Policy` is loadable
//!   - language-specific shape is correct (toolchain command appears
//!     in `subprocess.allow_commands`, git destructive ops in
//!     `subprocess.deny_args`, staging/prod files in `filesystem.deny`)

use std::process::Command;

use aegis_policy::{Policy, PolicyFile};

const BIN: &str = env!("CARGO_BIN_EXE_aegis");

fn run_init_to_stdout(lang: &str) -> String {
    let out = Command::new(BIN)
        .args(["init", "--lang", lang, "--output", "-"])
        .output()
        .expect("spawn aegis init");
    assert!(
        out.status.success(),
        "aegis init --lang {lang} failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("stdout is utf-8")
}

fn parse_and_resolve(toml_body: &str) -> PolicyFile {
    let raw = PolicyFile::from_toml_str(toml_body).expect("policy parses as toml");
    raw.resolve_inheritance().expect("secure-defaults resolves")
}

#[test]
fn every_language_produces_a_valid_policy() {
    for lang in ["python", "node", "ruby", "rust", "go"] {
        let body = run_init_to_stdout(lang);
        assert!(
            body.contains("inherits = \"secure-defaults\""),
            "{lang} template missing inherits"
        );
        let resolved = parse_and_resolve(&body);
        // Resolved policy loads — secure-defaults' deny lists merged in.
        Policy::from_file(resolved, std::env::temp_dir())
            .unwrap_or_else(|e| panic!("{lang} policy fails to load: {e}"));
    }
}

#[test]
fn every_language_blocks_git_destructive_ops() {
    for lang in ["python", "node", "ruby", "rust", "go"] {
        let body = run_init_to_stdout(lang);
        let file = parse_and_resolve(&body);
        let git_args = file
            .subprocess
            .deny_args
            .get("git")
            .unwrap_or_else(|| panic!("{lang} missing git deny_args"));
        for required in ["push --force", "reset --hard", "filter-branch"] {
            assert!(
                git_args.iter().any(|p| p == required),
                "{lang} git deny_args missing {required}"
            );
        }
    }
}

#[test]
fn every_language_blocks_prod_and_staging_config_files() {
    for lang in ["python", "node", "ruby", "rust", "go"] {
        let body = run_init_to_stdout(lang);
        let file = parse_and_resolve(&body);
        // At least the .env.production / .env.staging / .env.qa
        // pattern should be in filesystem.deny — these are commonly
        // checked-in by mistake and the preset doesn't cover them
        // specifically.
        let deny = &file.filesystem.deny;
        for required in ["**/.env.production", "**/.env.staging", "**/.env.qa"] {
            assert!(
                deny.iter().any(|p| p == required),
                "{lang} filesystem.deny missing {required}"
            );
        }
    }
}

#[test]
fn python_template_allows_python_toolchain() {
    let body = run_init_to_stdout("python");
    let file = parse_and_resolve(&body);
    let allow = &file.subprocess.allow_commands;
    for required in ["python3", "pip", "pytest", "ruff"] {
        assert!(allow.iter().any(|c| c == required), "python missing {required}");
    }
}

#[test]
fn node_template_allows_node_toolchain_and_blocks_publish() {
    let body = run_init_to_stdout("node");
    let file = parse_and_resolve(&body);
    let allow = &file.subprocess.allow_commands;
    for required in ["node", "npm", "tsc", "eslint"] {
        assert!(allow.iter().any(|c| c == required), "node missing {required}");
    }
    // npm publish should be blocked by default.
    let npm_args = file.subprocess.deny_args.get("npm").expect("npm deny_args");
    assert!(npm_args.iter().any(|p| p == "publish"));
}

#[test]
fn ruby_template_blocks_destructive_rails_db_tasks() {
    let body = run_init_to_stdout("ruby");
    let file = parse_and_resolve(&body);
    let rails_args = file
        .subprocess
        .deny_args
        .get("rails")
        .expect("rails deny_args");
    for required in ["db:drop", "db:reset"] {
        assert!(
            rails_args.iter().any(|p| p == required),
            "ruby rails deny_args missing {required}"
        );
    }
}

#[test]
fn rust_template_blocks_cargo_publish_and_yank() {
    let body = run_init_to_stdout("rust");
    let file = parse_and_resolve(&body);
    let cargo_args = file
        .subprocess
        .deny_args
        .get("cargo")
        .expect("cargo deny_args");
    for required in ["publish", "yank"] {
        assert!(
            cargo_args.iter().any(|p| p == required),
            "rust cargo deny_args missing {required}"
        );
    }
}

#[test]
fn unknown_language_is_rejected() {
    let out = Command::new(BIN)
        .args(["init", "--lang", "cobol", "--output", "-"])
        .output()
        .expect("spawn aegis init");
    assert!(!out.status.success(), "unknown lang must error");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("python") && stderr.contains("ruby"),
        "error must hint at supported languages, got: {stderr}"
    );
}

#[test]
fn refuses_to_overwrite_existing_file_without_force() {
    let dir = tempdir();
    let target = dir.join("aegis.toml");
    std::fs::write(&target, "# pre-existing").unwrap();

    let out = Command::new(BIN)
        .args([
            "init",
            "--lang",
            "python",
            "--output",
            target.to_str().unwrap(),
        ])
        .output()
        .expect("spawn aegis init");
    assert!(!out.status.success(), "should refuse overwrite");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("already exists"));
    // Original content preserved.
    let preserved = std::fs::read_to_string(&target).unwrap();
    assert_eq!(preserved, "# pre-existing");
}

#[test]
fn force_overwrites_existing_file() {
    let dir = tempdir();
    let target = dir.join("aegis.toml");
    std::fs::write(&target, "# pre-existing").unwrap();

    let out = Command::new(BIN)
        .args([
            "init",
            "--lang",
            "python",
            "--output",
            target.to_str().unwrap(),
            "--force",
        ])
        .output()
        .expect("spawn aegis init");
    assert!(out.status.success(), "force should succeed");
    let written = std::fs::read_to_string(&target).unwrap();
    assert!(written.contains("inherits = \"secure-defaults\""));
}

fn tempdir() -> std::path::PathBuf {
    let base = std::env::temp_dir().join(format!(
        "aegis_init_test_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&base).unwrap();
    base
}
