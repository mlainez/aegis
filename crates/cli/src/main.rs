//! `aegis` CLI. Two subcommands:
//!
//! - `aegis run --policy <toml> <script.star>` — load a policy and a
//!   Starlark script, run the script under capability-typed enforcement.
//! - `aegis init --lang <python|node|ruby|rust|go> [--output PATH]` —
//!   emit a starter policy file inheriting `secure-defaults`, with a
//!   language-appropriate toolchain allowlist and git-destructive /
//!   staging-config denies.
//!
//! Run exit codes:
//!   0 — script ran to completion
//!   1 — script error (Starlark eval failure)
//!   2 — policy violation at runtime
//!   3 — pre-execution verifier rejection
//!   4 — confirm hook denied
//!   5 — i/o or configuration error
//!   6 — runtime cap exceeded (wall-time deadline / call-stack)

mod init;

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use aegis_host::{
    AegisError, AllowAllConfirm, AuditSink, ConfirmDecision, ConfirmHook, ConfirmRequest,
    DenyAllConfirm, JsonlAuditSink, Runner,
};
use aegis_policy::Policy;
use clap::{Parser, Subcommand};

use crate::init::Lang;

#[derive(Parser, Debug)]
#[command(name = "aegis", version, about = "Run Starlark agent scripts under capability-typed policy")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run a Starlark script under a policy.
    Run(RunArgs),
    /// Generate a starter policy file for a project language.
    Init(InitArgs),
    /// Inspect or validate a policy file.
    Policy(PolicyCli),
    /// Inspect or verify the audit log.
    Audit(AuditCli),
}

#[derive(Parser, Debug)]
struct AuditCli {
    #[command(subcommand)]
    command: AuditCommand,
}

#[derive(Subcommand, Debug)]
enum AuditCommand {
    /// Walk a JSONL audit log and verify the SHA-256 chain. Each
    /// entry's `aegis_prev_hash` is checked against the SHA-256 of
    /// the previous line, and `aegis_seq` is checked for monotonic
    /// +1 progression. Reports per-line failures with the kind of
    /// mismatch. Exits 0 if the chain is intact, non-zero
    /// otherwise.
    Verify(AuditTargetArgs),
}

#[derive(Parser, Debug)]
struct AuditTargetArgs {
    /// Path to the JSONL audit log to verify.
    log: PathBuf,
}

#[derive(Parser, Debug)]
struct PolicyCli {
    #[command(subcommand)]
    command: PolicyCommand,
}

#[derive(Subcommand, Debug)]
enum PolicyCommand {
    /// Parse a policy file, resolve inheritance, run all load-time
    /// safety checks (including the self-writable guard), and exit 0
    /// on success. Useful as a CI lint step. Non-zero exit + a
    /// human-readable error on failure.
    Validate(PolicyTargetArgs),
    /// Print a human-readable summary of a policy: effective
    /// capabilities (derived from populated resource sections), all
    /// allow/deny rules, declared tools with routing hints, runtime
    /// caps, confirm-gated capabilities. Exits 0 on success.
    Show(PolicyTargetArgs),
}

#[derive(Parser, Debug)]
struct PolicyTargetArgs {
    /// Path to the policy TOML file.
    policy: PathBuf,
}

#[derive(Parser, Debug)]
struct RunArgs {
    /// Path to the policy TOML file. If omitted, falls back to the
    /// built-in `secure-defaults` baseline (denies every effecting
    /// capability) and prints a banner explaining how to grant any.
    #[arg(short, long)]
    policy: Option<PathBuf>,

    /// Starlark script to run.
    script: PathBuf,

    /// Append audit events to this file (JSON Lines). Defaults to stderr.
    #[arg(long)]
    audit_log: Option<PathBuf>,

    /// Task id stamped into audit events. Defaults to the script filename.
    #[arg(long)]
    task_id: Option<String>,

    /// Auto-confirm every confirm-per-call capability without prompting.
    /// Useful in tests/CI; refuse in production.
    #[arg(long)]
    yes: bool,
}

#[derive(Parser, Debug)]
struct InitArgs {
    /// Project language. Determines the toolchain allowlist and
    /// project-layout read/write_allow defaults.
    #[arg(short, long)]
    lang: Lang,

    /// Output path. Defaults to `aegis.toml` in the current directory.
    /// Use `-` to write to stdout instead.
    #[arg(short, long, default_value = "aegis.toml")]
    output: String,

    /// Overwrite an existing file at `--output`. Refused by default
    /// to protect a pre-existing policy.
    #[arg(short, long)]
    force: bool,
}

fn main() -> ExitCode {
    match dispatch() {
        Ok(()) => ExitCode::from(0),
        Err(e) => {
            eprintln!("aegis: {e}");
            match e {
                CliError::Aegis(AegisError::Verifier(_)) => ExitCode::from(3),
                CliError::Aegis(AegisError::Policy(_)) => ExitCode::from(2),
                CliError::Aegis(AegisError::ConfirmDenied(_)) => ExitCode::from(4),
                CliError::Aegis(AegisError::Starlark(_)) => ExitCode::from(1),
                CliError::Aegis(AegisError::RuntimeLimit(_)) => ExitCode::from(6),
                CliError::Aegis(AegisError::Io(_)) | CliError::Io(_) | CliError::Other(_) => {
                    ExitCode::from(5)
                }
                CliError::Aegis(AegisError::Other(_)) => ExitCode::from(5),
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("{0}")]
    Aegis(#[from] AegisError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

fn dispatch() -> Result<(), CliError> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run(args) => run(args),
        Command::Init(args) => init_cmd(args),
        Command::Policy(p) => match p.command {
            PolicyCommand::Validate(a) => policy_validate(a),
            PolicyCommand::Show(a) => policy_show(a),
        },
        Command::Audit(a) => match a.command {
            AuditCommand::Verify(args) => audit_verify(args),
        },
    }
}

fn audit_verify(args: AuditTargetArgs) -> Result<(), CliError> {
    let report = aegis_host::verify_chain(&args.log).map_err(CliError::Io)?;
    if report.ok() {
        println!(
            "OK: {} entries, chain valid (last seq = {}).",
            report.total_lines, report.last_seq
        );
        return Ok(());
    }
    eprintln!(
        "audit: chain BROKEN — {} failure(s) across {} entries",
        report.failures.len(),
        report.total_lines
    );
    for f in &report.failures {
        let seq = f
            .seq
            .map(|s| format!("seq={s}"))
            .unwrap_or_else(|| "seq=?".to_string());
        eprintln!("  line {} ({}): {}", f.line_number, seq, f.reason);
    }
    Err(CliError::Other(format!(
        "audit log {:?} failed verification ({} failures)",
        args.log,
        report.failures.len()
    )))
}

fn policy_validate(args: PolicyTargetArgs) -> Result<(), CliError> {
    let policy = Policy::load(&args.policy)
        .map_err(|e| CliError::Other(format!("validation failed: {e}")))?;
    let n = policy.effective_functions().len();
    println!(
        "OK: {} parses, resolves, passes self-writable guard. {n} capability(ies) enabled.",
        args.policy.display()
    );
    Ok(())
}

fn policy_show(args: PolicyTargetArgs) -> Result<(), CliError> {
    let policy = Policy::load(&args.policy)
        .map_err(|e| CliError::Other(format!("load policy {:?}: {e}", args.policy)))?;
    let file = policy.file_snapshot();

    println!("# policy: {}", args.policy.display());
    if let Some(name) = &file.name {
        println!("# name:   {name}");
    }
    if let Some(desc) = &file.description {
        println!("# desc:   {desc}");
    }
    if let Some(parent) = &file.inherits {
        println!("# inherits: {parent}");
    }
    println!();

    let effective = policy.effective_functions();
    println!("[capabilities]   (derived from populated resource sections)");
    if effective.is_empty() {
        println!("  (none — every effecting call will be denied)");
    } else {
        for cap in &effective {
            println!("  - {cap}");
        }
    }
    println!();

    print_section_list("[filesystem].read_allow", &file.filesystem.read_allow);
    print_section_list("[filesystem].local_only_read", &file.filesystem.local_only_read);
    print_section_list("[filesystem].write_allow", &file.filesystem.write_allow);
    print_section_list("[filesystem].delete_allow", &file.filesystem.delete_allow);
    print_section_list("[filesystem].deny", &file.filesystem.deny);

    print_section_list("[network].http_get_allow", &file.network.http_get_allow);
    print_section_list("[network].http_post_allow", &file.network.http_post_allow);
    print_section_list("[network].http_put_allow", &file.network.http_put_allow);
    print_section_list("[network].http_patch_allow", &file.network.http_patch_allow);
    print_section_list("[network].http_delete_allow", &file.network.http_delete_allow);
    print_section_list("[network].local_only_hosts", &file.network.local_only_hosts);
    print_section_list("[network].deny_hosts", &file.network.deny_hosts);
    print_section_list("[network].deny_ips", &file.network.deny_ips);

    print_section_list("[environment].allow_vars", &file.environment.allow_vars);
    print_section_list(
        "[environment].local_only_vars",
        &file.environment.local_only_vars,
    );
    print_section_list("[environment].deny_vars", &file.environment.deny_vars);

    print_section_list("[subprocess].allow_commands", &file.subprocess.allow_commands);
    print_section_list(
        "[subprocess].local_only_commands",
        &file.subprocess.local_only_commands,
    );
    print_section_list("[subprocess].deny_commands", &file.subprocess.deny_commands);
    if !file.subprocess.deny_args.is_empty() {
        println!("[subprocess.deny_args]");
        for (cmd, patterns) in &file.subprocess.deny_args {
            println!("  - {cmd}: {patterns:?}");
        }
        println!();
    }

    if file.runtime.max_seconds.is_some() || file.runtime.max_callstack_size.is_some() {
        println!("[runtime]");
        if let Some(s) = file.runtime.max_seconds {
            println!("  - max_seconds: {s}");
        }
        if let Some(n) = file.runtime.max_callstack_size {
            println!("  - max_callstack_size: {n}");
        }
        println!();
    }

    if !file.tools.is_empty() {
        println!("[tools]");
        for (name, record) in &file.tools {
            println!("  - {name}: {:?}", record.capabilities);
            if let Some(url) = &record.backend_url {
                println!("      → {} {url}", record.method());
            }
            if let Some(d) = &record.description {
                println!("      ({d})");
            }
        }
        println!();
    }

    if !file.confirm_per_call.is_empty() {
        println!("[confirm_per_call]");
        for cap in &file.confirm_per_call {
            println!("  - {cap}");
        }
        println!();
    }

    Ok(())
}

fn print_section_list(label: &str, items: &[String]) {
    if items.is_empty() {
        return;
    }
    println!("{label}");
    for item in items {
        println!("  - {item}");
    }
    println!();
}

fn init_cmd(args: InitArgs) -> Result<(), CliError> {
    let body = init::generate(args.lang);
    if args.output == "-" {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(body.as_bytes())?;
        return Ok(());
    }
    let path = PathBuf::from(&args.output);
    if path.exists() && !args.force {
        return Err(CliError::Other(format!(
            "{path:?} already exists; pass --force to overwrite"
        )));
    }
    std::fs::write(&path, &body)?;
    eprintln!(
        "aegis: wrote {path} ({lang}). Review the file, then run with --policy {path}.",
        path = path.display(),
        lang = args.lang.name(),
    );
    Ok(())
}

fn run(args: RunArgs) -> Result<(), CliError> {
    let policy = match args.policy.as_deref() {
        Some(path) => Policy::load(path)
            .map_err(|e| CliError::Other(format!("load policy {path:?}: {e}")))?,
        None => {
            print_no_policy_banner();
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            Policy::secure_defaults_at(cwd)
                .map_err(|e| CliError::Other(format!("load secure-defaults baseline: {e}")))?
        }
    };
    let script = std::fs::read_to_string(&args.script)?;
    let task_id = args
        .task_id
        .unwrap_or_else(|| {
            args.script
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("script.star")
                .to_string()
        });

    let audit: Arc<dyn AuditSink> = match &args.audit_log {
        Some(path) => {
            // Refuse to start if the audit log path is reachable to
            // the agent — write/delete would let it fabricate or
            // erase history; read would let it compute valid
            // hash-chain prev_hash values for forged appends. The
            // self-writable guard's audit-log sibling.
            let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
            policy
                .guard_audit_log(&canon)
                .map_err(|e| CliError::Other(format!("audit-log path is reachable to the agent: {e}")))?;
            Arc::new(JsonlAuditSink::file(path)?)
        }
        None => Arc::new(JsonlAuditSink::stderr()),
    };
    let confirm: Arc<dyn ConfirmHook> = if args.yes {
        Arc::new(AllowAllConfirm)
    } else if std::io::stderr().is_terminal() && std::io::stdin().is_terminal() {
        Arc::new(TtyConfirm)
    } else {
        Arc::new(DenyAllConfirm)
    };

    let runner = Runner::new(policy)
        .with_audit(audit)
        .with_confirm_hook(confirm);

    let outcome = runner.run(&task_id, &script, args.script.to_string_lossy().as_ref())?;
    for line in &outcome.printed {
        println!("{line}");
    }
    Ok(())
}

/// Loud-and-safe banner shown when `aegis run` fires without `--policy`.
/// Stderr only so it doesn't pollute structured stdout output.
fn print_no_policy_banner() {
    eprintln!("aegis: no --policy provided; using built-in `secure-defaults` baseline.");
    eprintln!("       This baseline DENIES every fs / net / subprocess / env capability.");
    eprintln!("       Pure computation and print() still work; every effect will fail.");
    eprintln!("       To grant capabilities, generate a starter policy:");
    eprintln!();
    eprintln!("           aegis init --lang python   # or node, ruby, rust, go");
    eprintln!();
    eprintln!("       Then run with `--policy aegis.toml`. See examples/policies/ for templates.");
}

struct TtyConfirm;
impl ConfirmHook for TtyConfirm {
    fn confirm(&self, request: &ConfirmRequest) -> ConfirmDecision {
        let mut stderr = std::io::stderr();
        let _ = writeln!(
            stderr,
            "[aegis] confirm {} for task {}: {}",
            request.capability, request.task_id, request.summary
        );
        let _ = write!(stderr, "        allow? [y/N] ");
        let _ = stderr.flush();
        let mut line = String::new();
        let stdin = std::io::stdin();
        let mut handle = stdin.lock();
        if handle.read_line(&mut line).is_err() {
            return ConfirmDecision::Deny;
        }
        let trimmed = line.trim().to_ascii_lowercase();
        if trimmed == "y" || trimmed == "yes" {
            ConfirmDecision::Allow
        } else {
            ConfirmDecision::Deny
        }
    }
}
