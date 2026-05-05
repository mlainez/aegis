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
    }
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
        Some(path) => Arc::new(JsonlAuditSink::file(path)?),
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
