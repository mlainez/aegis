//! Aegis host: embeds Starlark, registers capability-typed builtins,
//! enforces a [`Policy`] at every effecting call, and emits an audit log.
//!
//! The integration shape is:
//!
//! 1. Caller builds a [`Runner`] with a loaded `Policy`, an audit sink,
//!    and a [`ConfirmHook`].
//! 2. Caller hands a Starlark source string to [`Runner::run`].
//! 3. Runner runs the pre-execution verifier (rejects calls to
//!    not-allowed builtins before any code executes).
//! 4. Runner evaluates the script. Each capability-gated builtin
//!    re-checks the policy at call time and emits an audit event.

use std::cell::RefCell;
use std::path::Path;
use std::sync::Arc;

use aegis_policy::Policy;
pub use aegis_policy::PolicyError;
use starlark::any::ProvidesStaticType;
use starlark::environment::{GlobalsBuilder, LibraryExtension, Module};
use starlark::eval::Evaluator;
use starlark::syntax::{AstModule, Dialect};
use starlark::starlark_module;
use starlark::values::none::NoneType;
use starlark::values::list::UnpackList;
use thiserror::Error;

pub mod audit;
pub mod confirm;
pub mod verifier;

pub use audit::{AuditEvent, AuditSink, JsonlAuditSink, NullAuditSink};
pub use confirm::{AllowAllConfirm, ConfirmDecision, ConfirmHook, ConfirmRequest, DenyAllConfirm};

/// All known capability names. Slice 1 ships these four. Each maps to a
/// Starlark builtin of the same name (snake_case).
pub const CAPABILITIES: &[&str] = &[
    "fs_read",
    "fs_write",
    "subprocess_exec",
    "net_http_get",
];

#[derive(Debug, Error)]
pub enum AegisError {
    #[error("starlark error: {0}")]
    Starlark(String),
    #[error("policy violation: {0}")]
    Policy(String),
    #[error("verifier rejected script: {0}")]
    Verifier(String),
    #[error("confirm hook denied capability {0}")]
    ConfirmDenied(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

impl From<PolicyError> for AegisError {
    fn from(e: PolicyError) -> Self {
        AegisError::Policy(e.to_string())
    }
}

/// Captured error stashed on HostCtx so Runner::run can recover the
/// original error kind after Starlark wraps everything in its own type.
#[derive(Clone, Debug)]
struct CapturedError {
    kind: CapturedKind,
    message: String,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum CapturedKind {
    Policy,
    ConfirmDenied,
}

/// Outcome of running a script.
#[derive(Debug)]
pub struct RunOutcome {
    pub printed: Vec<String>,
}

/// Top-level entry point. Configure once, run many scripts.
pub struct Runner {
    policy: Arc<Policy>,
    audit: Arc<dyn AuditSink>,
    confirm: Arc<dyn ConfirmHook>,
}

impl Runner {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy: Arc::new(policy),
            audit: Arc::new(NullAuditSink),
            confirm: Arc::new(DenyAllConfirm),
        }
    }

    pub fn with_audit(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.audit = sink;
        self
    }

    pub fn with_confirm_hook(mut self, hook: Arc<dyn ConfirmHook>) -> Self {
        self.confirm = hook;
        self
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Parse, verify, and evaluate `source`. `task_id` lands in every
    /// audit event for provenance.
    pub fn run(&self, task_id: &str, source: &str, script_name: &str) -> Result<RunOutcome, AegisError> {
        verifier::verify(source, &self.policy)
            .map_err(|e| AegisError::Verifier(e.to_string()))?;

        let ast = AstModule::parse(script_name, source.to_string(), &Dialect::Standard)
            .map_err(|e| AegisError::Starlark(e.to_string()))?;

        let ctx = HostCtx {
            policy: self.policy.clone(),
            audit: self.audit.clone(),
            confirm: self.confirm.clone(),
            task_id: task_id.to_string(),
            step: RefCell::new(0),
            printed: RefCell::new(Vec::new()),
            captured: RefCell::new(None),
        };

        let globals = GlobalsBuilder::extended_by(&[
            LibraryExtension::Print,
            LibraryExtension::StructType,
            LibraryExtension::NamespaceType,
            LibraryExtension::Json,
            LibraryExtension::Map,
            LibraryExtension::Filter,
            LibraryExtension::Debug,
        ])
        .with(register_builtins)
        .build();
        let module = Module::new();
        let eval_result = {
            let print_handler = PrintCapture { ctx: &ctx };
            let mut eval = Evaluator::new(&module);
            eval.set_print_handler(&print_handler);
            eval.extra = Some(&ctx);
            eval.eval_module(ast, &globals)
                .map(|_| ())
                .map_err(|e| e.to_string())
        };
        let captured = ctx.captured.borrow_mut().take();
        let printed = ctx.printed.into_inner();

        if let Err(starlark_msg) = eval_result {
            // If a builtin captured a typed error before Starlark wrapped
            // it, surface that — the kind drives exit-code mapping.
            return Err(match captured {
                Some(c) => match c.kind {
                    CapturedKind::Policy => AegisError::Policy(c.message),
                    CapturedKind::ConfirmDenied => AegisError::ConfirmDenied(c.message),
                },
                None => AegisError::Starlark(starlark_msg),
            });
        }

        Ok(RunOutcome { printed })
    }
}

/// Per-evaluation context handed to builtins via `Evaluator::extra`.
#[derive(ProvidesStaticType)]
struct HostCtx {
    policy: Arc<Policy>,
    audit: Arc<dyn AuditSink>,
    confirm: Arc<dyn ConfirmHook>,
    task_id: String,
    step: RefCell<u32>,
    printed: RefCell<Vec<String>>,
    captured: RefCell<Option<CapturedError>>,
}

impl HostCtx {
    fn next_step(&self) -> u32 {
        let mut s = self.step.borrow_mut();
        *s += 1;
        *s
    }

    fn require_confirm(&self, capability: &str, summary: String) -> Result<(), AegisError> {
        if !self.policy.confirm_required(capability) {
            return Ok(());
        }
        let req = ConfirmRequest {
            task_id: self.task_id.clone(),
            capability: capability.to_string(),
            summary: summary.clone(),
        };
        match self.confirm.confirm(&req) {
            ConfirmDecision::Allow => Ok(()),
            ConfirmDecision::Deny => {
                let step = *self.step.borrow();
                self.emit(AuditEvent::denied(
                    &self.task_id,
                    step,
                    capability,
                    &summary,
                    "confirm hook denied",
                ));
                let msg = capability.to_string();
                self.capture(CapturedKind::ConfirmDenied, &msg);
                Err(AegisError::ConfirmDenied(msg))
            }
        }
    }

    fn emit(&self, event: AuditEvent) {
        self.audit.emit(event);
    }

    fn capture(&self, kind: CapturedKind, message: &str) {
        *self.captured.borrow_mut() = Some(CapturedError {
            kind,
            message: message.to_string(),
        });
    }
}

struct PrintCapture<'a> {
    ctx: &'a HostCtx,
}
impl<'a> starlark::PrintHandler for PrintCapture<'a> {
    fn println(&self, text: &str) -> starlark::Result<()> {
        self.ctx.printed.borrow_mut().push(text.to_string());
        Ok(())
    }
}

fn ctx_from_eval<'a, 'v>(eval: &'a Evaluator<'v, '_, '_>) -> anyhow::Result<&'a HostCtx> {
    eval.extra
        .ok_or_else(|| anyhow::anyhow!("aegis: missing host context"))?
        .downcast_ref::<HostCtx>()
        .ok_or_else(|| anyhow::anyhow!("aegis: wrong context type in evaluator extra slot"))
}

#[starlark_module]
fn register_builtins(builder: &mut GlobalsBuilder) {
    /// Read a UTF-8 file. Path is resolved against the policy root.
    /// Capability: `fs_read`.
    fn fs_read<'v>(path: &str, eval: &mut Evaluator<'v, '_, '_>) -> anyhow::Result<String> {
        let ctx = ctx_from_eval(eval)?;
        let step = ctx.next_step();
        match ctx.policy.check_fs_read(Path::new(path)) {
            Ok(resolved) => {
                ctx.require_confirm("fs_read", format!("read {}", resolved.display()))?;
                let result = std::fs::read_to_string(&resolved);
                ctx.emit(AuditEvent::fs(
                    &ctx.task_id,
                    step,
                    "fs_read",
                    &resolved,
                    result.is_ok(),
                    result.as_ref().err().map(|e| e.to_string()),
                ));
                Ok(result?)
            }
            Err(e) => {
                let msg = e.to_string();
                ctx.emit(AuditEvent::denied(
                    &ctx.task_id,
                    step,
                    "fs_read",
                    &format!("path={path}"),
                    &msg,
                ));
                ctx.capture(CapturedKind::Policy, &msg);
                Err(e.into())
            }
        }
    }

    /// Write a UTF-8 file (truncating). Capability: `fs_write`.
    fn fs_write<'v>(
        path: &str,
        content: &str,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> anyhow::Result<NoneType> {
        let ctx = ctx_from_eval(eval)?;
        let step = ctx.next_step();
        match ctx.policy.check_fs_write(Path::new(path)) {
            Ok(resolved) => {
                ctx.require_confirm(
                    "fs_write",
                    format!("write {} ({} bytes)", resolved.display(), content.len()),
                )?;
                if let Some(parent) = resolved.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                let result = std::fs::write(&resolved, content);
                ctx.emit(AuditEvent::fs(
                    &ctx.task_id,
                    step,
                    "fs_write",
                    &resolved,
                    result.is_ok(),
                    result.as_ref().err().map(|e| e.to_string()),
                ));
                result?;
                Ok(NoneType)
            }
            Err(e) => {
                let msg = e.to_string();
                ctx.emit(AuditEvent::denied(
                    &ctx.task_id,
                    step,
                    "fs_write",
                    &format!("path={path}"),
                    &msg,
                ));
                ctx.capture(CapturedKind::Policy, &msg);
                Err(e.into())
            }
        }
    }

    /// Run a subprocess. argv must be a list of strings; no shell, no
    /// /bin/sh expansion. Capability: `subprocess_exec`.
    fn subprocess_exec<'v>(
        argv: UnpackList<String>,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> anyhow::Result<String> {
        let ctx = ctx_from_eval(eval)?;
        let step = ctx.next_step();
        let argv = argv.items;
        if argv.is_empty() {
            return Err(anyhow::anyhow!("subprocess_exec: argv must not be empty"));
        }
        // Slice 1 enforcement is "is the capability allowed at all". Per-command
        // allowlist (e.g. only `git`, only `npm`) is policy work for Slice 2.
        let cmd_summary = argv.join(" ");
        ctx.require_confirm("subprocess_exec", format!("exec: {}", cmd_summary))?;
        let output = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .output();
        match output {
            Ok(out) => {
                let ok = out.status.success();
                let body = String::from_utf8_lossy(&out.stdout).to_string();
                ctx.emit(AuditEvent::subprocess(
                    &ctx.task_id,
                    step,
                    &argv,
                    out.status.code(),
                    ok,
                    None,
                ));
                if !ok {
                    let err = String::from_utf8_lossy(&out.stderr).to_string();
                    return Err(anyhow::anyhow!(
                        "subprocess_exec: non-zero exit ({:?}): {}",
                        out.status.code(),
                        err.trim()
                    ));
                }
                Ok(body)
            }
            Err(e) => {
                ctx.emit(AuditEvent::subprocess(
                    &ctx.task_id,
                    step,
                    &argv,
                    None,
                    false,
                    Some(e.to_string()),
                ));
                Err(e.into())
            }
        }
    }

    /// HTTP GET. Capability: `net_http_get`.
    fn net_http_get<'v>(
        url: &str,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> anyhow::Result<String> {
        let ctx = ctx_from_eval(eval)?;
        let step = ctx.next_step();
        match ctx.policy.check_http_get(url) {
            Ok(parsed) => {
                ctx.require_confirm("net_http_get", format!("GET {}", parsed))?;
                let result: Result<String, anyhow::Error> = (|| {
                    let resp = ureq::get(parsed.as_str()).call()?;
                    Ok(resp.into_string()?)
                })();
                ctx.emit(AuditEvent::http(
                    &ctx.task_id,
                    step,
                    "net_http_get",
                    parsed.as_str(),
                    result.is_ok(),
                    result.as_ref().err().map(|e| e.to_string()),
                ));
                result
            }
            Err(e) => {
                let msg = e.to_string();
                ctx.emit(AuditEvent::denied(
                    &ctx.task_id,
                    step,
                    "net_http_get",
                    &format!("url={url}"),
                    &msg,
                ));
                ctx.capture(CapturedKind::Policy, &msg);
                Err(e.into())
            }
        }
    }
}

/// Re-export the path type used by [`AuditEvent`] helpers.
pub use std::path::Path as AuditPath;

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_policy::PolicyFile;
    use std::path::PathBuf;

    fn runner_for(toml: &str, root: PathBuf) -> Runner {
        let file = PolicyFile::from_toml_str(toml).unwrap();
        let policy = Policy::from_file(file, root).unwrap();
        Runner::new(policy)
    }

    #[test]
    fn allowed_read_succeeds() {
        let tmp = std::env::temp_dir();
        let f = tmp.join("aegis_test_input.txt");
        std::fs::write(&f, "hello aegis").unwrap();

        let toml = r#"
[filesystem]
read_allow = ["/tmp/**", "/var/tmp/**"]

[functions]
allow = ["fs_read"]
"#;
        let runner = runner_for(toml, tmp);
        let path_lit = f.to_string_lossy().replace('\\', "/");
        let src = format!(r#"x = fs_read("{path_lit}")
print(x)"#);
        let outcome = runner.run("t1", &src, "test.star").unwrap();
        assert_eq!(outcome.printed, vec!["hello aegis".to_string()]);
    }

    #[test]
    fn write_outside_allow_is_denied() {
        let toml = r#"
[filesystem]
write_allow = ["/tmp/**"]
deny = ["~/.aws/**"]

[functions]
allow = ["fs_write"]
"#;
        let runner = runner_for(toml, PathBuf::from("/work"));
        let src = r#"fs_write("/etc/passwd", "x")"#;
        let err = runner.run("t1", src, "test.star").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("policy") || msg.contains("denied") || msg.contains("not in"),
            "expected policy violation, got: {msg}");
    }

    #[test]
    fn function_not_in_allowlist_rejected_pre_execution() {
        let toml = r#"
[functions]
allow = ["fs_read"]
"#;
        let runner = runner_for(toml, PathBuf::from("/tmp"));
        // Script calls subprocess_exec, which is not in the allowlist.
        let src = r#"subprocess_exec(["echo", "hi"])"#;
        let err = runner.run("t1", src, "test.star").unwrap_err();
        assert!(matches!(err, AegisError::Verifier(_)),
            "expected pre-execution verifier rejection, got: {err:?}");
    }
}
