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
use std::net::{IpAddr, ToSocketAddrs};
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
pub mod taint;
pub mod verifier;

pub use audit::{AuditEvent, AuditSink, JsonlAuditSink, NullAuditSink};
pub use confirm::{AllowAllConfirm, ConfirmDecision, ConfirmHook, ConfirmRequest, DenyAllConfirm};
pub use taint::{redact, TaintRegistry, REDACTED};

/// A capability the runtime knows how to enforce.
///
/// `name` is the dotted form policy files and audit events use
/// (`fs.read`). `raw` is the underscored name of the Starlark global
/// the host actually registers (`_aegis_fs_read`); a small prelude
/// binds the dotted access onto these via Starlark `struct()` values.
#[derive(Copy, Clone, Debug)]
pub struct Capability {
    pub name: &'static str,
    pub raw: &'static str,
}

pub const CAPABILITIES: &[Capability] = &[
    Capability { name: "fs.read", raw: "_aegis_fs_read" },
    Capability { name: "fs.write", raw: "_aegis_fs_write" },
    Capability { name: "fs.delete", raw: "_aegis_fs_delete" },
    Capability { name: "net.http_get", raw: "_aegis_net_http_get" },
    Capability { name: "net.http_post", raw: "_aegis_net_http_post" },
    Capability { name: "net.http_put", raw: "_aegis_net_http_put" },
    Capability { name: "net.http_patch", raw: "_aegis_net_http_patch" },
    Capability { name: "net.http_delete", raw: "_aegis_net_http_delete" },
    Capability { name: "subprocess.exec", raw: "_aegis_subprocess_exec" },
    Capability { name: "env.read", raw: "_aegis_env_read" },
];

/// Starlark prelude evaluated before the user script. Binds the dotted
/// namespaces (`fs.read`, `net.http_get`, etc.) onto the underscored
/// builtins the host registers as globals. Two-stage eval (prelude AST,
/// then user AST) keeps user-source line numbers correct in error
/// traces.
const PRELUDE: &str = "\
fs = struct(\n\
    read = _aegis_fs_read,\n\
    write = _aegis_fs_write,\n\
    delete = _aegis_fs_delete,\n\
)\n\
net = struct(\n\
    http_get = _aegis_net_http_get,\n\
    http_post = _aegis_net_http_post,\n\
    http_put = _aegis_net_http_put,\n\
    http_patch = _aegis_net_http_patch,\n\
    http_delete = _aegis_net_http_delete,\n\
)\n\
subprocess = struct(\n\
    exec = _aegis_subprocess_exec,\n\
)\n\
env = struct(\n\
    read = _aegis_env_read,\n\
)\n\
";

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

        let prelude_ast = AstModule::parse("__aegis_prelude__", PRELUDE.to_string(), &Dialect::Standard)
            .map_err(|e| AegisError::Other(format!("prelude parse failed: {e}")))?;
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
            taint: TaintRegistry::default(),
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
            eval.eval_module(prelude_ast, &globals)
                .map_err(|e| format!("aegis prelude failed: {e}"))
                .and_then(|_| {
                    eval.eval_module(ast, &globals)
                        .map(|_| ())
                        .map_err(|e| e.to_string())
                })
        };
        let captured = ctx.captured.borrow_mut().take();
        let taints = ctx.taint.snapshot();
        let printed: Vec<String> = ctx
            .printed
            .into_inner()
            .into_iter()
            .map(|line| redact(&line, &taints))
            .collect();

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
    /// Tainted values registered by local-only reads. Every output
    /// crossing the runtime boundary (printed lines, audit-event
    /// payloads, MCP tool result text) is scrubbed against this
    /// registry before leaving.
    taint: TaintRegistry,
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

    fn emit(&self, mut event: AuditEvent) {
        if !self.taint.is_empty() {
            let taints = self.taint.snapshot();
            taint::redact_json(&mut event.detail, &taints);
        }
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

/// Resolve a hostname (not an IP literal) to its A/AAAA records via the
/// system resolver. Returns an empty vec on resolution failure — the
/// caller proceeds and the actual HTTP attempt will surface the error.
/// This is fail-open by design: a temporary DNS hiccup shouldn't block
/// a legitimate request, and an attacker who could force a resolution
/// failure could equally serve a public-IP A record at check time and
/// rebind later (a known limit; full defense requires resolved-IP
/// pinning passed into the HTTP client).
fn resolve_host_to_ips(host: &str) -> Vec<IpAddr> {
    (host, 0u16)
        .to_socket_addrs()
        .ok()
        .map(|iter| iter.map(|sa| sa.ip()).collect())
        .unwrap_or_default()
}

/// Run each resolved IP for `host` through `policy.check_resolved_ip`
/// and return the first denial. No-op when `host` is itself an IP
/// literal (the policy's URL-level check already covered it).
fn dns_check(
    ctx: &HostCtx,
    action: &'static str,
    host: &str,
) -> Result<(), aegis_policy::PolicyError> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    for ip in resolve_host_to_ips(host) {
        ctx.policy.check_resolved_ip(action, host, ip)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Capability builtins.
//
// All effecting builtins live under underscored Starlark names (e.g.
// `_aegis_fs_read`). The Aegis prelude binds these to the dotted
// namespaces user code actually writes (`fs.read`, `net.http_get`, ...).
// Audit events and policy checks always speak the dotted form.
// ---------------------------------------------------------------------

#[starlark_module]
fn register_builtins(builder: &mut GlobalsBuilder) {
    fn _aegis_fs_read<'v>(path: &str, eval: &mut Evaluator<'v, '_, '_>) -> anyhow::Result<String> {
        let ctx = ctx_from_eval(eval)?;
        let step = ctx.next_step();
        match ctx.policy.check_fs_read(Path::new(path)) {
            Ok(resolved) => {
                ctx.require_confirm("fs.read", format!("read {}", resolved.display()))?;
                let result = std::fs::read_to_string(&resolved);
                if let Ok(content) = result.as_ref() {
                    if ctx.policy.fs_read_is_local_only(&resolved) {
                        ctx.taint.add(content);
                    }
                }
                ctx.emit(AuditEvent::fs(
                    &ctx.task_id,
                    step,
                    "fs.read",
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
                    "fs.read",
                    &format!("path={path}"),
                    &msg,
                ));
                ctx.capture(CapturedKind::Policy, &msg);
                Err(e.into())
            }
        }
    }

    fn _aegis_fs_write<'v>(
        path: &str,
        content: &str,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> anyhow::Result<NoneType> {
        let ctx = ctx_from_eval(eval)?;
        let step = ctx.next_step();
        match ctx.policy.check_fs_write(Path::new(path)) {
            Ok(resolved) => {
                ctx.require_confirm(
                    "fs.write",
                    format!("write {} ({} bytes)", resolved.display(), content.len()),
                )?;
                if let Some(parent) = resolved.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                let result = std::fs::write(&resolved, content);
                ctx.emit(AuditEvent::fs(
                    &ctx.task_id,
                    step,
                    "fs.write",
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
                    "fs.write",
                    &format!("path={path}"),
                    &msg,
                ));
                ctx.capture(CapturedKind::Policy, &msg);
                Err(e.into())
            }
        }
    }

    fn _aegis_fs_delete<'v>(
        path: &str,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> anyhow::Result<NoneType> {
        let ctx = ctx_from_eval(eval)?;
        let step = ctx.next_step();
        match ctx.policy.check_fs_delete(Path::new(path)) {
            Ok(resolved) => {
                ctx.require_confirm("fs.delete", format!("delete {}", resolved.display()))?;
                let result = std::fs::remove_file(&resolved);
                ctx.emit(AuditEvent::fs(
                    &ctx.task_id,
                    step,
                    "fs.delete",
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
                    "fs.delete",
                    &format!("path={path}"),
                    &msg,
                ));
                ctx.capture(CapturedKind::Policy, &msg);
                Err(e.into())
            }
        }
    }

    fn _aegis_subprocess_exec<'v>(
        argv: UnpackList<String>,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> anyhow::Result<String> {
        let ctx = ctx_from_eval(eval)?;
        let step = ctx.next_step();
        let argv = argv.items;
        if argv.is_empty() {
            return Err(anyhow::anyhow!("subprocess.exec: argv must not be empty"));
        }
        if let Err(e) = ctx.policy.check_subprocess_command(&argv[0]) {
            let msg = e.to_string();
            ctx.emit(AuditEvent::denied(
                &ctx.task_id,
                step,
                "subprocess.exec",
                &format!("argv={:?}", argv),
                &msg,
            ));
            ctx.capture(CapturedKind::Policy, &msg);
            return Err(e.into());
        }
        if let Err(e) = ctx.policy.check_subprocess_args(&argv) {
            let msg = e.to_string();
            ctx.emit(AuditEvent::denied(
                &ctx.task_id,
                step,
                "subprocess.exec",
                &format!("argv={:?}", argv),
                &msg,
            ));
            ctx.capture(CapturedKind::Policy, &msg);
            return Err(e.into());
        }
        let cmd_summary = argv.join(" ");
        ctx.require_confirm("subprocess.exec", format!("exec: {}", cmd_summary))?;
        let output = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .output();
        match output {
            Ok(out) => {
                let ok = out.status.success();
                let body = String::from_utf8_lossy(&out.stdout).to_string();
                let stderr_text = String::from_utf8_lossy(&out.stderr).to_string();
                if ctx.policy.subprocess_is_local_only(&argv[0]) {
                    ctx.taint.add(&body);
                    ctx.taint.add(&stderr_text);
                }
                ctx.emit(AuditEvent::subprocess(
                    &ctx.task_id,
                    step,
                    &argv,
                    out.status.code(),
                    ok,
                    None,
                ));
                if !ok {
                    return Err(anyhow::anyhow!(
                        "subprocess.exec: non-zero exit ({:?}): {}",
                        out.status.code(),
                        stderr_text.trim()
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

    fn _aegis_net_http_get<'v>(
        url: &str,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> anyhow::Result<String> {
        let ctx = ctx_from_eval(eval)?;
        let step = ctx.next_step();
        match ctx.policy.check_http_get(url) {
            Ok(parsed) => {
                if let Some(host) = parsed.host_str() {
                    if let Err(e) = dns_check(ctx, "http_get", host) {
                        let msg = e.to_string();
                        ctx.emit(AuditEvent::denied(
                            &ctx.task_id,
                            step,
                            "net.http_get",
                            &format!("url={url}"),
                            &msg,
                        ));
                        ctx.capture(CapturedKind::Policy, &msg);
                        return Err(e.into());
                    }
                }
                ctx.require_confirm("net.http_get", format!("GET {}", parsed))?;
                let host_label = parsed.host_str().map(|s| s.to_string()).unwrap_or_default();
                let result: Result<String, anyhow::Error> = (|| {
                    let resp = ureq::get(parsed.as_str()).call()?;
                    Ok(resp.into_string()?)
                })();
                if let Ok(body) = result.as_ref() {
                    if ctx.policy.host_is_local_only(&host_label) {
                        ctx.taint.add(body);
                    }
                }
                ctx.emit(AuditEvent::http(
                    &ctx.task_id,
                    step,
                    "net.http_get",
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
                    "net.http_get",
                    &format!("url={url}"),
                    &msg,
                ));
                ctx.capture(CapturedKind::Policy, &msg);
                Err(e.into())
            }
        }
    }

    fn _aegis_net_http_post<'v>(
        url: &str,
        body: &str,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> anyhow::Result<String> {
        let ctx = ctx_from_eval(eval)?;
        let step = ctx.next_step();
        match ctx.policy.check_http_post(url) {
            Ok(parsed) => {
                if let Some(host) = parsed.host_str() {
                    if let Err(e) = dns_check(ctx, "http_post", host) {
                        let msg = e.to_string();
                        ctx.emit(AuditEvent::denied(
                            &ctx.task_id,
                            step,
                            "net.http_post",
                            &format!("url={url}"),
                            &msg,
                        ));
                        ctx.capture(CapturedKind::Policy, &msg);
                        return Err(e.into());
                    }
                }
                ctx.require_confirm(
                    "net.http_post",
                    format!("POST {} ({} bytes)", parsed, body.len()),
                )?;
                let host_label = parsed.host_str().map(|s| s.to_string()).unwrap_or_default();
                let result: Result<String, anyhow::Error> = (|| {
                    let resp = ureq::post(parsed.as_str()).send_string(body)?;
                    Ok(resp.into_string()?)
                })();
                if let Ok(b) = result.as_ref() {
                    if ctx.policy.host_is_local_only(&host_label) {
                        ctx.taint.add(b);
                    }
                }
                ctx.emit(AuditEvent::http(
                    &ctx.task_id,
                    step,
                    "net.http_post",
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
                    "net.http_post",
                    &format!("url={url}"),
                    &msg,
                ));
                ctx.capture(CapturedKind::Policy, &msg);
                Err(e.into())
            }
        }
    }

    fn _aegis_net_http_put<'v>(
        url: &str,
        body: &str,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> anyhow::Result<String> {
        let ctx = ctx_from_eval(eval)?;
        let step = ctx.next_step();
        match ctx.policy.check_http_put(url) {
            Ok(parsed) => {
                if let Some(host) = parsed.host_str() {
                    if let Err(e) = dns_check(ctx, "http_put", host) {
                        let msg = e.to_string();
                        ctx.emit(AuditEvent::denied(
                            &ctx.task_id,
                            step,
                            "net.http_put",
                            &format!("url={url}"),
                            &msg,
                        ));
                        ctx.capture(CapturedKind::Policy, &msg);
                        return Err(e.into());
                    }
                }
                ctx.require_confirm(
                    "net.http_put",
                    format!("PUT {} ({} bytes)", parsed, body.len()),
                )?;
                let host_label = parsed.host_str().map(|s| s.to_string()).unwrap_or_default();
                let result: Result<String, anyhow::Error> = (|| {
                    let resp = ureq::put(parsed.as_str()).send_string(body)?;
                    Ok(resp.into_string()?)
                })();
                if let Ok(b) = result.as_ref() {
                    if ctx.policy.host_is_local_only(&host_label) {
                        ctx.taint.add(b);
                    }
                }
                ctx.emit(AuditEvent::http(
                    &ctx.task_id,
                    step,
                    "net.http_put",
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
                    "net.http_put",
                    &format!("url={url}"),
                    &msg,
                ));
                ctx.capture(CapturedKind::Policy, &msg);
                Err(e.into())
            }
        }
    }

    fn _aegis_net_http_patch<'v>(
        url: &str,
        body: &str,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> anyhow::Result<String> {
        let ctx = ctx_from_eval(eval)?;
        let step = ctx.next_step();
        match ctx.policy.check_http_patch(url) {
            Ok(parsed) => {
                if let Some(host) = parsed.host_str() {
                    if let Err(e) = dns_check(ctx, "http_patch", host) {
                        let msg = e.to_string();
                        ctx.emit(AuditEvent::denied(
                            &ctx.task_id,
                            step,
                            "net.http_patch",
                            &format!("url={url}"),
                            &msg,
                        ));
                        ctx.capture(CapturedKind::Policy, &msg);
                        return Err(e.into());
                    }
                }
                ctx.require_confirm(
                    "net.http_patch",
                    format!("PATCH {} ({} bytes)", parsed, body.len()),
                )?;
                let host_label = parsed.host_str().map(|s| s.to_string()).unwrap_or_default();
                let result: Result<String, anyhow::Error> = (|| {
                    let resp = ureq::patch(parsed.as_str()).send_string(body)?;
                    Ok(resp.into_string()?)
                })();
                if let Ok(b) = result.as_ref() {
                    if ctx.policy.host_is_local_only(&host_label) {
                        ctx.taint.add(b);
                    }
                }
                ctx.emit(AuditEvent::http(
                    &ctx.task_id,
                    step,
                    "net.http_patch",
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
                    "net.http_patch",
                    &format!("url={url}"),
                    &msg,
                ));
                ctx.capture(CapturedKind::Policy, &msg);
                Err(e.into())
            }
        }
    }

    fn _aegis_net_http_delete<'v>(
        url: &str,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> anyhow::Result<String> {
        let ctx = ctx_from_eval(eval)?;
        let step = ctx.next_step();
        match ctx.policy.check_http_delete(url) {
            Ok(parsed) => {
                if let Some(host) = parsed.host_str() {
                    if let Err(e) = dns_check(ctx, "http_delete", host) {
                        let msg = e.to_string();
                        ctx.emit(AuditEvent::denied(
                            &ctx.task_id,
                            step,
                            "net.http_delete",
                            &format!("url={url}"),
                            &msg,
                        ));
                        ctx.capture(CapturedKind::Policy, &msg);
                        return Err(e.into());
                    }
                }
                ctx.require_confirm("net.http_delete", format!("DELETE {}", parsed))?;
                let host_label = parsed.host_str().map(|s| s.to_string()).unwrap_or_default();
                let result: Result<String, anyhow::Error> = (|| {
                    let resp = ureq::delete(parsed.as_str()).call()?;
                    Ok(resp.into_string()?)
                })();
                if let Ok(b) = result.as_ref() {
                    if ctx.policy.host_is_local_only(&host_label) {
                        ctx.taint.add(b);
                    }
                }
                ctx.emit(AuditEvent::http(
                    &ctx.task_id,
                    step,
                    "net.http_delete",
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
                    "net.http_delete",
                    &format!("url={url}"),
                    &msg,
                ));
                ctx.capture(CapturedKind::Policy, &msg);
                Err(e.into())
            }
        }
    }

    fn _aegis_env_read<'v>(
        name: &str,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> anyhow::Result<String> {
        let ctx = ctx_from_eval(eval)?;
        let step = ctx.next_step();
        match ctx.policy.check_env_read(name) {
            Ok(()) => {
                ctx.require_confirm("env.read", format!("read env var {name}"))?;
                let value = std::env::var(name).unwrap_or_default();
                if ctx.policy.env_is_local_only(name) {
                    ctx.taint.add(&value);
                }
                ctx.emit(AuditEvent::env(&ctx.task_id, step, name, true, None));
                Ok(value)
            }
            Err(e) => {
                let msg = e.to_string();
                ctx.emit(AuditEvent::denied(
                    &ctx.task_id,
                    step,
                    "env.read",
                    &format!("name={name}"),
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

