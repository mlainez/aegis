//! Aegis policy types and runtime matchers.
//!
//! Policy is parsed configuration data, not executable code, so an agent
//! script cannot mutate or rewrite the policy from inside the sandbox.
//! Three sections: filesystem (gitignore-style path rules), network
//! (host/IP allowlist + denylist), and functions (Starlark builtin
//! allowlist).

use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

pub mod presets;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy denies {action} on path {path:?}: {reason}")]
    PathDenied {
        action: &'static str,
        path: PathBuf,
        reason: String,
    },
    #[error("policy denies {action} on host {host:?}: {reason}")]
    HostDenied {
        action: &'static str,
        host: String,
        reason: String,
    },
    #[error("policy denies call to function {name:?}: {reason}")]
    FunctionDenied { name: String, reason: String },
    #[error("policy denies tool {name:?}: {reason}")]
    ToolDenied { name: String, reason: String },
    #[error("policy denies env var {name:?}: {reason}")]
    EnvDenied { name: String, reason: String },
    #[error("policy denies subprocess command {command:?}: {reason}")]
    CommandDenied { command: String, reason: String },
    #[error("policy denies subprocess command {command:?} with forbidden argument pattern {pattern:?}: {reason}")]
    ArgsDenied {
        command: String,
        pattern: String,
        reason: String,
    },
    #[error("policy file is invalid: {0}")]
    Invalid(String),
    #[error(
        "policy file at {policy_path:?} is itself matched by [filesystem].{action}_allow; refusing to load — an agent that can {action} its own policy can disable every other rule. Tighten your allow patterns or add the policy file to [filesystem].deny."
    )]
    SelfWritable {
        policy_path: PathBuf,
        action: &'static str,
    },
}

/// Top-level policy. Loaded from a TOML file. The `source_path` is
/// retained so the runtime can re-read on every call (defeats in-memory
/// tampering).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyFile {
    /// Optional schema version. Consumers that pin to a major version
    /// should reject files whose `version` mismatches. Absent = "I'll
    /// take whatever you parse".
    #[serde(default)]
    pub version: Option<String>,

    /// Inherit from a named built-in preset. The preset is loaded as
    /// the base and this file's fields are merged on top: list fields
    /// (allow/deny lists) concat with dedup; map fields (deny_args)
    /// key-merge with per-key concat; scalars are "this file wins".
    /// Currently supported: `"secure-defaults"`.
    #[serde(default)]
    pub inherits: Option<String>,

    /// Free-form metadata for humans / CI. Not interpreted.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,

    #[serde(default)]
    pub filesystem: FilesystemPolicy,
    #[serde(default)]
    pub network: NetworkPolicy,
    #[serde(default)]
    pub environment: EnvironmentPolicy,
    #[serde(default)]
    pub subprocess: SubprocessPolicy,
    /// Map from external tool names (as exposed by an MCP host or an
    /// IDE agent runtime) to the dotted Aegis capability names the
    /// tool requires. A consuming host that receives a tool call (e.g.
    /// `Bash {command: "ls"}`) looks up `Bash` here, gets back
    /// `["subprocess.exec"]`, and verifies each capability against the
    /// derived capability set before invoking the tool.
    ///
    /// Default-deny: a tool not declared here is rejected by
    /// `Policy::check_tool`.
    ///
    /// The TOML accepts two forms per entry — a bare list of
    /// capability names (`Read = ["fs.read"]`) or a full
    /// [`ToolRecord`] table with optional `backend_url` /
    /// `backend_method` / `description` routing hints.
    #[serde(default, deserialize_with = "deserialize_tools")]
    pub tools: std::collections::BTreeMap<String, ToolRecord>,
    #[serde(default)]
    pub confirm_per_call: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FilesystemPolicy {
    #[serde(default)]
    pub read_allow: Vec<String>,
    /// Paths whose CONTENTS are readable by the script but whose value
    /// must never leave the runtime back to the calling host. A read
    /// matching a `local_only_read` pattern succeeds and the returned
    /// content is tainted: every output sink (printed lines, audit
    /// payloads, MCP tool results) is scrubbed for any occurrence of
    /// the value before crossing the runtime boundary. Local-only wins
    /// over a plain `read_allow` if both match.
    #[serde(default)]
    pub local_only_read: Vec<String>,
    #[serde(default)]
    pub write_allow: Vec<String>,
    #[serde(default)]
    pub delete_allow: Vec<String>,
    /// Belt-and-suspenders denylist applied to all three actions. Deny
    /// wins over allow.
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub http_get_allow: Vec<String>,
    #[serde(default)]
    pub http_post_allow: Vec<String>,
    /// Reserved for future enforcement; included in the schema so
    /// portable policy files can declare PUT/PATCH/DELETE intent today.
    #[serde(default)]
    pub http_put_allow: Vec<String>,
    #[serde(default)]
    pub http_patch_allow: Vec<String>,
    #[serde(default)]
    pub http_delete_allow: Vec<String>,
    #[serde(default)]
    pub deny_hosts: Vec<String>,
    #[serde(default)]
    pub deny_ips: Vec<String>,
    /// Hosts whose HTTP response bodies are readable by the script but
    /// must never leave the runtime back to the calling host. A
    /// response from any `local_only_hosts` host (regardless of verb)
    /// is tainted at the runtime boundary. The host must additionally
    /// be in the appropriate `http_*_allow` list (or in
    /// `local_only_hosts` is treated as the allow source — see
    /// resolution rules in EnvironmentPolicy::local_only_vars docs).
    #[serde(default)]
    pub local_only_hosts: Vec<String>,
}

// FunctionPolicy was removed. Capabilities are now derived from the
// resource sections alone — populating `[filesystem].read_allow`
// implies `fs.read` is permitted, populating
// `[subprocess].allow_commands` implies `subprocess.exec`, and so on.
// See `derive_capabilities` below.

/// Full record for a `[tools.X]` entry: the capabilities it requires
/// plus optional routing hints (where the tool's outbound call should
/// go, how it should be made). The routing fields are *informational*
/// — the network policy is still the enforcement layer; a `backend_url`
/// must additionally satisfy `[network].http_*_allow` at call time.
///
/// Two TOML forms are accepted (see custom deserializer):
///
/// ```toml
/// # Short form — just a list of required capabilities:
/// Read = ["fs.read"]
///
/// # Long form — full record with routing hints:
/// [tools.WebSearch]
/// capabilities  = ["net.http_get"]
/// backend_url   = "https://searx.be/search"
/// backend_method = "GET"
/// description   = "Privacy-respecting open-source meta-search."
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ToolRecord {
    /// Aegis capabilities the tool requires. The tool is permitted iff
    /// every entry here has a populated resource section.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Routing hint: the URL this tool's outbound HTTP call is
    /// expected to target. Bridges (e.g. the local-executor harness)
    /// can read this to inject "for WebSearch, GET this URL" into the
    /// system prompt, instead of leaving the local model to guess.
    #[serde(default)]
    pub backend_url: Option<String>,
    /// Routing hint: HTTP method. "GET" / "POST" / "PUT" / "PATCH" /
    /// "DELETE". Defaults to GET when absent.
    #[serde(default)]
    pub backend_method: Option<String>,
    /// Free-form human / system-prompt description.
    #[serde(default)]
    pub description: Option<String>,
}

impl ToolRecord {
    /// Convenience: HTTP method as an uppercase &str, defaulting to
    /// "GET" when not declared.
    pub fn method(&self) -> &str {
        self.backend_method
            .as_deref()
            .unwrap_or("GET")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnvironmentPolicy {
    /// Exact env var names the script may read. Default-deny.
    #[serde(default)]
    pub allow_vars: Vec<String>,
    /// Names that are never readable, even if present in `allow_vars`.
    /// Belt-and-suspenders against typos that leak credentials.
    #[serde(default)]
    pub deny_vars: Vec<String>,
    /// Names readable by the script but whose values must NEVER leave
    /// the runtime back to the calling host. The runtime taints values
    /// returned from `env.read` for these names: every script output
    /// (printed lines, audit-log payloads, MCP tool results) is
    /// scanned and any occurrence of the value is replaced with
    /// `[REDACTED]` before it crosses the runtime boundary.
    ///
    /// Use case: a cloud orchestrator delegates to a local executor;
    /// the local executor needs the user's API key to call a remote
    /// service, but the key must not bubble up to the cloud
    /// orchestrator. The local model can still pass the key into a
    /// `net.http_get` / `net.http_post` call (an outbound effect
    /// gated by the network policy); only the *return path* out of
    /// the runtime is scrubbed.
    ///
    /// Resolution (deny wins, taint wins over plain allow):
    ///   - in `deny_vars`        → read fails
    ///   - in `local_only_vars`  → read succeeds, value is tainted
    ///   - in `allow_vars` only  → read succeeds, value is plain
    ///   - in none of the above  → read fails
    #[serde(default)]
    pub local_only_vars: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SubprocessPolicy {
    /// Commands the script may exec, matched against the basename of
    /// argv[0]. Empty means "no commands at all", even if the
    /// `subprocess.exec` capability is otherwise allowed.
    #[serde(default)]
    pub allow_commands: Vec<String>,
    /// Commands whose stdout/stderr the script may read but must
    /// never leave the runtime back to the calling host. Subprocess
    /// output from any local-only command is tainted; its bytes will
    /// be redacted in printed output, audit payloads, and MCP results.
    /// Local-only wins over plain `allow_commands` if both match.
    #[serde(default)]
    pub local_only_commands: Vec<String>,
    /// Commands that are never permitted; deny wins over allow.
    #[serde(default)]
    pub deny_commands: Vec<String>,
    /// Per-command argument denylist. Map keys are commands (basename
    /// match), values are forbidden argument patterns (substring match
    /// against the joined argv). Examples: `"git" = ["push --force",
    /// "reset --hard"]`. Reserved for future enforcement; declared in
    /// the spec so portable policies can capture intent today.
    #[serde(default)]
    pub deny_args: std::collections::BTreeMap<String, Vec<String>>,
}


impl PolicyFile {
    pub fn from_toml_str(s: &str) -> Result<Self> {
        toml::from_str(s).context("parse policy TOML")
    }

    /// Merge `over` on top of `self`. List fields concat with dedup
    /// and gitignore-style negation (`"!X"` strips `X`); map fields
    /// (`tools`, `subprocess.deny_args`) merge per-key with the same
    /// negation rules; scalars favor `over` when set.
    ///
    /// Public so embedding hosts can layer policies programmatically
    /// (for example, a per-task overlay on top of a project policy).
    pub fn merge_with(self, over: PolicyFile) -> PolicyFile {
        merge_policy_files(self, over)
    }

    /// Resolve `inherits` by loading the named preset, parsing it, and
    /// merging this file on top. If `inherits` is `None`, returns self
    /// unchanged. Errors if the preset name is unknown.
    pub fn resolve_inheritance(self) -> Result<Self> {
        let Some(name) = self.inherits.clone() else {
            return Ok(self);
        };
        let preset_src = presets::lookup(&name).ok_or_else(|| {
            anyhow::anyhow!(
                "unknown policy preset: {name:?}; known presets: {:?}",
                presets::names()
            )
        })?;
        let base = PolicyFile::from_toml_str(preset_src)
            .with_context(|| format!("parse built-in preset {name:?}"))?;
        Ok(merge_policy_files(base, self))
    }
}

/// Merge an inherited list (`base`) with a user-file list (`over`),
/// supporting gitignore-style negation:
///
/// - `"X"` adds `X` (with dedup against base).
/// - `"!X"` removes `X` from the result if present. If `X` wasn't in
///   the base, this is a silent no-op.
///
/// Negations are intentional weakening of an inherited deny — they're
/// visible in the policy file (`!~/.aws/**` is hard to mistake for a
/// typo) and survive every code review the policy goes through.
/// Within a single user file, order matters: `["!X", "X"]` ends with
/// `X` present; `["X", "!X"]` ends with `X` absent.
fn concat_dedup(mut base: Vec<String>, over: Vec<String>) -> Vec<String> {
    for v in over {
        if let Some(target) = v.strip_prefix('!') {
            base.retain(|item| item != target);
        } else if !base.contains(&v) {
            base.push(v);
        }
    }
    base
}

/// Merge `[tools]` maps. Capability lists merge per-key with
/// concat-dedup-and-negation (`"!fs.write"` strips that capability
/// from an inherited entry). Routing hints (`backend_url`,
/// `backend_method`, `description`) merge as scalar overlays — `over`
/// wins when set, otherwise `base` wins.
fn merge_tools(
    mut base: std::collections::BTreeMap<String, ToolRecord>,
    over: std::collections::BTreeMap<String, ToolRecord>,
) -> std::collections::BTreeMap<String, ToolRecord> {
    for (k, v) in over {
        let entry = base.entry(k).or_default();
        // Capabilities: gitignore-style negation merge.
        for item in v.capabilities {
            if let Some(target) = item.strip_prefix('!') {
                entry.capabilities.retain(|s| s != target);
            } else if !entry.capabilities.contains(&item) {
                entry.capabilities.push(item);
            }
        }
        // Routing hints: scalar overlay (over wins when set).
        if v.backend_url.is_some() {
            entry.backend_url = v.backend_url;
        }
        if v.backend_method.is_some() {
            entry.backend_method = v.backend_method;
        }
        if v.description.is_some() {
            entry.description = v.description;
        }
    }
    base
}

/// Custom deserializer for `[tools]`. Accepts two forms per entry —
/// a bare list of capability strings (`Read = ["fs.read"]`) or a
/// table with `capabilities` plus optional routing hints — and
/// normalizes both to [`ToolRecord`].
fn deserialize_tools<'de, D>(
    d: D,
) -> Result<std::collections::BTreeMap<String, ToolRecord>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Either {
        Caps(Vec<String>),
        Full(ToolRecord),
    }
    let raw: std::collections::BTreeMap<String, Either> =
        std::collections::BTreeMap::deserialize(d)?;
    Ok(raw
        .into_iter()
        .map(|(k, v)| match v {
            Either::Caps(caps) => (
                k,
                ToolRecord {
                    capabilities: caps,
                    ..Default::default()
                },
            ),
            Either::Full(rec) => (k, rec),
        })
        .collect())
}

fn merge_deny_args(
    mut base: std::collections::BTreeMap<String, Vec<String>>,
    over: std::collections::BTreeMap<String, Vec<String>>,
) -> std::collections::BTreeMap<String, Vec<String>> {
    for (k, v) in over {
        let entry = base.entry(k).or_default();
        for item in v {
            if let Some(target) = item.strip_prefix('!') {
                entry.retain(|s| s != target);
            } else if !entry.contains(&item) {
                entry.push(item);
            }
        }
    }
    base
}

fn merge_policy_files(base: PolicyFile, over: PolicyFile) -> PolicyFile {
    PolicyFile {
        version: over.version.or(base.version),
        // `inherits` does not chain; user file's value (or absence)
        // wins outright.
        inherits: over.inherits,
        name: over.name.or(base.name),
        description: over.description.or(base.description),
        filesystem: FilesystemPolicy {
            read_allow: concat_dedup(
                base.filesystem.read_allow,
                over.filesystem.read_allow,
            ),
            write_allow: concat_dedup(
                base.filesystem.write_allow,
                over.filesystem.write_allow,
            ),
            delete_allow: concat_dedup(
                base.filesystem.delete_allow,
                over.filesystem.delete_allow,
            ),
            local_only_read: concat_dedup(
                base.filesystem.local_only_read,
                over.filesystem.local_only_read,
            ),
            deny: concat_dedup(base.filesystem.deny, over.filesystem.deny),
        },
        network: NetworkPolicy {
            http_get_allow: concat_dedup(
                base.network.http_get_allow,
                over.network.http_get_allow,
            ),
            http_post_allow: concat_dedup(
                base.network.http_post_allow,
                over.network.http_post_allow,
            ),
            http_put_allow: concat_dedup(
                base.network.http_put_allow,
                over.network.http_put_allow,
            ),
            http_patch_allow: concat_dedup(
                base.network.http_patch_allow,
                over.network.http_patch_allow,
            ),
            http_delete_allow: concat_dedup(
                base.network.http_delete_allow,
                over.network.http_delete_allow,
            ),
            deny_hosts: concat_dedup(base.network.deny_hosts, over.network.deny_hosts),
            deny_ips: concat_dedup(base.network.deny_ips, over.network.deny_ips),
            local_only_hosts: concat_dedup(
                base.network.local_only_hosts,
                over.network.local_only_hosts,
            ),
        },
        environment: EnvironmentPolicy {
            allow_vars: concat_dedup(
                base.environment.allow_vars,
                over.environment.allow_vars,
            ),
            deny_vars: concat_dedup(
                base.environment.deny_vars,
                over.environment.deny_vars,
            ),
            local_only_vars: concat_dedup(
                base.environment.local_only_vars,
                over.environment.local_only_vars,
            ),
        },
        subprocess: SubprocessPolicy {
            allow_commands: concat_dedup(
                base.subprocess.allow_commands,
                over.subprocess.allow_commands,
            ),
            deny_commands: concat_dedup(
                base.subprocess.deny_commands,
                over.subprocess.deny_commands,
            ),
            local_only_commands: concat_dedup(
                base.subprocess.local_only_commands,
                over.subprocess.local_only_commands,
            ),
            deny_args: merge_deny_args(base.subprocess.deny_args, over.subprocess.deny_args),
        },
        tools: merge_tools(base.tools, over.tools),
        confirm_per_call: concat_dedup(base.confirm_per_call, over.confirm_per_call),
    }
}

/// A loaded policy plus the resolved root directory all relative path
/// patterns are evaluated against.
#[derive(Debug, Clone)]
pub struct Policy {
    file: PolicyFile,
    root: PathBuf,
    fs_read: PathMatcher,
    fs_local_only_read: PathMatcher,
    fs_write: PathMatcher,
    fs_delete: PathMatcher,
    fs_deny: PathMatcher,
    net_get_hosts: HostMatcher,
    net_post_hosts: HostMatcher,
    net_put_hosts: HostMatcher,
    net_patch_hosts: HostMatcher,
    net_delete_hosts: HostMatcher,
    net_deny_hosts: HostMatcher,
    net_local_only_hosts: HostMatcher,
    /// Parsed deny_ips entries, each held as an `IpNet`. Literal IPs
    /// (`169.254.169.254`) are stored as host networks (`/32` or
    /// `/128`); CIDR ranges (`10.0.0.0/8`) are stored as-is.
    net_deny_ips: Vec<IpNet>,
    env_allow: Vec<String>,
    env_deny: Vec<String>,
    env_local_only: Vec<String>,
    subprocess_allow: Vec<String>,
    subprocess_deny: Vec<String>,
    subprocess_local_only: Vec<String>,
    subprocess_deny_args: std::collections::BTreeMap<String, Vec<String>>,
    /// Capabilities derived from the populated resource sections.
    /// Single source of truth for what `check_function` permits.
    fn_derived: Vec<&'static str>,
    tools: std::collections::BTreeMap<String, ToolRecord>,
    confirm_per_call: Vec<String>,
}

impl Policy {
    /// Load a policy file, anchoring relative path patterns at the
    /// **policy file's own directory**. This is the portable default:
    /// `read_allow = ["src/**"]` means "the `src/` next to this
    /// policy file", regardless of where the operator invoked aegis
    /// from. A policy file shipped with a project keeps working when
    /// the project moves, gets cloned, or runs in CI; the user does
    /// not need to leak their personal directory structure into the
    /// policy.
    ///
    /// Both absolute (`/etc/passwd`, `/tmp/**`) and relative
    /// (`src/**`, `*.toml`) patterns are supported. Relative ones
    /// resolve against the policy file's parent directory.
    ///
    /// To override the anchor (e.g. to load the same policy file
    /// against a different working tree), use `load_with_root`.
    pub fn load(path: &Path) -> Result<Self> {
        let anchor = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        Self::load_with_root(path, anchor)
    }

    /// Load a policy file with an explicit `root` for relative-path
    /// pattern resolution. `root` is also where relative path
    /// arguments at runtime are resolved against.
    pub fn load_with_root(path: &Path, root: PathBuf) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read policy file {path:?}"))?;
        let file = PolicyFile::from_toml_str(&raw)?.resolve_inheritance()?;
        let root = std::fs::canonicalize(&root).unwrap_or(root);
        let policy = Self::from_file(file, root)?;
        let policy_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        policy.guard_self_writable(&policy_path)?;
        Ok(policy)
    }

    /// Refuse to load a policy that grants write or delete on its own
    /// file. An agent that can rewrite the policy that controls it can
    /// disable every other rule on the next run; the trust boundary
    /// has to start outside the agent's reach.
    ///
    /// `Policy::load` and `Policy::load_with_root` call this
    /// automatically. Direct embedders that build a `Policy` via
    /// `from_file` and know the on-disk policy path should call it
    /// themselves.
    pub fn guard_self_writable(&self, policy_path: &Path) -> Result<(), PolicyError> {
        // Note: deny still wins here, so a file appearing in both
        // write_allow and deny is fine (deny will block the write at
        // runtime). We probe with the actual `check_fs_*` methods so
        // the guard reflects the real enforcement decision.
        if self.check_fs_write(policy_path).is_ok() {
            return Err(PolicyError::SelfWritable {
                policy_path: policy_path.to_path_buf(),
                action: "write",
            });
        }
        if self.check_fs_delete(policy_path).is_ok() {
            return Err(PolicyError::SelfWritable {
                policy_path: policy_path.to_path_buf(),
                action: "delete",
            });
        }
        Ok(())
    }

    /// Construct a policy from the built-in `secure-defaults` preset
    /// alone, with no user file layered on top. This is the fallback
    /// used by the CLI and MCP server when invoked without a policy
    /// argument.
    ///
    /// The preset is purely a denylist (credentials paths, RFC1918 +
    /// metadata IPs, secret env-var names, destructive commands) and
    /// has no allow lists, so the resulting policy denies every
    /// effecting capability. Pure computation and `print()` are the
    /// only things that succeed. Loud-and-safe: any project that wants
    /// to actually do something must declare it explicitly.
    pub fn secure_defaults_at(root: PathBuf) -> Result<Self> {
        let preset_src =
            presets::lookup("secure-defaults").expect("built-in secure-defaults preset");
        let file = PolicyFile::from_toml_str(preset_src)
            .context("parse built-in secure-defaults preset")?;
        let root = std::fs::canonicalize(&root).unwrap_or(root);
        Self::from_file(file, root)
    }

    pub fn from_file(file: PolicyFile, root: PathBuf) -> Result<Self> {
        let fs_read = PathMatcher::build(&root, &file.filesystem.read_allow)?;
        let fs_local_only_read =
            PathMatcher::build(&root, &file.filesystem.local_only_read)?;
        let fs_write = PathMatcher::build(&root, &file.filesystem.write_allow)?;
        let fs_delete = PathMatcher::build(&root, &file.filesystem.delete_allow)?;
        let fs_deny = PathMatcher::build(&root, &file.filesystem.deny)?;
        let net_get_hosts = HostMatcher::build(&file.network.http_get_allow)?;
        let net_post_hosts = HostMatcher::build(&file.network.http_post_allow)?;
        let net_put_hosts = HostMatcher::build(&file.network.http_put_allow)?;
        let net_patch_hosts = HostMatcher::build(&file.network.http_patch_allow)?;
        let net_delete_hosts = HostMatcher::build(&file.network.http_delete_allow)?;
        let net_deny_hosts = HostMatcher::build(&file.network.deny_hosts)?;
        let net_local_only_hosts = HostMatcher::build(&file.network.local_only_hosts)?;
        let net_deny_ips = file
            .network
            .deny_ips
            .iter()
            .map(|s| {
                parse_ip_or_cidr(s)
                    .with_context(|| format!("invalid [network].deny_ips entry {s:?}"))
            })
            .collect::<Result<Vec<IpNet>>>()?;
        let env_allow = file.environment.allow_vars.clone();
        let env_deny = file.environment.deny_vars.clone();
        let env_local_only = file.environment.local_only_vars.clone();
        let subprocess_allow = file.subprocess.allow_commands.clone();
        let subprocess_deny = file.subprocess.deny_commands.clone();
        let subprocess_local_only = file.subprocess.local_only_commands.clone();
        let subprocess_deny_args = file.subprocess.deny_args.clone();
        let fn_derived = derive_capabilities(&file);
        let tools = file.tools.clone();
        let confirm_per_call = file.confirm_per_call.clone();
        Ok(Self {
            file,
            root,
            fs_read,
            fs_local_only_read,
            fs_write,
            fs_delete,
            fs_deny,
            net_get_hosts,
            net_post_hosts,
            net_put_hosts,
            net_patch_hosts,
            net_delete_hosts,
            net_deny_hosts,
            net_local_only_hosts,
            net_deny_ips,
            env_allow,
            env_deny,
            env_local_only,
            subprocess_allow,
            subprocess_deny,
            subprocess_local_only,
            subprocess_deny_args,
            fn_derived,
            tools,
            confirm_per_call,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn confirm_required(&self, capability: &str) -> bool {
        self.confirm_per_call.iter().any(|c| c == capability)
    }

    /// Look up `name` in `[tools]`. Returns the list of capabilities
    /// the tool requires if it's declared AND every capability is
    /// permitted by `[functions].allow`. Default-deny: an undeclared
    /// tool is rejected.
    ///
    /// This is the entry point for hosts that consult Aegis as a
    /// policy oracle — they receive a tool call by name (Bash, Read,
    /// Edit, WebFetch, WebSearch...) and want a yes/no plus the full
    /// [`ToolRecord`] (capabilities + routing hints) to act on.
    pub fn check_tool(&self, name: &str) -> Result<&ToolRecord, PolicyError> {
        let record = self.tools.get(name).ok_or_else(|| PolicyError::ToolDenied {
            name: name.to_string(),
            reason: "tool not declared in [tools]".into(),
        })?;
        for cap in &record.capabilities {
            self.check_function(cap).map_err(|e| PolicyError::ToolDenied {
                name: name.to_string(),
                reason: format!("required capability {cap:?} not allowed: {e}"),
            })?;
        }
        Ok(record)
    }

    /// Look up a tool's routing hint (URL + method + description) by
    /// name without checking capability permission. Useful for
    /// bridges that surface available tools to a model — they want
    /// the routing info even if the tool happens to fail the
    /// capability check (so they can show a clear "not enabled"
    /// reason).
    pub fn tool_routing(&self, name: &str) -> Option<&ToolRecord> {
        self.tools.get(name)
    }

    /// Whether the named capability is permitted by the policy. A
    /// capability is permitted exactly when the corresponding resource
    /// section is populated — `read_allow` or `local_only_read` for
    /// `fs.read`, `allow_commands` or `local_only_commands` for
    /// `subprocess.exec`, etc. There is no separate `[functions]`
    /// allowlist; populating a resource section is the declaration of
    /// intent.
    pub fn check_function(&self, name: &str) -> Result<(), PolicyError> {
        if self.fn_derived.iter().any(|f| *f == name) {
            return Ok(());
        }
        Err(PolicyError::FunctionDenied {
            name: name.to_string(),
            reason: format!(
                "no resource section enables {name:?} \
                 (populate [filesystem].read_allow / write_allow / \
                 delete_allow / local_only_read for fs.* capabilities; \
                 [network].http_*_allow / local_only_hosts for net.*; \
                 [environment].allow_vars / local_only_vars for \
                 env.read; [subprocess].allow_commands / \
                 local_only_commands for subprocess.exec)"
            ),
        })
    }

    /// The capabilities currently enabled. Useful for diagnostics
    /// ("what can my agent actually do?") and for hosts that want to
    /// surface the effective permission set.
    pub fn effective_functions(&self) -> Vec<&str> {
        self.fn_derived.iter().copied().collect()
    }

    pub fn check_fs_read(&self, path: &Path) -> Result<PathBuf, PolicyError> {
        self.check_fs(path, FsAction::Read)
    }
    pub fn check_fs_write(&self, path: &Path) -> Result<PathBuf, PolicyError> {
        self.check_fs(path, FsAction::Write)
    }
    pub fn check_fs_delete(&self, path: &Path) -> Result<PathBuf, PolicyError> {
        self.check_fs(path, FsAction::Delete)
    }

    fn check_fs(&self, path: &Path, action: FsAction) -> Result<PathBuf, PolicyError> {
        let resolved = resolve_path(&self.root, path);
        if self.fs_deny.is_match(&resolved) {
            return Err(PolicyError::PathDenied {
                action: action.as_str(),
                path: resolved,
                reason: "matches [filesystem].deny pattern".into(),
            });
        }
        let allow = match action {
            FsAction::Read => &self.fs_read,
            FsAction::Write => &self.fs_write,
            FsAction::Delete => &self.fs_delete,
        };
        // Reads can also be permitted by `local_only_read` (the path
        // is readable but the value will be tainted). Writes and
        // deletes have no local-only equivalent.
        let permitted = allow.is_match(&resolved)
            || (matches!(action, FsAction::Read)
                && self.fs_local_only_read.is_match(&resolved));
        if !permitted {
            return Err(PolicyError::PathDenied {
                action: action.as_str(),
                path: resolved,
                reason: format!("not in [filesystem].{}_allow", action.as_str()),
            });
        }
        Ok(resolved)
    }

    pub fn check_http_get(&self, url: &str) -> Result<Url, PolicyError> {
        self.check_http(url, HttpVerb::Get)
    }
    pub fn check_http_post(&self, url: &str) -> Result<Url, PolicyError> {
        self.check_http(url, HttpVerb::Post)
    }
    pub fn check_http_put(&self, url: &str) -> Result<Url, PolicyError> {
        self.check_http(url, HttpVerb::Put)
    }
    pub fn check_http_patch(&self, url: &str) -> Result<Url, PolicyError> {
        self.check_http(url, HttpVerb::Patch)
    }
    pub fn check_http_delete(&self, url: &str) -> Result<Url, PolicyError> {
        self.check_http(url, HttpVerb::Delete)
    }

    fn check_http(&self, url: &str, verb: HttpVerb) -> Result<Url, PolicyError> {
        let parsed = Url::parse(url).map_err(|e| PolicyError::HostDenied {
            action: verb.as_str(),
            host: url.to_string(),
            reason: format!("invalid URL: {e}"),
        })?;
        let host = parsed
            .host_str()
            .ok_or_else(|| PolicyError::HostDenied {
                action: verb.as_str(),
                host: url.to_string(),
                reason: "URL has no host".into(),
            })?
            .to_string();
        // If the host is itself an IP literal, run it through the
        // CIDR-aware deny check immediately (no DNS step needed).
        if let Ok(ip) = host.parse::<IpAddr>() {
            self.check_resolved_ip(verb.as_str(), &host, ip)?;
        }
        if self.net_deny_hosts.is_match(&host) {
            return Err(PolicyError::HostDenied {
                action: verb.as_str(),
                host,
                reason: "matches [network].deny_hosts".into(),
            });
        }
        let allow = match verb {
            HttpVerb::Get => &self.net_get_hosts,
            HttpVerb::Post => &self.net_post_hosts,
            HttpVerb::Put => &self.net_put_hosts,
            HttpVerb::Patch => &self.net_patch_hosts,
            HttpVerb::Delete => &self.net_delete_hosts,
        };
        // Hosts in `local_only_hosts` are also permitted (their
        // response bodies will be tainted at output boundaries).
        if !allow.is_match(&host) && !self.net_local_only_hosts.is_match(&host) {
            return Err(PolicyError::HostDenied {
                action: verb.as_str(),
                host,
                reason: format!("not in [network].{}_allow", verb.as_str()),
            });
        }
        Ok(parsed)
    }

    /// Pure CIDR-aware check of an already-resolved IP against
    /// `[network].deny_ips`. Pass any IP returned by DNS resolution
    /// for a request's hostname through this call before initiating
    /// the network IO. The `host_label` is used in the error and audit
    /// fields so denials carry the original hostname (e.g.
    /// `evil.example.com → 192.168.1.1 in deny_ips`).
    pub fn check_resolved_ip(
        &self,
        action: &'static str,
        host_label: &str,
        ip: IpAddr,
    ) -> Result<(), PolicyError> {
        for net in &self.net_deny_ips {
            if net.contains(&ip) {
                return Err(PolicyError::HostDenied {
                    action,
                    host: format!("{host_label} ({ip})"),
                    reason: format!("resolved IP {ip} matches [network].deny_ips entry {net}"),
                });
            }
        }
        Ok(())
    }

    pub fn check_env_read(&self, name: &str) -> Result<(), PolicyError> {
        if self.env_deny.iter().any(|n| n == name) {
            return Err(PolicyError::EnvDenied {
                name: name.to_string(),
                reason: "matches [environment].deny_vars".into(),
            });
        }
        let in_allow = self.env_allow.iter().any(|n| n == name);
        let in_local_only = self.env_local_only.iter().any(|n| n == name);
        if !in_allow && !in_local_only {
            return Err(PolicyError::EnvDenied {
                name: name.to_string(),
                reason: "not in [environment].allow_vars or local_only_vars".into(),
            });
        }
        Ok(())
    }

    /// Whether reading the env var should yield a tainted value.
    /// Local-only wins over plain allow when the same name appears in
    /// both lists.
    pub fn env_is_local_only(&self, name: &str) -> bool {
        self.env_local_only.iter().any(|n| n == name)
    }

    /// Whether the resolved filesystem path's CONTENTS, once read,
    /// should be tainted at output boundaries. Path must already have
    /// passed `check_fs_read`. Local-only wins over plain `read_allow`.
    pub fn fs_read_is_local_only(&self, resolved: &Path) -> bool {
        self.fs_local_only_read.is_match(resolved)
    }

    /// Whether subprocess output (stdout/stderr) from this command
    /// should be tainted at output boundaries. Matched by basename of
    /// argv[0], or against the full literal argv[0] for absolute-path
    /// entries.
    pub fn subprocess_is_local_only(&self, argv0: &str) -> bool {
        let basename = std::path::Path::new(argv0)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(argv0);
        self.subprocess_local_only
            .iter()
            .any(|c| c == basename || c == argv0)
    }

    /// Whether HTTP response bodies from this host should be tainted
    /// at output boundaries.
    pub fn host_is_local_only(&self, host: &str) -> bool {
        self.net_local_only_hosts.is_match(host)
    }

    /// Match argv[0] against the subprocess command policy. Both lists
    /// match against the *basename* of argv[0] (so "/usr/bin/git" and
    /// "git" both match "git"). Deny wins. Empty allowlist means "no
    /// commands at all".
    pub fn check_subprocess_command(&self, argv0: &str) -> Result<(), PolicyError> {
        let basename = std::path::Path::new(argv0)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(argv0);
        if self
            .subprocess_deny
            .iter()
            .any(|c| c == basename || c == argv0)
        {
            return Err(PolicyError::CommandDenied {
                command: argv0.to_string(),
                reason: "matches [subprocess].deny_commands".into(),
            });
        }
        if self
            .subprocess_allow
            .iter()
            .any(|c| c == basename || c == argv0)
        {
            return Ok(());
        }
        if self
            .subprocess_local_only
            .iter()
            .any(|c| c == basename || c == argv0)
        {
            // local-only command — permitted; output will be tainted.
            return Ok(());
        }
        Err(PolicyError::CommandDenied {
            command: argv0.to_string(),
            reason: "not in [subprocess].allow_commands".into(),
        })
    }

    /// Apply [subprocess.deny_args] to a fully-resolved argv. Looks up
    /// the entry by basename of argv[0] (and falls back to the literal
    /// argv[0] for absolute-path keys). Each forbidden pattern is
    /// substring-matched against the space-joined argv[1..]. First
    /// match wins.
    ///
    /// The substring discipline is deliberate: simple, predictable,
    /// auditable. It has known false-positive cases (the pattern `add`
    /// matches `bundle config add` even though the intent was to block
    /// `bundle add`). Mitigation: write more specific patterns
    /// (`"add "` with a trailing space, or `"add gem-name"`).
    pub fn check_subprocess_args(&self, argv: &[String]) -> Result<(), PolicyError> {
        if argv.is_empty() {
            return Ok(());
        }
        let argv0 = &argv[0];
        let basename = std::path::Path::new(argv0)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(argv0);
        let patterns = self
            .subprocess_deny_args
            .get(basename)
            .or_else(|| self.subprocess_deny_args.get(argv0));
        let Some(patterns) = patterns else {
            return Ok(());
        };
        let joined = argv[1..].join(" ");
        for pattern in patterns {
            if joined.contains(pattern) {
                return Err(PolicyError::ArgsDenied {
                    command: argv0.clone(),
                    pattern: pattern.clone(),
                    reason: format!("argument matches [subprocess.deny_args].{}", basename),
                });
            }
        }
        Ok(())
    }

    /// Snapshot of the underlying file for audit log provenance.
    pub fn file_snapshot(&self) -> &PolicyFile {
        &self.file
    }
}

#[derive(Copy, Clone, Debug)]
enum FsAction {
    Read,
    Write,
    Delete,
}
impl FsAction {
    fn as_str(self) -> &'static str {
        match self {
            FsAction::Read => "read",
            FsAction::Write => "write",
            FsAction::Delete => "delete",
        }
    }
}

#[derive(Copy, Clone, Debug)]
enum HttpVerb {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}
impl HttpVerb {
    fn as_str(self) -> &'static str {
        match self {
            HttpVerb::Get => "http_get",
            HttpVerb::Post => "http_post",
            HttpVerb::Put => "http_put",
            HttpVerb::Patch => "http_patch",
            HttpVerb::Delete => "http_delete",
        }
    }
}

#[derive(Debug, Clone)]
struct PathMatcher {
    set: GlobSet,
}

impl PathMatcher {
    fn build(root: &Path, patterns: &[String]) -> Result<Self> {
        let mut builder = GlobSetBuilder::new();
        for raw in patterns {
            let translated = translate_pattern(root, raw);
            let glob = Glob::new(&translated)
                .with_context(|| format!("policy pattern {raw:?}"))?;
            builder.add(glob);
        }
        Ok(Self {
            set: builder.build()?,
        })
    }
    fn is_match(&self, path: &Path) -> bool {
        self.set.is_match(path)
    }
}

#[derive(Debug, Clone)]
struct HostMatcher {
    set: GlobSet,
}

impl HostMatcher {
    fn build(patterns: &[String]) -> Result<Self> {
        let mut builder = GlobSetBuilder::new();
        for raw in patterns {
            let glob = Glob::new(raw)
                .with_context(|| format!("policy host pattern {raw:?}"))?;
            builder.add(glob);
        }
        Ok(Self {
            set: builder.build()?,
        })
    }
    fn is_match(&self, host: &str) -> bool {
        self.set.is_match(host)
    }
}

/// Translate a user-facing path pattern into an absolute globset pattern.
///
/// Rules:
/// - `~/foo` → `<home>/foo`
/// - `/abs/foo` → unchanged
/// - relative pattern with no `/` (e.g. `.env`) → `<root>/**/<pattern>`
///   so it matches anywhere under root, mirroring gitignore behavior.
/// - relative pattern with `/` (e.g. `src/**`) → `<root>/<pattern>`
fn translate_pattern(root: &Path, raw: &str) -> String {
    if let Some(rest) = raw.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            return format!("{}/{}", home.display(), rest);
        }
    }
    if raw == "~" {
        if let Some(home) = home_dir() {
            return home.display().to_string();
        }
    }
    if raw.starts_with('/') {
        return raw.to_string();
    }
    if !raw.contains('/') {
        return format!("{}/**/{}", root.display(), raw);
    }
    format!("{}/{}", root.display(), raw)
}

/// Parse an entry from `[network].deny_ips` into an `IpNet`. Accepts
/// both literal IPs (`"169.254.169.254"`, `"::1"`) — coerced to a host
/// network with the appropriate prefix length — and CIDR ranges
/// (`"10.0.0.0/8"`, `"fc00::/7"`).
fn parse_ip_or_cidr(s: &str) -> Result<IpNet> {
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(net);
    }
    let ip: IpAddr = s
        .parse()
        .with_context(|| format!("not a valid IP or CIDR: {s:?}"))?;
    Ok(match ip {
        IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::new(v4, 32).expect("valid /32")),
        IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::new(v6, 128).expect("valid /128")),
    })
}

/// Compute the set of capabilities implied by populated resource
/// sections. Used when `[functions].allow` is absent: any non-empty
/// resource list is read as the operator declaring intent to use the
/// matching capability.
///
/// Local-only and plain allow lists both count: if you list any host
/// in `local_only_hosts`, you implicitly intend the corresponding
/// HTTP verbs to be usable.
fn derive_capabilities(file: &PolicyFile) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    let fs = &file.filesystem;
    if !fs.read_allow.is_empty() || !fs.local_only_read.is_empty() {
        out.push("fs.read");
    }
    if !fs.write_allow.is_empty() {
        out.push("fs.write");
    }
    if !fs.delete_allow.is_empty() {
        out.push("fs.delete");
    }
    let net = &file.network;
    let any_local_only_host = !net.local_only_hosts.is_empty();
    if !net.http_get_allow.is_empty() || any_local_only_host {
        out.push("net.http_get");
    }
    if !net.http_post_allow.is_empty() || any_local_only_host {
        out.push("net.http_post");
    }
    if !net.http_put_allow.is_empty() || any_local_only_host {
        out.push("net.http_put");
    }
    if !net.http_patch_allow.is_empty() || any_local_only_host {
        out.push("net.http_patch");
    }
    if !net.http_delete_allow.is_empty() || any_local_only_host {
        out.push("net.http_delete");
    }
    let env = &file.environment;
    if !env.allow_vars.is_empty() || !env.local_only_vars.is_empty() {
        out.push("env.read");
    }
    let sub = &file.subprocess;
    if !sub.allow_commands.is_empty() || !sub.local_only_commands.is_empty() {
        out.push("subprocess.exec");
    }
    out
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Resolve a user-supplied path to an absolute path. Steps:
/// - `~/...` expands to `$HOME/...` (and a bare `~` to `$HOME`).
/// - relative paths are joined with `root`.
/// - `.` and `..` components are normalized.
///
/// Does not require the path to exist (writes can target new files).
fn resolve_path(root: &Path, p: &Path) -> PathBuf {
    let raw = if let Some(s) = p.to_str() {
        if s == "~" {
            home_dir().unwrap_or_else(|| p.to_path_buf())
        } else if let Some(rest) = s.strip_prefix("~/") {
            home_dir()
                .map(|h| h.join(rest))
                .unwrap_or_else(|| p.to_path_buf())
        } else if p.is_absolute() {
            p.to_path_buf()
        } else {
            root.join(p)
        }
    } else if p.is_absolute() {
        p.to_path_buf()
    } else {
        root.join(p)
    };

    let mut out = PathBuf::new();
    for c in raw.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

