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
    #[serde(default)]
    pub functions: FunctionPolicy,
    #[serde(default)]
    pub confirm_per_call: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FilesystemPolicy {
    #[serde(default)]
    pub read_allow: Vec<String>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FunctionPolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SubprocessPolicy {
    /// Commands the script may exec, matched against the basename of
    /// argv[0]. Empty means "no commands at all", even if the
    /// `subprocess.exec` capability is otherwise allowed.
    #[serde(default)]
    pub allow_commands: Vec<String>,
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
            deny_args: merge_deny_args(base.subprocess.deny_args, over.subprocess.deny_args),
        },
        functions: FunctionPolicy {
            allow: concat_dedup(base.functions.allow, over.functions.allow),
            deny: concat_dedup(base.functions.deny, over.functions.deny),
        },
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
    fs_write: PathMatcher,
    fs_delete: PathMatcher,
    fs_deny: PathMatcher,
    net_get_hosts: HostMatcher,
    net_post_hosts: HostMatcher,
    net_deny_hosts: HostMatcher,
    /// Parsed deny_ips entries, each held as an `IpNet`. Literal IPs
    /// (`169.254.169.254`) are stored as host networks (`/32` or
    /// `/128`); CIDR ranges (`10.0.0.0/8`) are stored as-is.
    net_deny_ips: Vec<IpNet>,
    env_allow: Vec<String>,
    env_deny: Vec<String>,
    subprocess_allow: Vec<String>,
    subprocess_deny: Vec<String>,
    subprocess_deny_args: std::collections::BTreeMap<String, Vec<String>>,
    fn_allow: Vec<String>,
    fn_deny: Vec<String>,
    confirm_per_call: Vec<String>,
}

impl Policy {
    /// Load a policy file, anchoring relative path patterns at the
    /// process current working directory.
    pub fn load(path: &Path) -> Result<Self> {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        Self::load_with_root(path, cwd)
    }

    /// Load a policy file, anchoring relative path patterns at `root`.
    /// `root` is also where relative path arguments at runtime are
    /// resolved against.
    pub fn load_with_root(path: &Path, root: PathBuf) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read policy file {path:?}"))?;
        let file = PolicyFile::from_toml_str(&raw)?.resolve_inheritance()?;
        let root = std::fs::canonicalize(&root).unwrap_or(root);
        Self::from_file(file, root)
    }

    pub fn from_file(file: PolicyFile, root: PathBuf) -> Result<Self> {
        let fs_read = PathMatcher::build(&root, &file.filesystem.read_allow)?;
        let fs_write = PathMatcher::build(&root, &file.filesystem.write_allow)?;
        let fs_delete = PathMatcher::build(&root, &file.filesystem.delete_allow)?;
        let fs_deny = PathMatcher::build(&root, &file.filesystem.deny)?;
        let net_get_hosts = HostMatcher::build(&file.network.http_get_allow)?;
        let net_post_hosts = HostMatcher::build(&file.network.http_post_allow)?;
        let net_deny_hosts = HostMatcher::build(&file.network.deny_hosts)?;
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
        let subprocess_allow = file.subprocess.allow_commands.clone();
        let subprocess_deny = file.subprocess.deny_commands.clone();
        let subprocess_deny_args = file.subprocess.deny_args.clone();
        let fn_allow = file.functions.allow.clone();
        let fn_deny = file.functions.deny.clone();
        let confirm_per_call = file.confirm_per_call.clone();
        Ok(Self {
            file,
            root,
            fs_read,
            fs_write,
            fs_delete,
            fs_deny,
            net_get_hosts,
            net_post_hosts,
            net_deny_hosts,
            net_deny_ips,
            env_allow,
            env_deny,
            subprocess_allow,
            subprocess_deny,
            subprocess_deny_args,
            fn_allow,
            fn_deny,
            confirm_per_call,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn confirm_required(&self, capability: &str) -> bool {
        self.confirm_per_call.iter().any(|c| c == capability)
    }

    pub fn check_function(&self, name: &str) -> Result<(), PolicyError> {
        if self.fn_deny.iter().any(|f| f == name) {
            return Err(PolicyError::FunctionDenied {
                name: name.to_string(),
                reason: "explicit deny in [functions].deny".into(),
            });
        }
        if self.fn_allow.iter().any(|f| f == name) {
            return Ok(());
        }
        Err(PolicyError::FunctionDenied {
            name: name.to_string(),
            reason: "not in [functions].allow allowlist".into(),
        })
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
        if !allow.is_match(&resolved) {
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
        };
        if !allow.is_match(&host) {
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
        if !self.env_allow.iter().any(|n| n == name) {
            return Err(PolicyError::EnvDenied {
                name: name.to_string(),
                reason: "not in [environment].allow_vars".into(),
            });
        }
        Ok(())
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
}
impl HttpVerb {
    fn as_str(self) -> &'static str {
        match self {
            HttpVerb::Get => "http_get",
            HttpVerb::Post => "http_post",
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

#[cfg(test)]
mod tests {
    use super::*;

    fn dev_policy() -> Policy {
        let toml = r#"
[filesystem]
read_allow = ["src/**", "/tmp/**"]
write_allow = ["/tmp/**"]
delete_allow = ["/tmp/**"]
deny = ["~/.aws/**", ".env", "**/secrets/**"]

[network]
http_get_allow = ["api.github.com", "*.npmjs.org"]
http_post_allow = []
deny_hosts = ["evil.example.com"]
deny_ips = ["169.254.169.254"]

[functions]
allow = ["fs.read", "net.http_get"]
deny = []
"#;
        let file = PolicyFile::from_toml_str(toml).unwrap();
        Policy::from_file(file, PathBuf::from("/work")).unwrap()
    }

    #[test]
    fn fn_allow_and_deny() {
        let p = dev_policy();
        assert!(p.check_function("fs.read").is_ok());
        assert!(p.check_function("subprocess.exec").is_err());
    }

    #[test]
    fn fs_read_allow_relative() {
        let p = dev_policy();
        assert!(p.check_fs_read(Path::new("src/main.rs")).is_ok());
    }

    #[test]
    fn fs_read_deny_credential() {
        let p = dev_policy();
        let home = home_dir().unwrap_or(PathBuf::from("/home/x"));
        let creds = home.join(".aws/credentials");
        assert!(p.check_fs_read(&creds).is_err());
    }

    #[test]
    fn fs_read_anywhere_dot_env() {
        let p = dev_policy();
        // `.env` should match anywhere under root via gitignore-ish translation.
        assert!(p.check_fs_read(Path::new("/work/sub/.env")).is_err());
    }

    #[test]
    fn fs_write_outside_tmp_denied() {
        let p = dev_policy();
        assert!(p.check_fs_write(Path::new("/work/src/main.rs")).is_err());
        assert!(p.check_fs_write(Path::new("/tmp/out.txt")).is_ok());
    }

    #[test]
    fn http_get_allow_host_glob() {
        let p = dev_policy();
        assert!(p.check_http_get("https://api.github.com/repos").is_ok());
        assert!(p.check_http_get("https://registry.npmjs.org/foo").is_ok());
        assert!(p.check_http_get("https://evil.example.com/").is_err());
        assert!(p.check_http_get("https://169.254.169.254/").is_err());
    }

    fn cidr_policy() -> Policy {
        let toml = r#"
[network]
http_get_allow = ["api.github.com"]
deny_ips = [
    "169.254.0.0/16",
    "10.0.0.0/8",
    "127.0.0.1",      # literal — should be coerced to /32
    "::1",            # literal IPv6
]

[functions]
allow = ["net.http_get"]
"#;
        let file = PolicyFile::from_toml_str(toml).unwrap();
        Policy::from_file(file, PathBuf::from("/work")).unwrap()
    }

    #[test]
    fn cidr_blocks_link_local_range() {
        let p = cidr_policy();
        // any IP in 169.254.0.0/16
        assert!(p
            .check_http_get("https://169.254.169.254/latest/meta-data/")
            .is_err());
        assert!(p.check_http_get("https://169.254.0.1/").is_err());
        assert!(p.check_http_get("https://169.254.255.255/").is_err());
        // Outside the /16
        assert!(p.check_http_get("https://169.255.0.1/").is_err()); // outside CIDR but not allowed → host-allow check rejects
    }

    #[test]
    fn cidr_blocks_rfc1918_range() {
        let p = cidr_policy();
        for ip in ["10.0.0.1", "10.0.0.255", "10.255.255.255"] {
            let url = format!("https://{ip}/admin");
            let err = p.check_http_get(&url).unwrap_err().to_string();
            assert!(err.contains("deny_ips"), "expected CIDR rejection for {ip}, got: {err}");
        }
    }

    #[test]
    fn literal_ip_in_deny_ips_works() {
        let p = cidr_policy();
        assert!(p.check_http_get("https://127.0.0.1/").is_err());
        assert!(p.check_http_get("https://[::1]/").is_err());
    }

    #[test]
    fn check_resolved_ip_pure() {
        let p = cidr_policy();
        // hostname-style label, IP from a hypothetical DNS resolution
        let internal: IpAddr = "192.168.1.1".parse().unwrap();
        // not in any deny_ips entry → allowed
        assert!(p
            .check_resolved_ip("http_get", "internal.example.com", internal)
            .is_ok());

        let metadata: IpAddr = "169.254.169.254".parse().unwrap();
        let err = p
            .check_resolved_ip("http_get", "metadata.example.com", metadata)
            .unwrap_err()
            .to_string();
        assert!(err.contains("169.254.0.0/16"), "{err}");
        assert!(err.contains("metadata.example.com"), "{err}");
    }

    fn full_policy() -> Policy {
        let toml = r#"
[environment]
allow_vars = ["PATH", "USER"]
deny_vars = ["AWS_SECRET_ACCESS_KEY"]

[subprocess]
allow_commands = ["git", "/usr/local/bin/npm"]
deny_commands = ["rm", "dd", "shred"]

[functions]
allow = ["env.read", "subprocess.exec"]
"#;
        let file = PolicyFile::from_toml_str(toml).unwrap();
        Policy::from_file(file, PathBuf::from("/work")).unwrap()
    }

    #[test]
    fn env_allow_and_deny() {
        let p = full_policy();
        assert!(p.check_env_read("PATH").is_ok());
        assert!(p.check_env_read("USER").is_ok());
        assert!(p.check_env_read("HOME").is_err()); // not in allow_vars
        assert!(p.check_env_read("AWS_SECRET_ACCESS_KEY").is_err()); // explicit deny
    }

    #[test]
    fn subprocess_command_allow_basename() {
        let p = full_policy();
        // bare command name in allow
        assert!(p.check_subprocess_command("git").is_ok());
        // /usr/bin/git matches because basename match
        assert!(p.check_subprocess_command("/usr/bin/git").is_ok());
        // explicit absolute path in allow
        assert!(p.check_subprocess_command("/usr/local/bin/npm").is_ok());
        // basename of /usr/bin/npm is "npm" which is NOT in allow (only "/usr/local/bin/npm" is)
        assert!(p.check_subprocess_command("/usr/bin/npm").is_err());
    }

    #[test]
    fn subprocess_command_deny_wins() {
        let p = full_policy();
        assert!(p.check_subprocess_command("rm").is_err());
        assert!(p.check_subprocess_command("/bin/rm").is_err()); // basename
        assert!(p.check_subprocess_command("dd").is_err());
    }

    #[test]
    fn subprocess_unknown_command_denied() {
        let p = full_policy();
        assert!(p.check_subprocess_command("curl").is_err());
        assert!(p.check_subprocess_command("ssh").is_err());
    }

    fn deny_args_policy() -> Policy {
        let toml = r#"
[subprocess]
allow_commands = ["git", "rails", "bundle"]

[subprocess.deny_args]
git = ["push --force", "push -f", "reset --hard"]
rails = ["db:drop", "db:reset"]
bundle = ["add", "publish"]

[functions]
allow = ["subprocess.exec"]
"#;
        let file = PolicyFile::from_toml_str(toml).unwrap();
        Policy::from_file(file, PathBuf::from("/work")).unwrap()
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn deny_args_blocks_multitoken_pattern() {
        let p = deny_args_policy();
        // git push --force origin main → blocked by "push --force"
        let r = p.check_subprocess_args(&argv(&["git", "push", "--force", "origin", "main"]));
        assert!(r.is_err());
        let err = r.unwrap_err().to_string();
        assert!(err.contains("push --force"), "{err}");
    }

    #[test]
    fn deny_args_basename_match() {
        let p = deny_args_policy();
        // /usr/bin/git push -f → still matches via basename
        let r = p.check_subprocess_args(&argv(&["/usr/bin/git", "push", "-f"]));
        assert!(r.is_err());
    }

    #[test]
    fn deny_args_allows_safe_invocation() {
        let p = deny_args_policy();
        assert!(p
            .check_subprocess_args(&argv(&["git", "push", "origin", "main"]))
            .is_ok());
        assert!(p
            .check_subprocess_args(&argv(&["git", "log", "--oneline"]))
            .is_ok());
    }

    #[test]
    fn deny_args_single_token_pattern() {
        let p = deny_args_policy();
        // bundle add gem-name → blocked by "add"
        assert!(p
            .check_subprocess_args(&argv(&["bundle", "add", "rails"]))
            .is_err());
        // rails db:drop → blocked
        assert!(p
            .check_subprocess_args(&argv(&["rails", "db:drop"]))
            .is_err());
        // rails server → no entry matches
        assert!(p
            .check_subprocess_args(&argv(&["rails", "server"]))
            .is_ok());
    }

    #[test]
    fn deny_args_command_with_no_entry_is_allowed() {
        let p = deny_args_policy();
        // npm not in deny_args map at all
        assert!(p
            .check_subprocess_args(&argv(&["npm", "publish"]))
            .is_ok());
    }

    #[test]
    fn deny_args_empty_argv_is_noop() {
        let p = deny_args_policy();
        assert!(p.check_subprocess_args(&[]).is_ok());
    }

    #[test]
    fn inherits_secure_defaults_pulls_in_baseline_denies() {
        // Minimal user file with no boilerplate.
        let user = r#"
inherits = "secure-defaults"

[filesystem]
read_allow = ["src/**"]
write_allow = ["src/**"]

[functions]
allow = ["fs.read", "fs.write"]
"#;
        let file = PolicyFile::from_toml_str(user)
            .unwrap()
            .resolve_inheritance()
            .unwrap();
        let p = Policy::from_file(file, PathBuf::from("/work")).unwrap();

        // Inherited fs deny list catches credentials.
        let home = home_dir().unwrap_or_else(|| PathBuf::from("/home/x"));
        let creds = home.join(".aws/credentials");
        assert!(p.check_fs_read(&creds).is_err());

        // Inherited deny_vars catches OPENAI_API_KEY.
        assert!(p.check_env_read("OPENAI_API_KEY").is_err());

        // Inherited deny_commands catches rm/sudo/kubectl.
        assert!(p.check_subprocess_command("rm").is_err());
        assert!(p.check_subprocess_command("kubectl").is_err());

        // The user's own allow_list still applies.
        assert!(p.check_fs_read(Path::new("/work/src/main.rs")).is_ok());
    }

    #[test]
    fn user_extends_preset_deny_lists() {
        let user = r#"
inherits = "secure-defaults"

[filesystem]
read_allow = ["src/**"]
deny = ["**/Gemfile.lock"]    # extra deny on top of preset's

[functions]
allow = ["fs.read"]
"#;
        let file = PolicyFile::from_toml_str(user)
            .unwrap()
            .resolve_inheritance()
            .unwrap();

        // User's deny entry survived.
        assert!(file.filesystem.deny.iter().any(|p| p == "**/Gemfile.lock"));
        // Preset's deny entries also survived.
        assert!(file.filesystem.deny.iter().any(|p| p == "~/.aws/**"));
        assert!(file.filesystem.deny.iter().any(|p| p == ".env"));
    }

    #[test]
    fn override_can_remove_preset_filesystem_deny() {
        let user = r#"
inherits = "secure-defaults"

[filesystem]
read_allow = ["~/.aws/**"]      # we WANT to read aws creds
deny = ["!~/.aws/**"]           # remove the inherited block

[functions]
allow = ["fs.read"]
"#;
        let file = PolicyFile::from_toml_str(user)
            .unwrap()
            .resolve_inheritance()
            .unwrap();
        // The preset's universal `~/.aws/**` deny is gone.
        assert!(!file.filesystem.deny.iter().any(|p| p == "~/.aws/**"));
        // Other inherited denies are still there.
        assert!(file.filesystem.deny.iter().any(|p| p == "**/.env"));
    }

    #[test]
    fn override_can_unblock_preset_subprocess_command() {
        // Preset blocks kubectl. A k8s operator agent legitimately
        // needs it inside a kind/minikube sandbox.
        let user = r#"
inherits = "secure-defaults"

[subprocess]
allow_commands = ["kubectl"]
deny_commands = ["!kubectl"]    # un-deny

[functions]
allow = ["subprocess.exec"]
"#;
        let file = PolicyFile::from_toml_str(user)
            .unwrap()
            .resolve_inheritance()
            .unwrap();
        assert!(!file.subprocess.deny_commands.iter().any(|c| c == "kubectl"));
        // Other inherited denies remain.
        assert!(file.subprocess.deny_commands.iter().any(|c| c == "rm"));
        assert!(file.subprocess.deny_commands.iter().any(|c| c == "sudo"));
    }

    #[test]
    fn override_can_remove_preset_deny_ip_cidr() {
        // Local dev: legitimately want to talk to a service on
        // 127.0.0.1 (the preset's loopback block normally prevents this).
        let user = r#"
inherits = "secure-defaults"

[network]
http_get_allow = ["localhost"]
deny_ips = ["!127.0.0.0/8"]

[functions]
allow = ["net.http_get"]
"#;
        let file = PolicyFile::from_toml_str(user)
            .unwrap()
            .resolve_inheritance()
            .unwrap();
        assert!(!file.network.deny_ips.iter().any(|p| p == "127.0.0.0/8"));
        // Cloud metadata block survives.
        assert!(file
            .network
            .deny_ips
            .iter()
            .any(|p| p == "169.254.0.0/16"));
        // Final policy parses cleanly (no leftover "!..." strings).
        let p = Policy::from_file(file, PathBuf::from("/work")).unwrap();
        // Confirm the IP-level check now lets 127.0.0.1 through.
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(p.check_resolved_ip("http_get", "localhost", ip).is_ok());
        // ...while 169.254.169.254 is still rejected.
        let metadata: IpAddr = "169.254.169.254".parse().unwrap();
        assert!(p
            .check_resolved_ip("http_get", "metadata", metadata)
            .is_err());
    }

    #[test]
    fn override_negate_nonexistent_is_silent_noop() {
        let user = r#"
inherits = "secure-defaults"

[filesystem]
read_allow = ["src/**"]
deny = ["!~/never-was-in-the-preset/**"]

[functions]
allow = ["fs.read"]
"#;
        // No error; merged file just doesn't have that entry.
        let file = PolicyFile::from_toml_str(user)
            .unwrap()
            .resolve_inheritance()
            .unwrap();
        // The `!` form is consumed, not retained.
        assert!(!file
            .filesystem
            .deny
            .iter()
            .any(|p| p.starts_with('!')));
    }

    #[test]
    fn override_can_remove_preset_confirm() {
        let user = r#"
inherits = "secure-defaults"
confirm_per_call = ["!subprocess.exec"]

[functions]
allow = ["subprocess.exec"]
"#;
        let file = PolicyFile::from_toml_str(user)
            .unwrap()
            .resolve_inheritance()
            .unwrap();
        // subprocess.exec is no longer prompt-gated.
        assert!(!file
            .confirm_per_call
            .iter()
            .any(|c| c == "subprocess.exec"));
        // fs.delete is still prompt-gated.
        assert!(file.confirm_per_call.iter().any(|c| c == "fs.delete"));
    }

    #[test]
    fn override_can_remove_specific_deny_args_pattern() {
        let preset_like = r#"
[subprocess.deny_args]
git = ["push --force", "reset --hard"]
"#;
        let user = r#"
[subprocess.deny_args]
git = ["!reset --hard"]
"#;
        let base = PolicyFile::from_toml_str(preset_like).unwrap();
        let over = PolicyFile::from_toml_str(user).unwrap();
        let merged = merge_policy_files(base, over);
        let git_args = merged.subprocess.deny_args.get("git").unwrap();
        assert!(git_args.contains(&"push --force".to_string()));
        assert!(!git_args.contains(&"reset --hard".to_string()));
    }

    #[test]
    fn unknown_preset_errors_clearly() {
        let user = r#"inherits = "does-not-exist""#;
        let res = PolicyFile::from_toml_str(user)
            .unwrap()
            .resolve_inheritance();
        assert!(res.is_err());
        let msg = res.unwrap_err().to_string();
        assert!(msg.contains("does-not-exist"));
    }

    #[test]
    fn deny_args_merge_concatenates_per_command() {
        // Preset has no deny_args; user provides some. Then a derived
        // file (synthesized in test) merges in additional patterns.
        let base_toml = r#"
[subprocess.deny_args]
git = ["push --force"]
"#;
        let over_toml = r#"
[subprocess.deny_args]
git = ["reset --hard"]
rails = ["db:drop"]
"#;
        let base = PolicyFile::from_toml_str(base_toml).unwrap();
        let over = PolicyFile::from_toml_str(over_toml).unwrap();
        let merged = merge_policy_files(base, over);
        let git_args = merged.subprocess.deny_args.get("git").unwrap();
        assert!(git_args.contains(&"push --force".to_string()));
        assert!(git_args.contains(&"reset --hard".to_string()));
        let rails_args = merged.subprocess.deny_args.get("rails").unwrap();
        assert!(rails_args.contains(&"db:drop".to_string()));
    }

}
