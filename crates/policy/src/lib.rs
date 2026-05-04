//! Aegis policy types and runtime matchers.
//!
//! Policy is parsed configuration data, not executable code, so an agent
//! script cannot mutate or rewrite the policy from inside the sandbox.
//! Three sections: filesystem (gitignore-style path rules), network
//! (host/IP allowlist + denylist), and functions (Starlark builtin
//! allowlist).

use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

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
    /// Schema for declaring database access. The Aegis runtime does not
    /// enforce this section directly (no db.* builtins yet); it's part
    /// of the portable policy schema so other agentic systems and
    /// future Aegis versions can read it.
    #[serde(default)]
    pub database: DatabasePolicy,
    /// Schema for declaring deployment / infrastructure access. Same
    /// portability story as `database`.
    #[serde(default)]
    pub deployment: DeploymentPolicy,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DatabasePolicy {
    /// Allowed connections. Connection name is opaque to the policy
    /// engine — the host integration maps a name to a real DSN.
    #[serde(default)]
    pub connections: Vec<DatabaseConnection>,
    /// Connections the agent must never reference (production primary,
    /// admin handles, etc.). Deny wins over `connections`.
    #[serde(default)]
    pub deny_connections: Vec<String>,
    /// SQL operations the agent must never run on any connection,
    /// regardless of read/write flags. Operations are matched
    /// case-insensitively against the leading keyword of a query.
    /// Examples: `"DROP"`, `"TRUNCATE"`, `"ALTER"`, `"CREATE USER"`.
    #[serde(default)]
    pub deny_operations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DatabaseConnection {
    pub name: String,
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub write: bool,
    /// Schemas the agent may touch on this connection. Empty = no
    /// restriction (subject to deny_tables).
    #[serde(default)]
    pub schemas_allow: Vec<String>,
    /// Tables the agent must not touch even on a writable connection.
    /// Globs are permitted ("auth.*", "billing.*").
    #[serde(default)]
    pub tables_deny: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeploymentPolicy {
    /// Per-target action allowlist. Targets are symbolic names
    /// (`"dev"`, `"staging"`, `"prod_eu"`); the host integration maps
    /// those onto kubectl contexts, AWS profiles, terraform workspaces,
    /// etc.
    #[serde(default)]
    pub targets: Vec<DeploymentTarget>,
    /// Targets the agent must never address.
    #[serde(default)]
    pub deny_targets: Vec<String>,
    /// Tools the policy speaks to (kubectl, terraform, aws, gcloud,
    /// flyctl). Acts as a hint to host integrations — the actual
    /// enforcement of which tool is invoked usually flows through
    /// [subprocess].allow_commands.
    #[serde(default)]
    pub tools: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeploymentTarget {
    pub name: String,
    /// Action verbs allowed on this target. Conventional verbs:
    /// "get", "describe", "logs", "status", "apply", "rollout",
    /// "scale", "delete", "exec". Globs permitted ("*").
    #[serde(default)]
    pub allow_actions: Vec<String>,
    /// Verbs forbidden on this target; deny wins over allow.
    #[serde(default)]
    pub deny_actions: Vec<String>,
    /// Free-form note for humans (why this target has these rules).
    #[serde(default)]
    pub note: Option<String>,
}

impl PolicyFile {
    pub fn from_toml_str(s: &str) -> Result<Self> {
        toml::from_str(s).context("parse policy TOML")
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
    net_deny_ips: Vec<String>,
    env_allow: Vec<String>,
    env_deny: Vec<String>,
    subprocess_allow: Vec<String>,
    subprocess_deny: Vec<String>,
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
        let file: PolicyFile = PolicyFile::from_toml_str(&raw)?;
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
        let net_deny_ips = file.network.deny_ips.clone();
        let env_allow = file.environment.allow_vars.clone();
        let env_deny = file.environment.deny_vars.clone();
        let subprocess_allow = file.subprocess.allow_commands.clone();
        let subprocess_deny = file.subprocess.deny_commands.clone();
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
        if self.net_deny_ips.iter().any(|ip| ip == &host) {
            return Err(PolicyError::HostDenied {
                action: verb.as_str(),
                host,
                reason: "matches [network].deny_ips".into(),
            });
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

    #[test]
    fn database_and_deployment_sections_deserialize() {
        let toml = r#"
version = "1"
name = "fastapi_prod_readonly"

[database]
deny_connections = ["prod_primary"]
deny_operations = ["DROP", "TRUNCATE", "ALTER"]

[[database.connections]]
name = "prod_replica"
read = true
write = false
schemas_allow = ["public", "analytics"]
tables_deny = ["users", "auth.*", "billing.*"]

[deployment]
deny_targets = ["prod_us_primary"]
tools = ["kubectl", "aws"]

[[deployment.targets]]
name = "prod_eu"
allow_actions = ["get", "describe", "logs"]
deny_actions = ["delete", "scale", "apply"]
note = "Read-only diagnostic access only"
"#;
        let file = PolicyFile::from_toml_str(toml).unwrap();
        assert_eq!(file.version.as_deref(), Some("1"));
        assert_eq!(file.database.connections.len(), 1);
        assert_eq!(file.database.connections[0].name, "prod_replica");
        assert!(file.database.connections[0].read);
        assert!(!file.database.connections[0].write);
        assert_eq!(file.deployment.targets.len(), 1);
        assert_eq!(file.deployment.targets[0].name, "prod_eu");
        assert_eq!(
            file.deployment.targets[0].allow_actions,
            vec!["get".to_string(), "describe".to_string(), "logs".to_string()]
        );
    }
}
