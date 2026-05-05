//! Integration tests for `aegis_policy`. Exercises only the public API:
//! `PolicyFile::from_toml_str`, `Policy::from_file`, `Policy::check_*`,
//! preset inheritance, and `PolicyFile::merge_with`.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use aegis_policy::{Policy, PolicyFile};

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/home/x"))
}

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
    let creds = home_dir().join(".aws/credentials");
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

#[test]
fn http_verb_allow_lists_independent() {
    let toml = r#"
[network]
http_get_allow    = ["api.github.com"]
http_post_allow   = ["api.example.com"]
http_put_allow    = ["api.example.com"]
http_patch_allow  = ["api.example.com"]
http_delete_allow = ["api.example.com"]

[functions]
allow = ["net.http_get", "net.http_post", "net.http_put", "net.http_patch", "net.http_delete"]
"#;
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let p = Policy::from_file(file, PathBuf::from("/work")).unwrap();
    assert!(p.check_http_get("https://api.github.com/zen").is_ok());
    assert!(p.check_http_get("https://api.example.com/").is_err());
    assert!(p.check_http_post("https://api.example.com/x").is_ok());
    assert!(p.check_http_post("https://api.github.com/x").is_err());
    assert!(p.check_http_put("https://api.example.com/x").is_ok());
    assert!(p.check_http_patch("https://api.example.com/x").is_ok());
    assert!(p.check_http_delete("https://api.example.com/x").is_ok());
    assert!(p.check_http_put("https://api.github.com/x").is_err());
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
    assert!(p
        .check_http_get("https://169.254.169.254/latest/meta-data/")
        .is_err());
    assert!(p.check_http_get("https://169.254.0.1/").is_err());
    assert!(p.check_http_get("https://169.254.255.255/").is_err());
    assert!(p.check_http_get("https://169.255.0.1/").is_err());
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
    let internal: IpAddr = "192.168.1.1".parse().unwrap();
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
    assert!(p.check_env_read("HOME").is_err());
    assert!(p.check_env_read("AWS_SECRET_ACCESS_KEY").is_err());
}

#[test]
fn subprocess_command_allow_basename() {
    let p = full_policy();
    assert!(p.check_subprocess_command("git").is_ok());
    assert!(p.check_subprocess_command("/usr/bin/git").is_ok());
    assert!(p.check_subprocess_command("/usr/local/bin/npm").is_ok());
    assert!(p.check_subprocess_command("/usr/bin/npm").is_err());
}

#[test]
fn subprocess_command_deny_wins() {
    let p = full_policy();
    assert!(p.check_subprocess_command("rm").is_err());
    assert!(p.check_subprocess_command("/bin/rm").is_err());
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
    let r = p.check_subprocess_args(&argv(&["git", "push", "--force", "origin", "main"]));
    assert!(r.is_err());
    let err = r.unwrap_err().to_string();
    assert!(err.contains("push --force"), "{err}");
}

#[test]
fn deny_args_basename_match() {
    let p = deny_args_policy();
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
    assert!(p
        .check_subprocess_args(&argv(&["bundle", "add", "rails"]))
        .is_err());
    assert!(p
        .check_subprocess_args(&argv(&["rails", "db:drop"]))
        .is_err());
    assert!(p
        .check_subprocess_args(&argv(&["rails", "server"]))
        .is_ok());
}

#[test]
fn deny_args_command_with_no_entry_is_allowed() {
    let p = deny_args_policy();
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

    let creds = home_dir().join(".aws/credentials");
    assert!(p.check_fs_read(&creds).is_err());

    assert!(p.check_env_read("OPENAI_API_KEY").is_err());

    assert!(p.check_subprocess_command("rm").is_err());
    assert!(p.check_subprocess_command("kubectl").is_err());

    assert!(p.check_fs_read(Path::new("/work/src/main.rs")).is_ok());
}

#[test]
fn user_extends_preset_deny_lists() {
    let user = r#"
inherits = "secure-defaults"

[filesystem]
read_allow = ["src/**"]
deny = ["**/Gemfile.lock"]

[functions]
allow = ["fs.read"]
"#;
    let file = PolicyFile::from_toml_str(user)
        .unwrap()
        .resolve_inheritance()
        .unwrap();
    assert!(file.filesystem.deny.iter().any(|p| p == "**/Gemfile.lock"));
    assert!(file.filesystem.deny.iter().any(|p| p == "~/.aws/**"));
    assert!(file.filesystem.deny.iter().any(|p| p == ".env"));
}

#[test]
fn override_can_remove_preset_filesystem_deny() {
    let user = r#"
inherits = "secure-defaults"

[filesystem]
read_allow = ["~/.aws/**"]
deny = ["!~/.aws/**"]

[functions]
allow = ["fs.read"]
"#;
    let file = PolicyFile::from_toml_str(user)
        .unwrap()
        .resolve_inheritance()
        .unwrap();
    assert!(!file.filesystem.deny.iter().any(|p| p == "~/.aws/**"));
    assert!(file.filesystem.deny.iter().any(|p| p == "**/.env"));
}

#[test]
fn override_can_unblock_preset_subprocess_command() {
    let user = r#"
inherits = "secure-defaults"

[subprocess]
allow_commands = ["kubectl"]
deny_commands = ["!kubectl"]

[functions]
allow = ["subprocess.exec"]
"#;
    let file = PolicyFile::from_toml_str(user)
        .unwrap()
        .resolve_inheritance()
        .unwrap();
    assert!(!file.subprocess.deny_commands.iter().any(|c| c == "kubectl"));
    assert!(file.subprocess.deny_commands.iter().any(|c| c == "rm"));
    assert!(file.subprocess.deny_commands.iter().any(|c| c == "sudo"));
}

#[test]
fn override_can_remove_preset_deny_ip_cidr() {
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
    assert!(file
        .network
        .deny_ips
        .iter()
        .any(|p| p == "169.254.0.0/16"));
    let p = Policy::from_file(file, PathBuf::from("/work")).unwrap();
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    assert!(p.check_resolved_ip("http_get", "localhost", ip).is_ok());
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
    let file = PolicyFile::from_toml_str(user)
        .unwrap()
        .resolve_inheritance()
        .unwrap();
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
    assert!(!file
        .confirm_per_call
        .iter()
        .any(|c| c == "subprocess.exec"));
    assert!(file.confirm_per_call.iter().any(|c| c == "fs.delete"));
}

#[test]
fn tools_block_lookup_and_capability_check() {
    // fs.read and net.http_get are derivable (resource sections
    // populated). fs.write and subprocess.exec are NOT (their
    // resource sections are empty).
    let toml = r#"
[filesystem]
read_allow = ["src/**"]

[network]
http_get_allow = ["api.example.com"]

[tools]
Read = ["fs.read"]
Edit = ["fs.read", "fs.write"]
Bash = ["subprocess.exec"]
WebFetch = ["net.http_get"]
"#;
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let p = Policy::from_file(file, PathBuf::from("/work")).unwrap();
    let record = p.check_tool("Read").unwrap();
    assert_eq!(record.capabilities, vec!["fs.read".to_string()]);
    assert!(p.check_tool("WebFetch").is_ok());
    let err = p.check_tool("Edit").unwrap_err().to_string();
    assert!(err.contains("Edit"), "{err}");
    assert!(err.contains("fs.write"), "{err}");
    assert!(p.check_tool("Bash").is_err());
    let err = p.check_tool("UnknownTool").unwrap_err().to_string();
    assert!(err.contains("not declared"), "{err}");
}

#[test]
fn tools_inherit_and_extend_via_merge() {
    let base_toml = r#"
[tools]
Read = ["fs.read"]
Bash = ["subprocess.exec"]
"#;
    let over_toml = r#"
[tools]
Bash = ["!subprocess.exec"]
WebFetch = ["net.http_get"]
"#;
    let base = PolicyFile::from_toml_str(base_toml).unwrap();
    let over = PolicyFile::from_toml_str(over_toml).unwrap();
    let merged = base.merge_with(over);
    assert_eq!(
        merged.tools.get("Read").unwrap().capabilities,
        vec!["fs.read".to_string()]
    );
    assert!(merged.tools.get("Bash").unwrap().capabilities.is_empty());
    assert_eq!(
        merged.tools.get("WebFetch").unwrap().capabilities,
        vec!["net.http_get".to_string()]
    );
}

#[test]
fn tools_long_form_carries_routing_hints() {
    // The long-form `[tools.X]` table accepts a `backend_url` and
    // `backend_method` so a bridge layer (e.g. local_mcp.py) can
    // route a tool's outbound call to a known endpoint without
    // asking the model to guess.
    let toml = r#"
[network]
http_get_allow = ["api.duckduckgo.com"]

[tools.WebSearch]
capabilities   = ["net.http_get"]
backend_url    = "https://api.duckduckgo.com/?format=json&no_html=1&q="
backend_method = "GET"
description    = "DuckDuckGo Instant Answer API (public, non-tracking)."
"#;
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let p = Policy::from_file(file, PathBuf::from("/work")).unwrap();
    let record = p.check_tool("WebSearch").unwrap();
    assert_eq!(record.capabilities, vec!["net.http_get".to_string()]);
    assert_eq!(
        record.backend_url.as_deref(),
        Some("https://api.duckduckgo.com/?format=json&no_html=1&q=")
    );
    assert_eq!(record.method(), "GET");
    assert!(record.description.is_some());
}

#[test]
fn tools_short_and_long_forms_coexist() {
    let toml = r#"
[filesystem]
read_allow = ["src/**"]

[network]
http_get_allow = ["api.duckduckgo.com"]

[tools]
# Short form for everyday tools.
Read = ["fs.read"]

# Long form just for the entry that needs routing.
[tools.WebSearch]
capabilities = ["net.http_get"]
backend_url  = "https://api.duckduckgo.com/?format=json&q="
"#;
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let p = Policy::from_file(file, PathBuf::from("/work")).unwrap();
    let read = p.check_tool("Read").unwrap();
    assert_eq!(read.capabilities, vec!["fs.read".to_string()]);
    assert!(read.backend_url.is_none());
    let ws = p.check_tool("WebSearch").unwrap();
    assert_eq!(ws.backend_url.as_deref(), Some("https://api.duckduckgo.com/?format=json&q="));
}

#[test]
fn tools_method_defaults_to_get() {
    // backend_url without backend_method ⇒ GET is implied.
    let toml = r#"
[network]
http_get_allow = ["api.duckduckgo.com"]

[tools.WebSearch]
capabilities = ["net.http_get"]
backend_url  = "https://api.duckduckgo.com/?format=json&q="
"#;
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let p = Policy::from_file(file, PathBuf::from("/work")).unwrap();
    let ws = p.check_tool("WebSearch").unwrap();
    assert_eq!(ws.method(), "GET");
}

#[test]
fn tools_routing_merges_with_user_overlay_winning() {
    // base declares WebSearch pointing at DuckDuckGo; user file
    // overrides with a different backend (Brave).
    let base_toml = r#"
[tools.WebSearch]
capabilities = ["net.http_get"]
backend_url  = "https://api.duckduckgo.com/?format=json&q="
"#;
    let over_toml = r#"
[tools.WebSearch]
capabilities = ["net.http_get"]
backend_url  = "https://api.search.brave.com/res/v1/web/search"
backend_method = "GET"
"#;
    let base = PolicyFile::from_toml_str(base_toml).unwrap();
    let over = PolicyFile::from_toml_str(over_toml).unwrap();
    let merged = base.merge_with(over);
    let ws = merged.tools.get("WebSearch").unwrap();
    assert_eq!(
        ws.backend_url.as_deref(),
        Some("https://api.search.brave.com/res/v1/web/search")
    );
}

#[test]
fn tool_routing_returns_record_even_when_capabilities_not_enabled() {
    // tool_routing() skips the capability check, so a bridge can
    // still surface "WebSearch points at api.duckduckgo.com" even when
    // `net.http_get` isn't enabled (so it can show a clear "enable
    // [network].http_get_allow" message).
    let toml = r#"
[tools.WebSearch]
capabilities = ["net.http_get"]
backend_url  = "https://api.duckduckgo.com/?format=json&q="
"#;
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let p = Policy::from_file(file, PathBuf::from("/work")).unwrap();
    // check_tool fails because net.http_get isn't derivable.
    assert!(p.check_tool("WebSearch").is_err());
    // tool_routing still returns the record.
    let ws = p.tool_routing("WebSearch").unwrap();
    assert_eq!(ws.backend_url.as_deref(), Some("https://api.duckduckgo.com/?format=json&q="));
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
    let merged = base.merge_with(over);
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
fn secure_defaults_fallback_denies_every_capability() {
    // The CLI/MCP fallback when no --policy is passed. Must deny every
    // effecting capability: the preset has only deny lists and no
    // allows, so empty allowlists short-circuit each gate.
    let p = Policy::secure_defaults_at(PathBuf::from("/work")).unwrap();
    assert!(p.check_function("fs.read").is_err());
    assert!(p.check_function("fs.write").is_err());
    assert!(p.check_function("net.http_get").is_err());
    assert!(p.check_function("subprocess.exec").is_err());
    assert!(p.check_function("env.read").is_err());
    assert!(p.check_fs_read(Path::new("/tmp/x")).is_err());
    assert!(p.check_fs_write(Path::new("/tmp/x")).is_err());
    assert!(p.check_http_get("https://api.github.com/").is_err());
    assert!(p.check_env_read("PATH").is_err());
    assert!(p.check_subprocess_command("git").is_err());
    // Inherited deny entries are also active (belt-and-suspenders).
    assert!(p.check_env_read("AWS_SECRET_ACCESS_KEY").is_err());
    assert!(p.check_subprocess_command("rm").is_err());
}

// ----------------------------------------------------------------------
// Auto-derived [functions].allow: when the user doesn't write a
// `[functions]` block, the runtime infers permitted capabilities from
// the resource sections (read_allow ⇒ fs.read, allow_commands ⇒
// subprocess.exec, etc.). Avoids the redundancy of stating the same
// intent twice.
// ----------------------------------------------------------------------

#[test]
fn auto_derives_fs_read_from_read_allow_alone() {
    // No [functions] block at all. read_allow is enough.
    let toml = r#"
[filesystem]
read_allow = ["src/**", "/tmp/**"]
"#;
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let p = Policy::from_file(file, PathBuf::from("/work")).unwrap();
    assert!(p.check_function("fs.read").is_ok(), "fs.read should auto-derive");
    // Other capabilities NOT auto-derived because their sections are empty.
    assert!(p.check_function("fs.write").is_err());
    assert!(p.check_function("subprocess.exec").is_err());
}

#[test]
fn auto_derives_subprocess_exec_from_allow_commands() {
    let toml = r#"
[subprocess]
allow_commands = ["git"]
"#;
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let p = Policy::from_file(file, PathBuf::from("/work")).unwrap();
    assert!(p.check_function("subprocess.exec").is_ok());
    assert!(p.check_function("fs.read").is_err());
}

#[test]
fn auto_derives_from_local_only_lists() {
    // local_only_* counts as "operator declared intent to use this
    // capability" — same as a regular allow list.
    let toml = r#"
[environment]
local_only_vars = ["OPENAI_API_KEY"]

[network]
local_only_hosts = ["api.openai.com"]
"#;
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let p = Policy::from_file(file, PathBuf::from("/work")).unwrap();
    assert!(p.check_function("env.read").is_ok());
    assert!(p.check_function("net.http_get").is_ok());
    assert!(p.check_function("net.http_post").is_ok());
}

#[test]
fn capabilities_are_enabled_only_by_populating_resource_sections() {
    // The operator declared read_allow but NOT write_allow.
    // fs.read is permitted; fs.write is not. (Empty resource section
    // == capability not declared. There is no [functions] block to
    // re-state the same fact.)
    let toml = r#"
[filesystem]
read_allow = ["src/**"]
"#;
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let p = Policy::from_file(file, PathBuf::from("/work")).unwrap();
    assert!(p.check_function("fs.read").is_ok());
    assert!(p.check_function("fs.write").is_err());
}

#[test]
fn effective_functions_lists_what_is_actually_enabled() {
    let toml = r#"
[filesystem]
read_allow = ["src/**"]

[subprocess]
allow_commands = ["git"]
"#;
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let p = Policy::from_file(file, PathBuf::from("/work")).unwrap();
    let effective: Vec<&str> = p.effective_functions();
    assert!(effective.contains(&"fs.read"));
    assert!(effective.contains(&"subprocess.exec"));
    assert!(!effective.contains(&"fs.write"));
    assert!(!effective.contains(&"net.http_get"));
}

#[test]
fn missing_resource_for_capability_gives_actionable_error() {
    // No resource section, no [functions]. Calling fs.read should
    // give an error that names the section the user needs to
    // populate.
    let toml = r#"
[filesystem]
write_allow = ["/tmp/**"]   # only write enabled
"#;
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let p = Policy::from_file(file, PathBuf::from("/work")).unwrap();
    let err = p.check_function("fs.read").unwrap_err().to_string();
    assert!(
        err.contains("read_allow") && err.contains("fs.read"),
        "expected actionable error pointing at read_allow, got: {err}"
    );
}

// ----------------------------------------------------------------------
// Self-writable guard: a policy that lets the agent write or delete its
// own file would be self-defeating — on the next run the agent could
// have rewritten it to permit anything. Refuse at load time.
// ----------------------------------------------------------------------

fn write_temp_policy(name: &str, body: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aegis_self_test_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    path
}

#[test]
fn rejects_policy_that_allows_writing_to_itself_via_broad_glob() {
    // Relative patterns now anchor at the policy file's own directory
    // (the portable default), so `**` reaches the policy file itself.
    let path = write_temp_policy("aegis.toml", "PLACEHOLDER");
    let body = r#"
[filesystem]
read_allow = ["**"]
write_allow = ["**"]

[functions]
allow = ["fs.read", "fs.write"]
"#;
    std::fs::write(&path, body).unwrap();
    let res = Policy::load(&path);
    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("refusing to load") && err.contains("write"),
        "expected SelfWritable error, got: {err}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn rejects_policy_that_allows_writing_to_itself_via_exact_name() {
    // A bare `aegis.toml` pattern would (per gitignore semantics)
    // match anywhere under the policy root, including the policy
    // file itself.
    let path = write_temp_policy("aegis.toml", "PLACEHOLDER");
    let body = r#"
[filesystem]
read_allow = ["aegis.toml"]
write_allow = ["aegis.toml"]

[functions]
allow = ["fs.read", "fs.write"]
"#;
    std::fs::write(&path, body).unwrap();
    let res = Policy::load(&path);
    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("refusing to load"),
        "expected SelfWritable error, got: {err}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn rejects_policy_that_allows_deleting_itself() {
    let path = write_temp_policy("aegis.toml", "PLACEHOLDER");
    let body = r#"
[filesystem]
delete_allow = ["**"]

[functions]
allow = ["fs.delete"]
"#;
    std::fs::write(&path, body).unwrap();
    let res = Policy::load(&path);
    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("refusing to load") && err.contains("delete"),
        "expected SelfWritable (delete) error, got: {err}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn explicit_deny_on_policy_file_satisfies_the_guard() {
    // A broad write_allow combined with a specific deny on the policy
    // file is a sound pattern — runtime enforcement honors deny-wins,
    // and the guard probes via the real check_fs_* methods, so it
    // sees the file as not writable and lets the policy load.
    let path = write_temp_policy(
        "aegis.toml",
        "PLACEHOLDER",
    );
    // Substitute the actual path into the deny entry so the match is
    // exact regardless of where the temp directory lives.
    let abs = path.to_string_lossy().replace('\\', "/");
    let body = format!(
        r#"
[filesystem]
read_allow = ["**"]
write_allow = ["**"]
deny = ["{abs}"]

[functions]
allow = ["fs.read", "fs.write"]
"#
    );
    std::fs::write(&path, body).unwrap();
    let res = Policy::load(&path);
    assert!(
        res.is_ok(),
        "policy with deny on its own file should load: {:?}",
        res.unwrap_err().to_string()
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn unrelated_write_allow_passes_the_guard() {
    let body = r#"
[filesystem]
read_allow = ["**"]
write_allow = ["src/**", "/tmp/build/**"]

[functions]
allow = ["fs.read", "fs.write"]
"#;
    let path = write_temp_policy("aegis.toml", body);
    let res = Policy::load(&path);
    assert!(res.is_ok(), "narrow write_allow should not trip the guard");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn mixes_relative_and_absolute_patterns_in_one_policy() {
    // The pattern form is auto-detected:
    //   "src/**"   — relative, anchors at policy file's parent dir
    //   "/tmp/**"  — absolute, used as-is
    //   "~/cache/" — tilde-expanded, used as-is
    // All three coexist in the same list.
    let path = write_temp_policy("aegis.toml", "PLACEHOLDER");
    let body = r#"
[filesystem]
read_allow  = ["src/**", "/tmp/**", "~/.cache/aegis/**"]
write_allow = ["src/**", "/tmp/aegis_demo/**"]

[functions]
allow = ["fs.read", "fs.write"]
"#;
    std::fs::write(&path, body).unwrap();
    let policy = Policy::load(&path).unwrap();

    let policy_dir = path.parent().unwrap();
    // Relative `src/**` resolves under the policy's own dir.
    let rel_hit = policy_dir.join("src/main.rs");
    assert!(policy.check_fs_read(&rel_hit).is_ok(), "relative src/**");
    assert!(policy.check_fs_write(&rel_hit).is_ok(), "relative src/** writable");

    // Absolute `/tmp/**` works regardless of policy location.
    assert!(policy
        .check_fs_read(Path::new("/tmp/anything"))
        .is_ok(), "absolute /tmp/**");
    assert!(policy
        .check_fs_write(Path::new("/tmp/aegis_demo/out.txt"))
        .is_ok(), "absolute write");

    // Non-allowed paths still fail.
    assert!(policy
        .check_fs_read(Path::new("/etc/some_other_file"))
        .is_err());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn read_allow_matching_policy_file_is_fine() {
    // Reading the policy is not a privilege escalation — the agent
    // can already see what it's allowed to do. Only write/delete
    // matter for the self-modification guard.
    let body = r#"
[filesystem]
read_allow = ["**"]

[functions]
allow = ["fs.read"]
"#;
    let path = write_temp_policy("aegis.toml", body);
    let res = Policy::load(&path);
    assert!(res.is_ok(), "read-only policy match should be allowed");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn deny_args_merge_concatenates_per_command() {
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
    let merged = base.merge_with(over);
    let git_args = merged.subprocess.deny_args.get("git").unwrap();
    assert!(git_args.contains(&"push --force".to_string()));
    assert!(git_args.contains(&"reset --hard".to_string()));
    let rails_args = merged.subprocess.deny_args.get("rails").unwrap();
    assert!(rails_args.contains(&"db:drop".to_string()));
}
