//! Host network isolation via the platform firewall. Isolation blocks all
//! traffic EXCEPT loopback, the Sigil control channel (`control_host`), and any
//! extra allowlisted CIDRs — so a contained host can never sever the agent's
//! own link back to the server. `unisolate` removes the ruleset.
//!
//! These actions require root/administrator and are inherently destructive to
//! connectivity; they run the native firewall tool and surface its result.

use sigil_edr_proto::pb;

/// Build the effective allowlist: always loopback + the control host, plus any
/// caller-provided CIDRs.
fn allowlist(isolate: Option<&pb::Isolate>, control_host: &str) -> Vec<String> {
    let mut allow = vec!["127.0.0.1".to_string(), "::1".to_string()];
    if !control_host.is_empty() {
        allow.push(control_host.to_string());
    }
    if let Some(iso) = isolate {
        allow.extend(iso.allowlist_cidrs.iter().cloned());
    }
    allow
}

/// Apply host isolation. Returns `(ok, message)`.
pub fn isolate(iso: Option<&pb::Isolate>, control_host: &str) -> (bool, String) {
    let allow = allowlist(iso, control_host);
    apply(&allow)
}

/// Remove host isolation. Returns `(ok, message)`.
pub fn unisolate() -> (bool, String) {
    clear()
}

// ---- Linux (nftables) -----------------------------------------------------

#[cfg(target_os = "linux")]
fn apply(allow: &[String]) -> (bool, String) {
    use std::io::Write;
    let mut ruleset = String::from(
        "table inet sigil_isolate {\n  chain output {\n    type filter hook output priority 0; policy drop;\n    ct state established,related accept\n    oifname \"lo\" accept\n",
    );
    for a in allow {
        ruleset.push_str(&format!("    ip daddr {a} accept\n"));
    }
    ruleset.push_str("  }\n}\n");

    let mut child = match std::process::Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return (false, format!("spawn nft: {e}")),
    };
    if let Some(stdin) = child.stdin.as_mut() {
        let _ = stdin.write_all(ruleset.as_bytes());
    }
    match child.wait() {
        Ok(s) if s.success() => (true, format!("host isolated (allow: {})", allow.join(", "))),
        Ok(s) => (false, format!("nft exited {s}")),
        Err(e) => (false, format!("nft wait: {e}")),
    }
}

#[cfg(target_os = "linux")]
fn clear() -> (bool, String) {
    run(&["nft", "delete", "table", "inet", "sigil_isolate"])
}

// ---- macOS (pf) -----------------------------------------------------------

#[cfg(target_os = "macos")]
fn apply(allow: &[String]) -> (bool, String) {
    // Anchor ruleset: pass to the allowlist, block everything else outbound.
    let mut rules = String::new();
    for a in allow {
        rules.push_str(&format!("pass out quick to {a}\n"));
    }
    rules.push_str("block drop out all\n");

    let anchor = "/etc/pf.anchors/sigil_isolate";
    if let Err(e) = std::fs::write(anchor, &rules) {
        return (false, format!("write pf anchor: {e}"));
    }
    // Load the anchor and enable pf.
    let load = std::process::Command::new("pfctl")
        .args(["-a", "sigil_isolate", "-f", anchor])
        .status();
    match load {
        Ok(s) if s.success() => {
            let mut child = std::process::Command::new("pfctl").arg("-e").spawn();
            if let Ok(c) = child.as_mut() {
                let _ = c.wait();
            }
            (true, format!("host isolated (allow: {})", allow.join(", ")))
        }
        Ok(s) => (false, format!("pfctl load exited {s}")),
        Err(e) => (false, format!("pfctl: {e}")),
    }
}

#[cfg(target_os = "macos")]
fn clear() -> (bool, String) {
    // Flush the anchor's rules (leaves pf itself as configured).
    run(&["pfctl", "-a", "sigil_isolate", "-F", "rules"])
}

// ---- Windows (netsh advfirewall) ------------------------------------------

#[cfg(target_os = "windows")]
fn apply(allow: &[String]) -> (bool, String) {
    // Set the default outbound action to block, then allow the control channel.
    let set = run(&[
        "netsh",
        "advfirewall",
        "set",
        "allprofiles",
        "firewallpolicy",
        "blockinbound,blockoutbound",
    ]);
    if !set.0 {
        return set;
    }
    for a in allow {
        let _ = run(&[
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=SigilIsolateAllow",
            "dir=out",
            "action=allow",
            &format!("remoteip={a}"),
        ]);
    }
    (true, format!("host isolated (allow: {})", allow.join(", ")))
}

#[cfg(target_os = "windows")]
fn clear() -> (bool, String) {
    let _ = run(&[
        "netsh",
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        "name=SigilIsolateAllow",
    ]);
    run(&[
        "netsh",
        "advfirewall",
        "set",
        "allprofiles",
        "firewallpolicy",
        "blockinbound,allowoutbound",
    ])
}

// ---- fallback -------------------------------------------------------------

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn apply(_allow: &[String]) -> (bool, String) {
    (false, "host isolation unsupported on this platform".into())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn clear() -> (bool, String) {
    (false, "host isolation unsupported on this platform".into())
}

/// Run a command, returning `(ok, message)`.
#[allow(dead_code)]
fn run(args: &[&str]) -> (bool, String) {
    let (cmd, rest) = args.split_first().expect("non-empty command");
    match std::process::Command::new(cmd).args(rest).status() {
        Ok(s) if s.success() => (true, format!("{} ok", args.join(" "))),
        Ok(s) => (false, format!("{} exited {s}", args.join(" "))),
        Err(e) => (false, format!("{cmd}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_always_includes_control_channel() {
        let iso = pb::Isolate {
            allowlist_cidrs: vec!["10.0.0.0/8".into()],
        };
        let allow = allowlist(Some(&iso), "siem.internal");
        assert!(allow.contains(&"127.0.0.1".to_string()));
        assert!(allow.contains(&"siem.internal".to_string()));
        assert!(allow.contains(&"10.0.0.0/8".to_string()));
    }

    #[test]
    fn allowlist_present_even_with_no_extra_cidrs() {
        let allow = allowlist(None, "1.2.3.4");
        assert!(allow.contains(&"1.2.3.4".to_string()));
        assert!(allow.contains(&"127.0.0.1".to_string()));
    }
}
