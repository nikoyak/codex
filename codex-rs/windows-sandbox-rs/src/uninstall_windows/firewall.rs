//! Removes known sandbox firewall rules while preserving unrelated rules.

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use windows::Win32::NetworkManagement::WindowsFirewall::INetFwPolicy2;
use windows::Win32::NetworkManagement::WindowsFirewall::NetFwPolicy2;
use windows::Win32::System::Com::CLSCTX_INPROC_SERVER;
use windows::Win32::System::Com::CoCreateInstance;
use windows::core::BSTR;

/// Removes the legacy rules and the rules namespaced by each per-home account tag.
pub(super) fn cleanup_firewall_rules(tags: &[String]) -> Result<()> {
    let policy: INetFwPolicy2 = unsafe {
        CoCreateInstance(&NetFwPolicy2, /*punkouter*/ None, CLSCTX_INPROC_SERVER)
            .context("access firewall policy for sandbox uninstall")?
    };
    let rules = unsafe { policy.Rules() }.context("access sandbox firewall rules")?;
    let mut errors = Vec::new();
    let tags = std::iter::once(None).chain(tags.iter().map(|tag| Some(tag.as_str())));
    for tag in tags {
        for base in [
            "codex_sandbox_offline_block_outbound",
            "codex_sandbox_offline_block_inbound",
            "codex_sandbox_offline_block_loopback_tcp",
            "codex_sandbox_offline_block_loopback_udp",
            "codex_sandbox_offline_allow_loopback_proxy",
        ] {
            let name = crate::account_names::scoped_rule_name(base, tag);
            if let Err(error) = unsafe { rules.Remove(&BSTR::from(name.as_str())) } {
                errors.push(format!("remove sandbox firewall rule {name}: {error}"));
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(errors.join("; ")))
    }
}
