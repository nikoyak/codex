//! Per-`CODEX_HOME` sandbox account naming.
//!
//! Sandbox accounts are machine-wide local users, but their DPAPI-protected
//! passwords live in a single `CODEX_HOME`. Sharing one fixed account pair
//! between several homes makes every elevated setup rotate a password that only
//! the running home records, invalidating all the others. Each home therefore
//! owns a pair derived from its own path, and everything keyed on the offline
//! account (firewall rules, WFP filters) is namespaced by the same tag.
//!
//! The legacy fixed pair stays valid for homes that already recorded it and for
//! the service-provisioned (registered Core) runtime, which is single-owner by
//! design.

use std::path::Path;

use crate::setup::OFFLINE_USERNAME as LEGACY_OFFLINE_USERNAME;
use crate::setup::ONLINE_USERNAME as LEGACY_ONLINE_USERNAME;

// SAM account names are limited to 20 characters.
pub(crate) const OFFLINE_PREFIX: &str = "CdxSbxOff_";
pub(crate) const ONLINE_PREFIX: &str = "CdxSbxOn_";
pub(crate) const GROUP_PREFIX: &str = "CdxSbxGrp_";
const TAG_LEN: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SandboxAccountNames {
    pub(crate) offline: String,
    pub(crate) online: String,
}

impl SandboxAccountNames {
    pub(crate) fn legacy() -> Self {
        Self {
            offline: LEGACY_OFFLINE_USERNAME.to_string(),
            online: LEGACY_ONLINE_USERNAME.to_string(),
        }
    }

    /// Deterministic pair owned by `codex_home` alone.
    pub(crate) fn derived(codex_home: &Path) -> Self {
        let tag = home_tag(codex_home);
        Self {
            offline: format!("{OFFLINE_PREFIX}{tag}"),
            online: format!("{ONLINE_PREFIX}{tag}"),
        }
    }

    /// Validates a pair read from owner-controlled files before it is used to
    /// create, log on to, or firewall an account. Only the legacy pair or a
    /// well-formed derived pair with a matching tag is accepted.
    pub(crate) fn from_recorded(offline: &str, online: &str) -> Option<Self> {
        if offline == LEGACY_OFFLINE_USERNAME && online == LEGACY_ONLINE_USERNAME {
            return Some(Self::legacy());
        }
        let offline_tag = offline.strip_prefix(OFFLINE_PREFIX)?;
        let online_tag = online.strip_prefix(ONLINE_PREFIX)?;
        (offline_tag == online_tag && is_tag(offline_tag)).then(|| Self {
            offline: offline.to_string(),
            online: online.to_string(),
        })
    }
}

/// Suffix that namespaces firewall rules and WFP filters of one offline account.
/// `None` for the legacy account, which keeps the original unsuffixed names.
pub(crate) fn resource_tag_for_offline_username(offline_username: &str) -> Option<&str> {
    offline_username
        .strip_prefix(OFFLINE_PREFIX)
        .filter(|tag| is_tag(tag))
}

/// Local group whose members are the sandbox accounts of one home. ACLs granted to the group
/// (read roots, write roots, `.sandbox`) must not reach another home's accounts, so each
/// derived pair gets its own group; the legacy pair keeps the shared group.
pub(crate) fn group_name_for_offline_username(offline_username: &str) -> String {
    match resource_tag_for_offline_username(offline_username) {
        Some(tag) => format!("{GROUP_PREFIX}{tag}"),
        None => crate::winutil::SANDBOX_USERS_GROUP.to_string(),
    }
}

/// Tag of a derived sandbox account (offline or online), or `None` for any other name.
pub(crate) fn tag_of_derived_account(username: &str) -> Option<&str> {
    username
        .strip_prefix(OFFLINE_PREFIX)
        .or_else(|| username.strip_prefix(ONLINE_PREFIX))
        .filter(|tag| is_tag(tag))
}

pub(crate) fn is_derived_group(name: &str) -> bool {
    name.strip_prefix(GROUP_PREFIX).is_some_and(is_tag)
}

/// Firewall rule and WFP filter names of the legacy account stay unsuffixed.
pub(crate) fn scoped_rule_name(base: &str, tag: Option<&str>) -> String {
    match tag {
        Some(tag) => format!("{base}_{tag}"),
        None => base.to_string(),
    }
}

fn is_tag(tag: &str) -> bool {
    tag.len() == TAG_LEN && tag.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn home_tag(codex_home: &Path) -> String {
    let resolved = dunce::canonicalize(codex_home).unwrap_or_else(|_| codex_home.to_path_buf());
    // NTFS paths are case-insensitive and accept either separator.
    let normalized = resolved
        .to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase();
    let hash = fnv1a_64(normalized.as_bytes());
    format!("{:08x}", (hash >> 32) as u32 ^ hash as u32)
}

// Stable across Rust versions, unlike `DefaultHasher`.
fn fnv1a_64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn derived_names_fit_sam_limit_and_round_trip() {
        let names = SandboxAccountNames::derived(Path::new(r"C:\Users\a\.codex"));
        assert!(names.offline.len() <= 20 && names.online.len() <= 20);
        assert_eq!(
            SandboxAccountNames::from_recorded(&names.offline, &names.online),
            Some(names)
        );
    }

    #[test]
    fn derived_names_are_stable_and_path_normalized() {
        let a = SandboxAccountNames::derived(Path::new(r"C:\Users\A\.codex"));
        let b = SandboxAccountNames::derived(Path::new("c:/users/a/.codex/"));
        assert_eq!(a, b);
    }

    #[test]
    fn different_homes_get_different_names() {
        let a = SandboxAccountNames::derived(Path::new(r"C:\Users\a\.codex"));
        let b = SandboxAccountNames::derived(Path::new(r"C:\Users\a\.codex-overflow"));
        assert!(a.offline != b.offline && a.online != b.online);
    }

    #[test]
    fn recorded_names_are_validated() {
        assert_eq!(
            SandboxAccountNames::from_recorded("CodexSandboxOffline", "CodexSandboxOnline"),
            Some(SandboxAccountNames::legacy())
        );
        for (offline, online) in [
            ("Administrator", "CodexSandboxOnline"),
            ("CdxSbxOff_0123abcd", "CdxSbxOn_0123abce"),
            ("CdxSbxOff_0123ABCD", "CdxSbxOn_0123ABCD"),
            ("CdxSbxOff_xyz", "CdxSbxOn_xyz"),
        ] {
            assert_eq!(SandboxAccountNames::from_recorded(offline, online), None);
        }
    }

    #[test]
    fn group_and_tag_helpers_follow_the_account_tag() {
        assert_eq!(
            group_name_for_offline_username("CdxSbxOff_0123abcd"),
            "CdxSbxGrp_0123abcd"
        );
        assert_eq!(
            group_name_for_offline_username("CodexSandboxOffline"),
            "CodexSandboxUsers"
        );
        assert_eq!(tag_of_derived_account("CdxSbxOn_0123abcd"), Some("0123abcd"));
        assert_eq!(tag_of_derived_account("CodexSandboxOnline"), None);
        assert!(is_derived_group("CdxSbxGrp_0123abcd"));
        assert!(!is_derived_group("CodexSandboxUsers"));
        assert_eq!(scoped_rule_name("rule", Some("0123abcd")), "rule_0123abcd");
        assert_eq!(scoped_rule_name("rule", None), "rule");
    }

    #[test]
    fn resource_tag_is_none_for_legacy() {
        assert_eq!(
            resource_tag_for_offline_username("CodexSandboxOffline"),
            None
        );
        assert_eq!(
            resource_tag_for_offline_username("CdxSbxOff_0123abcd"),
            Some("0123abcd")
        );
    }
}
