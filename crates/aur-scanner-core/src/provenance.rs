//! Provenance tracking: detect a package *gaining* risky behavior over time.
//!
//! The Atomic Arch hijacks were spotted because a package that never used Node
//! suddenly shelled out to `npm`/`bun`. Heuristic rules see each scan in
//! isolation; provenance compares the current PKGBUILD/install content against
//! the last time this package was seen and flags newly-introduced risk markers.
//!
//! State is a small JSON store keyed by package name. The first sighting of a
//! package establishes a baseline (no finding); subsequent additions are flagged.

use crate::types::{Category, Finding, Location, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A coarse risk marker: an id/label and the lowercase substrings that signal it.
struct Marker {
    id: &'static str,
    label: &'static str,
    needles: &'static [&'static str],
}

/// Behaviours whose *introduction* on an update is noteworthy. Deliberately
/// coarse: a legitimate package newly pulling npm is itself worth a heads-up.
const MARKERS: &[Marker] = &[
    Marker {
        id: "npm",
        label: "npm package install",
        needles: &["npm install", "npm i ", "npm ci"],
    },
    Marker {
        id: "pnpm",
        label: "pnpm install",
        needles: &["pnpm install", "pnpm add"],
    },
    Marker {
        id: "yarn",
        label: "yarn install",
        needles: &["yarn add", "yarn install"],
    },
    Marker {
        id: "bun",
        label: "bun install",
        needles: &["bun install", "bun add", "bunx"],
    },
    Marker {
        id: "pipe-shell",
        label: "pipe to shell",
        needles: &["| sh", "|sh", "| bash", "|bash"],
    },
    Marker {
        id: "eval",
        label: "eval",
        needles: &["eval "],
    },
    Marker {
        id: "base64-decode",
        label: "base64 decode",
        needles: &["base64 -d", "base64 --decode"],
    },
    Marker {
        id: "reverse-shell",
        label: "raw TCP socket",
        needles: &["/dev/tcp/"],
    },
    Marker {
        id: "ebpf",
        label: "eBPF object",
        needles: &[".bpf.c", ".bpf.o"],
    },
    Marker {
        id: "curl-net",
        label: "curl/wget fetch",
        needles: &["curl ", "wget "],
    },
];

/// One package's last-seen fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Snapshot {
    content_sha256: String,
    /// Marker ids present at last sighting (sorted, unique).
    markers: Vec<String>,
    last_seen: String,
    /// Maintainer email at last sighting, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    maintainer: Option<String>,
}

/// Persistent provenance store.
#[derive(Debug)]
pub struct ProvenanceStore {
    path: PathBuf,
    snapshots: HashMap<String, Snapshot>,
    dirty: bool,
}

impl ProvenanceStore {
    /// Default on-disk location: `$XDG_CACHE_HOME/aur-scanner/provenance.json`.
    pub fn default_path() -> PathBuf {
        dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("aur-scanner/provenance.json")
    }

    /// Load the store from `path`, tolerating a missing or malformed file.
    pub fn load(path: PathBuf) -> Self {
        let snapshots = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Self {
            path,
            snapshots,
            dirty: false,
        }
    }

    /// Create an empty in-memory store for testing.
    pub fn empty_for_test() -> Self {
        Self {
            path: PathBuf::from("/dev/null"),
            snapshots: HashMap::new(),
            dirty: false,
        }
    }

    /// Compute the marker ids present in `content`.
    fn markers_in(content: &str) -> Vec<String> {
        let lc = content.to_lowercase();
        let mut found: Vec<String> = MARKERS
            .iter()
            .filter(|m| m.needles.iter().any(|n| lc.contains(n)))
            .map(|m| m.id.to_string())
            .collect();
        found.sort();
        found.dedup();
        found
    }

    fn label_for(id: &str) -> &'static str {
        MARKERS
            .iter()
            .find(|m| m.id == id)
            .map(|m| m.label)
            .unwrap_or("risky behavior")
    }

    /// Evaluate a package's current content against its last-seen snapshot,
    /// returning findings for newly-introduced risk markers, and record the
    /// new baseline. `now` is an RFC3339 timestamp supplied by the caller.
    /// If `maintainer` is provided and has changed alongside new risky
    /// behavior, an additional maintainer-hijack finding is emitted.
    pub fn evaluate(
        &mut self,
        package: &str,
        content: &str,
        now: &str,
        file: &Path,
        maintainer: Option<&str>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let current_markers = Self::markers_in(content);
        let sha = sha256_hex(content);

        let maintainer_changed = maintainer
            .and_then(|m| {
                self.snapshots
                    .get(package)
                    .and_then(|s| s.maintainer.as_deref())
                    .map(|prev| prev != m)
            })
            .unwrap_or(false);

        if let Some(prev) = self.snapshots.get(package) {
            let added: Vec<&String> = current_markers
                .iter()
                .filter(|m| !prev.markers.contains(m))
                .collect();
            if !added.is_empty() {
                let labels: Vec<&str> = added.iter().map(|id| Self::label_for(id)).collect();
                findings.push(Finding {
                    id: "PROV-001".to_string(),
                    severity: Severity::High,
                    category: Category::SuspiciousMetadata,
                    title: format!(
                        "Package gained risky behavior since last scan: {}",
                        labels.join(", ")
                    ),
                    description: format!(
                        "'{}' introduced behavior it did not have at the previous scan ({}). \
                         A package suddenly fetching/executing code on update is the primary \
                         tell of an AUR hijack.",
                        package,
                        labels.join(", ")
                    ),
                    location: Location {
                        file: file.to_path_buf(),
                        line: None,
                        column: None,
                        snippet: None,
                    },
                    recommendation:
                        "Review the PKGBUILD/install diff before building. If the new behavior \
                         is unexplained, do not build and report the package."
                            .to_string(),
                    cwe_id: Some("CWE-506".to_string()),
                    metadata: serde_json::json!({
                        "added_markers": added,
                        "previous_seen": prev.last_seen,
                    }),
                });

                // Maintainer changed alongside risky additions: classic hijack.
                if maintainer_changed {
                    let new_m = maintainer.unwrap_or("(none)");
                    let old_m = prev.maintainer.as_deref().unwrap_or("(none)");
                    findings.push(Finding {
                        id: "PROV-002".to_string(),
                        severity: Severity::High,
                        category: Category::SuspiciousMetadata,
                        title: "Package maintainer changed with risky behavior added".to_string(),
                        description: format!(
                            "'{}' changed maintainer from '{}' to '{}' in the same update that \
                             introduced risky behavior ({}). This is the classic signature of an \
                             AUR package hijack.",
                            package,
                            old_m,
                            new_m,
                            labels.join(", ")
                        ),
                        location: Location {
                            file: file.to_path_buf(),
                            line: None,
                            column: None,
                            snippet: None,
                        },
                        recommendation:
                            "Verify the maintainer change is legitimate before building. \
                             If unexplained, do not build and report the package."
                                .to_string(),
                        cwe_id: Some("CWE-506".to_string()),
                        metadata: serde_json::json!({
                            "old_maintainer": old_m,
                            "new_maintainer": new_m,
                            "added_markers": added,
                        }),
                    });
                }
            } else if maintainer_changed {
                // Maintainer changed without new risky behavior.  Flag it as
                // informational: it isn't a confirmed hijack, but it is the
                // single most reliable early-warning signal.
                let new_m = maintainer.unwrap_or("(none)");
                let old_m = prev.maintainer.as_deref().unwrap_or("(none)");
                findings.push(Finding {
                    id: "PROV-003".to_string(),
                    severity: Severity::Low,
                    category: Category::SuspiciousMetadata,
                    title: "Package maintainer changed since last scan".to_string(),
                    description: format!(
                        "'{}' maintainer changed from '{}' to '{}', although no new \
                         risky behavior was detected.  Maintainer changes are the most \
                         common precursor to orphaned-package hijacks; verify this is \
                         legitimate before building.",
                        package, old_m, new_m,
                    ),
                    location: Location {
                        file: file.to_path_buf(),
                        line: None,
                        column: None,
                        snippet: None,
                    },
                    recommendation: "Verify the maintainer change is legitimate.".to_string(),
                    cwe_id: None,
                    metadata: serde_json::json!({
                        "old_maintainer": old_m,
                        "new_maintainer": new_m,
                    }),
                });
            }
        }

        let changed = self
            .snapshots
            .get(package)
            .map(|s| s.content_sha256 != sha)
            .unwrap_or(true);
        if changed {
            self.snapshots.insert(
                package.to_string(),
                Snapshot {
                    content_sha256: sha,
                    markers: current_markers,
                    last_seen: now.to_string(),
                    maintainer: maintainer.map(String::from),
                },
            );
            self.dirty = true;
        }

        findings
    }

    /// Persist the store if modified. Creates parent directories as needed.
    pub fn save(&self) -> std::io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.snapshots).map_err(std::io::Error::other)?;
        std::fs::write(&self.path, json)
    }

    /// Number of tracked packages.
    pub fn tracked(&self) -> usize {
        self.snapshots.len()
    }
}

fn sha256_hex(content: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(content.as_bytes());
    format!("{:x}", h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> ProvenanceStore {
        ProvenanceStore {
            path: PathBuf::from("/dev/null"),
            snapshots: HashMap::new(),
            dirty: false,
        }
    }

    #[test]
    fn first_sighting_is_baseline_no_finding() {
        let mut s = store();
        let f = s.evaluate(
            "pkg",
            "build() { make }",
            "2026-06-13T00:00:00Z",
            Path::new("PKGBUILD"),
            None,
        );
        assert!(f.is_empty());
        assert_eq!(s.tracked(), 1);
    }

    #[test]
    fn flags_newly_added_npm() {
        let mut s = store();
        s.evaluate("pkg", "build() { make }", "t0", Path::new("PKGBUILD"), None);
        let f = s.evaluate(
            "pkg",
            "build() { make }\npost_install() { npm install atomic-lockfile }",
            "t1",
            Path::new("PKGBUILD"),
            None,
        );
        assert!(f.iter().any(|x| x.id == "PROV-001"));
    }

    #[test]
    fn no_finding_when_behavior_unchanged() {
        let mut s = store();
        let c = "build() { make }\npost_install() { npm install foo }";
        s.evaluate("pkg", c, "t0", Path::new("PKGBUILD"), None);
        let f = s.evaluate("pkg", c, "t1", Path::new("PKGBUILD"), None);
        assert!(f.is_empty());
    }

    #[test]
    fn preexisting_behavior_not_flagged_on_first_sight() {
        // A package that already had npm at first sight must not be flagged
        // (provenance only flags *additions*, not steady state).
        let mut s = store();
        let f = s.evaluate("pkg", "npm install foo", "t0", Path::new("PKGBUILD"), None);
        assert!(f.is_empty());
    }

    #[test]
    fn maintainer_change_without_risky_behavior_flags_prov003() {
        let mut s = store();
        let c = "build() { make }";
        s.evaluate(
            "pkg",
            c,
            "t0",
            Path::new("PKGBUILD"),
            Some("alice <alice@good.com>"),
        );
        // Same content, different maintainer, no risky behavior added.
        let f = s.evaluate(
            "pkg",
            c,
            "t1",
            Path::new("PKGBUILD"),
            Some("mallory <mallory@evil.com>"),
        );
        assert!(
            f.iter().any(|x| x.id == "PROV-003"),
            "PROV-003 must fire for maintainer change"
        );
        assert!(
            f.iter().all(|x| x.id != "PROV-001"),
            "PROV-001 must not fire (no risky behavior added)"
        );
        assert!(
            f.iter().all(|x| x.id != "PROV-002"),
            "PROV-002 must not fire (no risky behavior added)"
        );
    }

    #[test]
    fn username_only_change_triggers_prov003() {
        let mut s = store();
        let c = "build() { make }";
        s.evaluate(
            "pkg",
            c,
            "t0",
            Path::new("PKGBUILD"),
            Some("Alice <same@email.com>"),
        );
        // Same email, different name — should still trigger.
        let f = s.evaluate(
            "pkg",
            c,
            "t1",
            Path::new("PKGBUILD"),
            Some("Mallory <same@email.com>"),
        );
        assert!(
            f.iter().any(|x| x.id == "PROV-003"),
            "username change alone must trigger PROV-003"
        );
    }

    #[test]
    fn config_loads_from_toml_or_defaults() {
        use crate::ScanConfig;
        // Missing file -> defaults.
        let cfg =
            ScanConfig::from_toml_file_or_default(Path::new("/nonexistent/aur.toml")).unwrap();
        assert_eq!(cfg.timeout_seconds, 30);
    }
}
