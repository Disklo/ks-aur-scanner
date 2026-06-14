//! AUR Security Scanner Core Library
//!
//! Provides security analysis capabilities for Arch Linux AUR packages.
//! Detects malicious patterns in PKGBUILDs and install scripts.

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod analyzer;
pub mod aur;
pub mod cache;
pub mod catalog;
pub mod deobfuscate;
pub mod depgraph;
pub mod error;
pub mod overlay;
pub mod parser;
pub mod provenance;
pub mod rules;
pub mod sbom;
pub mod threat_intel;
pub mod types;

pub use error::{ParseError, Result, ScanError};
pub use types::*;

use analyzer::SecurityAnalyzer;
use parser::PkgbuildParser;
use rules::RuleEngine;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use threat_intel::IocDatabase;
use tracing::{debug, info, warn};

/// Main scanner that orchestrates all security analysis
pub struct Scanner {
    analyzers: Vec<Arc<dyn SecurityAnalyzer>>,
    parser: Box<dyn PkgbuildParser>,
    rule_engine: Arc<RuleEngine>,
    ioc_db: Arc<IocDatabase>,
    config: ScanConfig,
}

impl Scanner {
    /// Create a new scanner with the given configuration
    pub fn new(config: ScanConfig) -> Result<Self> {
        // Use default() which loads built-in rules
        let rule_engine = Arc::new(RuleEngine::default());
        let ioc_db = Arc::new(IocDatabase::load());

        let analyzers: Vec<Arc<dyn SecurityAnalyzer>> = vec![
            Arc::new(analyzer::PatternAnalyzer::new(rule_engine.clone())),
            Arc::new(analyzer::IocAnalyzer::new(ioc_db.clone())),
            Arc::new(analyzer::DeepAnalyzer::new()),
            Arc::new(analyzer::RemoteExecAnalyzer::new()),
            Arc::new(analyzer::SourceAnalyzer::new()),
            Arc::new(analyzer::ChecksumAnalyzer::new()),
            Arc::new(analyzer::PrivilegeAnalyzer::new()),
        ];

        let parser: Box<dyn PkgbuildParser> = Box::new(parser::StaticParser::new());

        Ok(Self {
            analyzers,
            parser,
            rule_engine,
            ioc_db,
            config,
        })
    }

    /// The IOC database backing this scanner (embedded defaults + overrides).
    pub fn ioc_database(&self) -> Arc<IocDatabase> {
        self.ioc_db.clone()
    }

    /// Create a scanner with default configuration
    pub fn with_defaults() -> Result<Self> {
        Self::new(ScanConfig::default())
    }

    /// Load rules from a directory
    pub fn load_rules(&mut self, rules_dir: &Path) -> Result<()> {
        Arc::get_mut(&mut self.rule_engine)
            .ok_or_else(|| ScanError::Config("Cannot modify rule engine".into()))?
            .load_rules_from_dir(rules_dir)?;
        Ok(())
    }

    /// Scan a PKGBUILD file
    pub async fn scan_pkgbuild(&self, path: &Path) -> Result<ScanResult> {
        let start = std::time::Instant::now();
        info!("Scanning PKGBUILD: {}", path.display());

        // Read and parse PKGBUILD. Cap the read: a real PKGBUILD is a few KB,
        // so a multi-megabyte one is itself abnormal and a memory-DoS risk from
        // a hostile repo. Refuse rather than load it all.
        let content = read_text_capped(path)?;
        let pkgbuild = self.parser.parse(&content)?;

        debug!(
            "Parsed package: {} version {}-{}",
            pkgbuild.pkgname.first().unwrap_or(&"unknown".to_string()),
            pkgbuild.pkgver,
            pkgbuild.pkgrel
        );

        // Parse install script if present. The install= filename is frequently
        // written with variables (install="$pkgname.install"), and the install
        // hook is exactly where install-time payloads (CHAOS RAT, Atomic Arch)
        // live -- so resolution must expand variables and fall back to globbing.
        let dir = path.parent().unwrap_or(Path::new("."));
        let install_path = resolve_install_path(dir, &pkgbuild);
        let install_script = if let Some(install_path) = install_path {
            match read_text_capped(&install_path) {
                Ok(script_content) => Some(parser::ParsedInstallScript {
                    content: script_content.clone(),
                    path: install_path,
                    hooks: parser::parse_install_hooks(&script_content),
                }),
                Err(e) => {
                    warn!(
                        "Failed to read install script {}: {}",
                        install_path.display(),
                        e
                    );
                    None
                }
            }
        } else {
            None
        };
        let scanned_install = install_script.as_ref().map(|s| s.path.clone());

        // Create analysis context
        let deob_pkgbuild = deobfuscate::deobfuscate_shell_text(&pkgbuild.raw_content);
        let deob_install = install_script
            .as_ref()
            .and_then(|s| deobfuscate::deobfuscate_shell_text(&s.content));
        let resolved_vars = track_variable_assignments(&pkgbuild.raw_content);
        let maintainer_id = extract_maintainer_id(&pkgbuild.raw_content);

        let context = AnalysisContext {
            pkgbuild: pkgbuild.clone(),
            install_script,
            config: self.config.clone(),
            file_path: path.to_path_buf(),
            deobfuscated_pkgbuild_content: deob_pkgbuild,
            deobfuscated_install_content: deob_install,
            resolved_variables: resolved_vars,
            maintainer_id,
        };

        // Run all analyzers
        let mut findings = Vec::new();
        for analyzer in &self.analyzers {
            match analyzer.analyze(&context).await {
                Ok(analyzer_findings) => {
                    debug!(
                        "Analyzer {} found {} issues",
                        analyzer.name(),
                        analyzer_findings.len()
                    );
                    findings.extend(analyzer_findings);
                }
                Err(e) => {
                    warn!("Analyzer {} failed: {}", analyzer.name(), e);
                }
            }
        }

        // Emit an audit code if deobfuscation was applied so the chain is
        // traceable: which deobfuscation techniques were used, and what the
        // resolved text looks like.
        if context.deobfuscated_install_content.is_some()
            || context.deobfuscated_pkgbuild_content.is_some()
        {
            let mut techniques = Vec::new();
            if context.deobfuscated_pkgbuild_content.is_some()
                || context.deobfuscated_install_content.is_some()
            {
                techniques.push("ansi-c-quote-flatten-normalize-variable-expansion");
            }
            if !context.resolved_variables.is_empty() {
                techniques.push("variable-tracking");
            }
            findings.push(Finding {
                id: "DEEP-003".to_string(),
                severity: Severity::Low,
                category: Category::Obfuscation,
                title: "Deobfuscation applied during scan".to_string(),
                description: format!(
                    "Shell deobfuscation techniques were applied: {}. \
                     The deobfuscated text was re-scanned for hidden commands. \
                     Any findings with 'deobfuscated: true' in their metadata \
                     were detected only after deobfuscation.",
                    techniques.join(", "),
                ),
                location: Location {
                    file: path.to_path_buf(),
                    line: None,
                    column: None,
                    snippet: None,
                },
                recommendation:
                    "Review deobfuscated findings carefully; they indicate deliberate evasion."
                        .to_string(),
                cwe_id: None,
                metadata: serde_json::json!({
                    "techniques": techniques,
                }),
            });
        }

        // Filter by minimum severity (lower enum value = higher severity)
        findings.retain(|f| f.severity <= self.config.min_severity);

        // Sort by severity (critical first)
        findings.sort_by_key(|f| f.severity);

        let duration = start.elapsed();
        info!(
            "Scan complete: {} findings in {:?}",
            findings.len(),
            duration
        );

        let mut scanned_files = vec![path.to_path_buf()];
        if let Some(install_path) = scanned_install {
            scanned_files.push(install_path);
        }

        Ok(ScanResult {
            package_name: pkgbuild.pkgname.first().cloned().unwrap_or_default(),
            package_version: format!("{}-{}", pkgbuild.pkgver, pkgbuild.pkgrel),
            findings,
            scanned_files,
            timestamp: chrono::Utc::now(),
            scan_duration_ms: duration.as_millis() as u64,
        })
    }

    /// Scan a directory containing a PKGBUILD
    pub async fn scan_directory(&self, dir: &Path) -> Result<ScanResult> {
        let pkgbuild_path = dir.join("PKGBUILD");
        if !pkgbuild_path.exists() {
            return Err(ScanError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("PKGBUILD not found in {}", dir.display()),
            )));
        }
        self.scan_pkgbuild(&pkgbuild_path).await
    }
}

/// Maximum size of a file the scanner will read into memory. Real PKGBUILDs
/// and install scripts are a few KB; anything past this is abnormal and a
/// memory-exhaustion risk from a hostile repository.
const MAX_SCAN_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Read a text file, refusing files larger than [`MAX_SCAN_FILE_BYTES`].
fn read_text_capped(path: &Path) -> Result<String> {
    let len = std::fs::metadata(path)?.len();
    if len > MAX_SCAN_FILE_BYTES {
        warn!(
            "refusing to read {} ({} bytes > {} cap): possible resource-exhaustion attempt",
            path.display(),
            len,
            MAX_SCAN_FILE_BYTES
        );
        return Err(ScanError::Io(std::io::Error::other(format!(
            "file too large to scan safely: {len} bytes"
        ))));
    }
    Ok(std::fs::read_to_string(path)?)
}

/// Resolve the path to a package's install script.
///
/// PKGBUILDs commonly reference the install file via variables
/// (`install="$pkgname.install"`), and some omit `install=` while still
/// shipping a `*.install` hook. Both cases must be resolved, because the
/// install hook is a primary malware delivery vector. Resolution order:
/// 1. Expand `$pkgname`/`$pkgbase` in the declared `install=` value.
/// 2. Fall back to a single `*.install` file in the package directory.
fn resolve_install_path(
    dir: &Path,
    pkgbuild: &parser::ParsedPkgbuild,
) -> Option<std::path::PathBuf> {
    let pkgname = pkgbuild.pkgname.first().cloned().unwrap_or_default();

    if let Some(install_file) = &pkgbuild.install {
        let expanded = expand_pkg_vars(install_file, &pkgname);
        // An install scriptlet is always a bare filename inside the package
        // directory. Reject path separators / traversal so a hostile install=
        // value cannot make us read a file outside the cloned package dir.
        if expanded.is_empty() || expanded.contains('/') || expanded.contains("..") {
            warn!(
                "ignoring suspicious install= value '{}' (path traversal)",
                install_file
            );
        } else {
            let candidate = dir.join(&expanded);
            if candidate.is_file() {
                return Some(candidate);
            }
            warn!(
                "install= references '{}' (resolved '{}') but the file is missing; \
                 falling back to *.install discovery",
                install_file, expanded
            );
        }
    }

    // Fallback: a lone *.install file in the package directory.
    let mut install_files: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("install"))
        .collect();
    install_files.sort();
    match install_files.len() {
        0 => None,
        1 => Some(install_files.remove(0)),
        _ => {
            // Prefer the one matching the package name; otherwise scan the first
            // and warn so the gap is visible rather than silent.
            let preferred = install_files
                .iter()
                .find(|p| p.file_stem().and_then(|s| s.to_str()) == Some(pkgname.as_str()))
                .cloned();
            if preferred.is_none() {
                warn!(
                    "multiple *.install files in {}; scanning '{}'",
                    dir.display(),
                    install_files[0].display()
                );
            }
            preferred.or_else(|| Some(install_files.remove(0)))
        }
    }
}

/// Expand the small set of PKGBUILD variables that legitimately appear in an
/// `install=` value: `$pkgname`/`${pkgname}` and `$pkgbase`/`${pkgbase}`.
fn expand_pkg_vars(value: &str, pkgname: &str) -> String {
    value
        .replace("${pkgname}", pkgname)
        .replace("$pkgname", pkgname)
        .replace("${pkgbase}", pkgname)
        .replace("$pkgbase", pkgname)
        .trim_matches(['"', '\''])
        .to_string()
}

/// Track simple variable assignments to help see through indirection obfuscation
/// where attackers use variables to hide command names (e.g., CMD=bun, then $CMD add).
/// Only tracks literal string assignments; arithmetic and command substitution are
/// deliberately skipped to avoid executing anything.
fn track_variable_assignments(content: &str) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    let re = regex_lite::var_assign();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if let Some(caps) = re.captures(trimmed) {
            let name = caps.get(1).map(|m| m.as_str().to_string());
            let value = caps.get(2).map(|m| m.as_str().to_string());
            if let (Some(n), Some(v)) = (name, value) {
                // Only track short simple values to avoid false positives.
                if v.len() <= 50 && !v.contains('<') && !v.contains('(') {
                    vars.insert(n, v);
                }
            }
        }
    }
    vars
}

/// Extract the full maintainer identifier from the PKGBUILD header,
/// including both name and email (e.g. `"John Doe <john@example.com>"`).
/// Returns `None` if no maintainer header is found.
pub fn extract_maintainer_id(content: &str) -> Option<String> {
    let re = regex::Regex::new(r"(?i)#\s*Maintainer:\s*(.+?)\s*$").ok()?;
    for line in content.lines() {
        if let Some(caps) = re.captures(line) {
            let raw = caps.get(1).map(|m| m.as_str().trim());
            // Strip trailing # comments on the same line.
            let cleaned = raw.map(|s| s.splitn(2, '#').next().unwrap_or(s).trim().to_string());
            return cleaned.filter(|s| !s.is_empty());
        }
    }
    None
}

/// Lightweight regex helpers kept in a sub-module so `regex` doesn't compile on
/// every call.
mod regex_lite {
    use std::sync::OnceLock;

    static VAR_ASSIGN: OnceLock<regex::Regex> = OnceLock::new();

    pub fn var_assign() -> &'static regex::Regex {
        VAR_ASSIGN.get_or_init(|| {
            regex::Regex::new(
                r#"(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)=(?:'([^']*)'|"([^"]*)"|([^\s;|&<>`$()'"]*))"#,
            )
            .expect("variable assignment regex must compile")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scanner_creation() {
        let scanner = Scanner::with_defaults();
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_install_path_rejects_traversal() {
        // A hostile install= value must not let resolution read outside the dir.
        let pkg = parser::ParsedPkgbuild {
            pkgname: vec!["x".into()],
            install: Some("../../../../etc/passwd".into()),
            ..Default::default()
        };
        let resolved = resolve_install_path(Path::new("/tmp/some-pkg-dir"), &pkg);
        assert!(resolved.is_none(), "traversal value must be rejected");
    }

    #[test]
    fn test_expand_pkg_vars() {
        assert_eq!(
            expand_pkg_vars("${pkgname}.install", "alvr"),
            "alvr.install"
        );
        assert_eq!(expand_pkg_vars("$pkgname.install", "alvr"), "alvr.install");
        assert_eq!(
            expand_pkg_vars("\"$pkgbase.install\"", "alvr"),
            "alvr.install"
        );
        assert_eq!(expand_pkg_vars("custom.install", "alvr"), "custom.install");
    }

    #[tokio::test]
    async fn test_scan_detects_install_hook_with_var_filename() {
        // Regression: install="${pkgname}.install" must still resolve so the
        // install-hook rules actually run.
        let scanner = Scanner::with_defaults().unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/malicious/atomic-arch");
        if !fixture.join("PKGBUILD").exists() {
            return; // fixture not present in this checkout
        }
        let result = scanner.scan_directory(&fixture).await.unwrap();
        assert!(
            result.findings.iter().any(|f| f.id == "ATOMIC-001"),
            "expected ATOMIC-001 from the install hook; got: {:?}",
            result.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
        assert!(result
            .scanned_files
            .iter()
            .any(|p| { p.extension().and_then(|e| e.to_str()) == Some("install") }));
    }

    #[test]
    fn test_extract_maintainer_id_strips_trailing_comment() {
        let content = "# Maintainer: John Doe <john@example.com>  # adopted 2024";
        assert_eq!(
            extract_maintainer_id(content).as_deref(),
            Some("John Doe <john@example.com>")
        );
    }

    #[test]
    fn test_extract_maintainer_id_no_header_returns_none() {
        assert_eq!(extract_maintainer_id("pkgname=foo\npkgver=1"), None);
    }

    #[test]
    fn test_extract_maintainer_id_empty_after_comment_strip() {
        // Entire value is a comment — should return None.
        let content = "# Maintainer: # was orphaned";
        assert_eq!(extract_maintainer_id(content), None);
    }
}
