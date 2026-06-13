//! IOC analyzer: matches scanned content against the local IOC database.
//!
//! Complements the heuristic pattern engine. Where the pattern engine reasons
//! about *behavior* ("an install hook runs npm"), this analyzer matches known
//! *indicators* ("the package atomic-lockfile", "the file scales.bpf.c"),
//! catching hijacks that otherwise look clean.

use super::SecurityAnalyzer;
use crate::error::Result;
use crate::threat_intel::IocDatabase;
use crate::types::{AnalysisContext, Category, Finding, Location, Severity};
use async_trait::async_trait;
use std::sync::Arc;

/// Analyzer that matches content against the IOC database.
pub struct IocAnalyzer {
    db: Arc<IocDatabase>,
}

impl IocAnalyzer {
    /// Create an analyzer backed by the given IOC database.
    pub fn new(db: Arc<IocDatabase>) -> Self {
        Self { db }
    }

    fn finding_for(
        &self,
        context: &AnalysisContext,
        file: &std::path::Path,
        hit: &crate::threat_intel::IocHit,
    ) -> Finding {
        let campaign_name = hit
            .campaign
            .as_deref()
            .and_then(|id| self.db.campaign(id))
            .map(|c| c.name.clone());
        let campaign_suffix = campaign_name
            .as_ref()
            .map(|n| format!(" (campaign: {n})"))
            .unwrap_or_default();

        Finding {
            id: "IOC-001".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            title: format!("Known IOC: {} '{}'", hit.kind.label(), hit.value),
            description: format!(
                "Content matches a known indicator of compromise: {} '{}'{}.",
                hit.kind.label(),
                hit.value,
                campaign_suffix
            ),
            location: Location {
                file: file.to_path_buf(),
                line: Some(hit.line),
                column: None,
                snippet: None,
            },
            recommendation:
                "Do NOT build. This matches a known-malicious indicator; treat the host as \
                 compromised if already built and rotate credentials."
                    .to_string(),
            cwe_id: Some("CWE-506".to_string()),
            metadata: serde_json::json!({
                "ioc_kind": format!("{:?}", hit.kind),
                "ioc_value": hit.value,
                "campaign": hit.campaign,
                "context": context.file_path.to_string_lossy(),
            }),
        }
    }
}

#[async_trait]
impl SecurityAnalyzer for IocAnalyzer {
    async fn analyze(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for hit in self.db.scan_content(&context.pkgbuild.raw_content) {
            findings.push(self.finding_for(context, &context.file_path, &hit));
        }

        if let Some(install) = &context.install_script {
            for hit in self.db.scan_content(&install.content) {
                findings.push(self.finding_for(context, &install.path, &hit));
            }
        }

        Ok(findings)
    }

    fn name(&self) -> &str {
        "ioc"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{PkgbuildParser, StaticParser};
    use crate::types::ScanConfig;
    use std::path::PathBuf;

    #[tokio::test]
    async fn flags_npm_payload_in_pkgbuild() {
        let parser = StaticParser::new();
        let pkgbuild = parser
            .parse("pkgname=x\npkgver=1\npkgrel=1\npackage() {\n npm install atomic-lockfile\n}\n")
            .unwrap();
        let context = AnalysisContext {
            pkgbuild,
            install_script: None,
            config: ScanConfig::default(),
            file_path: PathBuf::from("PKGBUILD"),
        };
        let analyzer = IocAnalyzer::new(Arc::new(IocDatabase::embedded()));
        let findings = analyzer.analyze(&context).await.unwrap();
        assert!(findings.iter().any(|f| f.id == "IOC-001"));
    }
}
