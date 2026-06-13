//! Local package overlay for race-free (TOCTOU-safe) scanning.
//!
//! `aur-scan check` normally fetches its own copy of each PKGBUILD from the AUR
//! and scans that. The helper (paru/yay) then independently re-clones and builds
//! its own copy -- so the bytes scanned are not provably the bytes built (a
//! time-of-check/time-of-use gap). To close it, the caller can scan the exact
//! on-disk directory the build will use and feed the locally-parsed package
//! metadata into dependency resolution via [`OverlaySource`].
//!
//! Names present in the overlay are answered from local PKGBUILDs; everything
//! else falls through to the wrapped remote source (the AUR RPC), so the full
//! dependency tree still resolves.

use crate::aur::{AurPackageInfo, PackageInfoSource};
use crate::error::Result;
use crate::parser::ParsedPkgbuild;
use async_trait::async_trait;
use std::collections::HashMap;

/// Synthesize AUR-style info from a locally-parsed PKGBUILD. Returns one entry
/// per `pkgname` (split packages share the same dependency metadata).
pub fn info_from_pkgbuild(pkg: &ParsedPkgbuild) -> Vec<AurPackageInfo> {
    let version = if pkg.pkgver.is_empty() {
        String::new()
    } else if let Some(epoch) = &pkg.epoch {
        format!("{}:{}-{}", epoch, pkg.pkgver, pkg.pkgrel)
    } else {
        format!("{}-{}", pkg.pkgver, pkg.pkgrel)
    };
    let base = pkg.pkgname.first().cloned().unwrap_or_default();
    pkg.pkgname
        .iter()
        .map(|name| AurPackageInfo {
            name: name.clone(),
            version: version.clone(),
            package_base: base.clone(),
            // Marker so downstream knows this came from a local dir, not the RPC.
            maintainer: Some("(local)".to_string()),
            depends: pkg.depends.clone(),
            make_depends: pkg.makedepends.clone(),
            check_depends: pkg.checkdepends.clone(),
            opt_depends: pkg.optdepends.clone(),
            provides: pkg.provides.clone(),
            ..Default::default()
        })
        .collect()
}

/// A [`PackageInfoSource`] that answers from a local overlay first, then a
/// wrapped remote source.
pub struct OverlaySource<'a> {
    overlay: HashMap<String, AurPackageInfo>,
    fallback: &'a dyn PackageInfoSource,
}

impl<'a> OverlaySource<'a> {
    /// Build an overlay from local infos, falling back to `fallback`.
    pub fn new(local: Vec<AurPackageInfo>, fallback: &'a dyn PackageInfoSource) -> Self {
        let overlay = local.into_iter().map(|i| (i.name.clone(), i)).collect();
        Self { overlay, fallback }
    }

    /// Names served from the local overlay.
    pub fn local_names(&self) -> impl Iterator<Item = &String> {
        self.overlay.keys()
    }
}

#[async_trait]
impl PackageInfoSource for OverlaySource<'_> {
    async fn info_batch(&self, names: &[&str]) -> Result<Vec<AurPackageInfo>> {
        let mut out = Vec::new();
        let mut missing: Vec<&str> = Vec::new();
        for n in names {
            if let Some(info) = self.overlay.get(*n) {
                out.push(info.clone());
            } else {
                missing.push(n);
            }
        }
        if !missing.is_empty() {
            out.extend(self.fallback.info_batch(&missing).await?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EmptyRemote;
    #[async_trait]
    impl PackageInfoSource for EmptyRemote {
        async fn info_batch(&self, _names: &[&str]) -> Result<Vec<AurPackageInfo>> {
            Ok(vec![]) // everything not local is "repo/unknown"
        }
    }

    #[test]
    fn info_from_pkgbuild_carries_deps() {
        let pkg = ParsedPkgbuild {
            pkgname: vec!["foo".into()],
            pkgver: "1.2".into(),
            pkgrel: "1".into(),
            depends: vec!["bar".into()],
            makedepends: vec!["cmake".into()],
            ..Default::default()
        };
        let infos = info_from_pkgbuild(&pkg);
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].version, "1.2-1");
        assert_eq!(infos[0].depends, vec!["bar"]);
    }

    #[tokio::test]
    async fn overlay_prefers_local_then_falls_back() {
        let local = info_from_pkgbuild(&ParsedPkgbuild {
            pkgname: vec!["foo".into()],
            pkgver: "1".into(),
            pkgrel: "1".into(),
            depends: vec!["bar".into()],
            ..Default::default()
        });
        let remote = EmptyRemote;
        let src = OverlaySource::new(local, &remote);
        let got = src.info_batch(&["foo", "bar"]).await.unwrap();
        // foo from overlay; bar absent (remote returns nothing) => repo leaf.
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "foo");
    }
}
