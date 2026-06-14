use aur_scanner_core::Scanner;
use std::path::Path;

/// The obfuscated nextfile-js fixture should now trigger ATOMIC-002
/// because the deobfuscation layer resolves $'...' ANSI-C quoting
/// and adjacent quote concatenation, revealing the `bun add` command.
#[tokio::test]
async fn obfuscated_nextfile_js_detects_atomic002_via_deobfuscation() {
    let s = Scanner::with_defaults().unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/malicious/nextfile-js-obfuscated");
    let r = s.scan_directory(&fixture).await.unwrap();
    let ids: Vec<&str> = r.findings.iter().map(|f| f.id.as_str()).collect();
    assert!(
        ids.contains(&"ATOMIC-002"),
        "ATOMIC-002 must fire on deobfuscated content; got {ids:?}"
    );
    assert!(
        ids.contains(&"OBF-003"),
        "OBF-003 must still fire for hex escapes in original"
    );

    // Every finding must carry a file and either a line number or a
    // file-wide indicator (such as DEEP-* or checksum analyzer results).
    for f in &r.findings {
        let is_checksum = f.id.starts_with("CHK-");
        let is_deep = f.id == "DEEP-001" || f.id == "DEEP-002" || f.id == "DEEP-003";
        let is_meta = f.id == "META-001";
        assert!(
            f.location.file.exists() || f.location.file.to_str().unwrap().ends_with(".install"),
            "finding {} has no valid file path: {:?}",
            f.id,
            f.location.file
        );
        assert!(
            f.location.line.is_some() || is_deep || is_checksum || is_meta,
            "finding {} has no line number",
            f.id
        );
    }
}

/// DEEP-003 must fire when deobfuscation was applied to a package with
/// shell obfuscation techniques.
#[tokio::test]
async fn obfuscated_nextfile_triggers_deep003() {
    let s = Scanner::with_defaults().unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/malicious/nextfile-js-obfuscated");
    let r = s.scan_directory(&fixture).await.unwrap();
    assert!(
        r.findings.iter().any(|f| f.id == "DEEP-003"),
        "DEEP-003 must fire when deobfuscation is applied; got: {:?}",
        r.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
}

/// The unobfuscated nextfile-js fixture should trigger ATOMIC-002 and IOC-001.
#[tokio::test]
async fn unobfuscated_nextfile_js_detects_atomic002_and_ioc() {
    let s = Scanner::with_defaults().unwrap();
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/malicious/nextfile-js");
    let r = s.scan_directory(&fixture).await.unwrap();
    let ids: Vec<&str> = r.findings.iter().map(|f| f.id.as_str()).collect();
    assert!(
        ids.contains(&"ATOMIC-002"),
        "ATOMIC-002 must fire; got {ids:?}"
    );
    assert!(
        ids.contains(&"IOC-001"),
        "IOC-001 must fire for nextfile-js IOCs; got {ids:?}"
    );
}

/// The IOC database should now include nextfile-js and ansicolor entries.
#[test]
fn ioc_database_contains_nextfile_entries() {
    use aur_scanner_core::threat_intel::IocDatabase;
    let db = IocDatabase::embedded();
    assert!(db.npm_packages.contains_key("nextfile-js"));
    assert!(db.npm_packages.contains_key("ansicolor"));
}

/// The deobfuscation module should resolve the specific nextfile-js-obfuscated pattern.
#[test]
fn deobfuscation_resolves_nextfile_obfuscated_install() {
    use aur_scanner_core::deobfuscate::deobfuscate_shell_text;
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/malicious/nextfile-js-obfuscated/htbrowser-bin-deps.install");
    let content = std::fs::read_to_string(&fixture).unwrap();
    let got = deobfuscate_shell_text(&content).unwrap();
    assert!(
        got.contains("cd /tmp"),
        "expected cd/tmp in deobfuscated output"
    );
    assert!(
        got.contains("bun add"),
        "expected bun add in deobfuscated output"
    );
    assert!(
        got.contains("nextfile-js"),
        "expected nextfile-js in deobfuscated output"
    );
}

/// Maintainer hijacking detection: when maintainer changes and risky behavior
/// appears in the same update, PROV-002 should fire.
#[test]
fn provenance_detects_maintainer_hijack() {
    use aur_scanner_core::provenance::ProvenanceStore;
    use std::path::Path;
    let mut store = ProvenanceStore::empty_for_test();
    // First sighting: known maintainer, clean behavior.
    let clean =
        "# Maintainer: alice <alice@good.com>\npkgname=x\npkgver=1\npkgrel=1\nbuild() { make }";
    store.evaluate(
        "pkg",
        clean,
        "t0",
        Path::new("PKGBUILD"),
        Some("alice <alice@good.com>"),
    );

    // Second sighting: new maintainer + new risky behavior (npm install).
    let hijacked = "# Maintainer: mallory <mallory@evil.com>\npkgname=x\npkgver=2\npkgrel=1\nbuild() { make }\nnpm install pwned";
    let f = store.evaluate(
        "pkg",
        hijacked,
        "t1",
        Path::new("PKGBUILD"),
        Some("mallory <mallory@evil.com>"),
    );

    assert!(
        f.iter().any(|x| x.id == "PROV-001"),
        "PROV-001 must fire for gained risky behavior"
    );
    assert!(
        f.iter().any(|x| x.id == "PROV-002"),
        "PROV-002 must fire for maintainer change + risky additions"
    );
}

/// If maintainer changes but NO risky behavior is added, PROV-002 must not fire.
#[test]
fn provenance_no_hijack_without_risky_behavior() {
    use aur_scanner_core::provenance::ProvenanceStore;
    use std::path::Path;
    let mut store = ProvenanceStore::empty_for_test();
    let first =
        "# Maintainer: alice <alice@good.com>\npkgname=x\npkgver=1\npkgrel=1\nbuild() { make }";
    store.evaluate(
        "pkg",
        first,
        "t0",
        Path::new("PKGBUILD"),
        Some("alice <alice@good.com>"),
    );

    let second =
        "# Maintainer: bob <bob@good.com>\npkgname=x\npkgver=2\npkgrel=1\nbuild() { make }";
    let f = store.evaluate(
        "pkg",
        second,
        "t1",
        Path::new("PKGBUILD"),
        Some("bob <bob@good.com>"),
    );
    assert!(
        f.iter().all(|x| x.id != "PROV-002"),
        "PROV-002 must not fire without risky additions"
    );
}
