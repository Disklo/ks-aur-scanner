//! Shell string deobfuscation.
//!
//! Resolve ANSI-C `$'...'` quoting (hex, octal, and standard escapes) and
//! adjacent quoted-token concatenation, so the rule engine can see through
//! character-level obfuscation that hides commands from line-based regexes.
//!
//! This is purely static string resolution: no shell execution, no process
//! spawning, no evaluation of the package content. It is analogous to how the
//! deep analyzer already reasons about decode->execute flows across lines.

use regex::Regex;
use std::collections::HashMap;

/// Deobfuscate shell text by resolving ANSI-C `$'...'` strings and flattening
/// adjacent quoted tokens into single words. Returns `None` if nothing changed.
pub fn deobfuscate_shell_text(text: &str) -> Option<String> {
    let mut changed = false;
    let vars = track_assignments(text);
    let mut result = String::with_capacity(text.len());

    for line in text.lines() {
        if !result.is_empty() {
            result.push('\n');
        }
        let stage1 = resolve_ansi_c(line);
        if stage1 != line {
            changed = true;
        }
        let stage2 = flatten_adjacent_quotes(&stage1);
        // Strip remaining quotes so bare characters between quoted segments
        // coalesce: "a"d"d" becomes add, 'c'"d" becomes cd after ANSI-C
        // wrapping. The original text is still scanned verbatim, so legitimate
        // quoting is not lost.
        let stage3 = strip_quotes(&stage2);
        // Lowercase and strip null / non-printable bytes so case-swapped
        // commands (BuN aDd) and null-padded tokens (b\0u\0n) resolve.
        // Whitespace and structural characters are preserved to avoid
        // mashing paths into command-shaped false positives.
        let stage4 = normalize_case_and_bytes(&stage3);
        let stage5 = resolve_variables(&stage4, &vars);
        if stage5 != line {
            changed = true;
            result.push_str(&stage5);
        } else {
            result.push_str(line);
        }
    }

    if changed {
        Some(result)
    } else {
        None
    }
}

/// Track simple variable assignments so indirection obfuscation like
/// `CMD=bun; $CMD add` can be resolved. Only literal string values are
/// tracked (no arithmetic, command substitution, or complex expressions).
fn track_assignments(text: &str) -> HashMap<String, String> {
    use regex::Regex;
    let re = Regex::new(
        r#"(?m)^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)=(['][^']*[']|["][^"]*["]|[^\s;|&<>`$()'"]*)"#,
    )
    .unwrap();
    let mut vars = HashMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if let Some(caps) = re.captures(trimmed) {
            let name = caps.get(1).map(|m| m.as_str().to_string());
            let value = caps.get(2).map(|m| {
                let v = m.as_str();
                // Strip surrounding quotes if present.
                let inner = v.strip_prefix('\'').and_then(|s| s.strip_suffix('\''));
                let inner = inner.or_else(|| v.strip_prefix('"').and_then(|s| s.strip_suffix('"')));
                inner.unwrap_or(v).to_string()
            });
            if let (Some(n), Some(v)) = (name, value) {
                if v.len() <= 200 && !v.contains('<') && !v.contains('(') && !v.contains('`') {
                    vars.insert(n.to_lowercase(), v);
                }
            }
        }
    }
    vars
}

/// Replace `$VAR` and `${VAR}` with tracked variable values.
/// Returns the input unchanged if no replacements were made.
fn resolve_variables(line: &str, vars: &HashMap<String, String>) -> String {
    if vars.is_empty() {
        return line.to_string();
    }
    let re = Regex::new(r"\$([A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})").unwrap();
    let mut result = line.to_string();
    let mut changed = true;
    // Loop to handle nested references (rare but possible).
    while changed {
        changed = false;
        let replaced = re
            .replace_all(&result, |caps: &regex::Captures| {
                let key_raw = &caps[1];
                let key = key_raw
                    .trim_start_matches('{')
                    .trim_end_matches('}')
                    .to_lowercase();
                vars.get(&key)
                    .cloned()
                    .unwrap_or_else(|| caps[0].to_string())
            })
            .to_string();
        if replaced != result {
            changed = true;
            result = replaced;
        }
    }
    result
}

/// Resolve ANSI-C `$'...'` quoting: hex (`\xNN`), octal (`\NNN`/`\0NNN`),
/// and standard escapes (`\n`, `\t`, `\\`, `\'`, etc.).  The resolved content
/// is wrapped in single quotes so the adjacent-quote flattening pass can merge
/// it with neighbouring quoted strings (e.g. `$'\x63'"d"` → `'c'"d"` → `cd`).
fn resolve_ansi_c(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        // Look for $'
        if bytes[i] == b'$' && i + 2 < bytes.len() && bytes[i + 1] == b'\'' {
            let start = i + 2; // skip $'
            let mut j = start;
            let mut resolved = String::new();
            while j < bytes.len() {
                if bytes[j] == b'\\' && j + 1 < bytes.len() {
                    let (ch, advance) = ansi_c_escape(&bytes[j + 1..]);
                    resolved.push(ch);
                    j += 1 + advance;
                } else if bytes[j] == b'\'' {
                    j += 1; // closing quote
                    break;
                } else {
                    resolved.push(bytes[j] as char);
                    j += 1;
                }
            }
            // Wrap resolved content in single quotes so adjacent-quote
            // flattening can merge it with neighbouring quoted segments.
            if !resolved.is_empty() {
                out.push('\'');
                out.push_str(&resolved);
                out.push('\'');
            }
            i = j;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Resolve one ANSI-C escape sequence (the characters *after* the backslash).
/// Returns the decoded character and how many bytes were consumed.
fn ansi_c_escape(tail: &[u8]) -> (char, usize) {
    if tail.is_empty() {
        return ('\\', 0);
    }
    let c = tail[0];
    match c {
        b'x' | b'X' => {
            let mut hex = String::new();
            let mut consumed = 1;
            for off in 1..=2 {
                if tail.len() > off && tail[off].is_ascii_hexdigit() {
                    hex.push(tail[off] as char);
                    consumed += 1;
                } else {
                    break;
                }
            }
            if hex.is_empty() {
                ('x', 0)
            } else {
                let val = u8::from_str_radix(&hex, 16).unwrap_or(0);
                (val as char, consumed)
            }
        }
        b'0'..=b'7' => {
            let mut consumed = 0;
            let mut val: u16 = 0;
            for off in 0..3 {
                if tail.len() > off && tail[off] >= b'0' && tail[off] <= b'7' {
                    val = val * 8 + (tail[off] - b'0') as u16;
                    consumed += 1;
                } else {
                    break;
                }
            }
            (val as u8 as char, consumed)
        }
        b'n' => ('\n', 1),
        b't' => ('\t', 1),
        b'r' => ('\r', 1),
        b'a' => ('\x07', 1),
        b'b' => ('\x08', 1),
        b'e' | b'E' => ('\x1b', 1),
        b'f' => ('\x0c', 1),
        b'v' => ('\x0b', 1),
        b'\\' => ('\\', 1),
        b'\'' => ('\'', 1),
        b'"' => ('"', 1),
        b'?' => ('?', 1),
        b'c' => {
            if tail.len() >= 2 {
                let ctrl = tail[1];
                let val = match ctrl {
                    b'a'..=b'z' => ctrl - b'a' + 1,
                    b'A'..=b'Z' => ctrl - b'A' + 1,
                    b'?' => 0x7f,
                    _ => ctrl,
                };
                (val as char, 2)
            } else {
                ('c', 0)
            }
        }
        _ => (c as char, 1),
    }
}

/// Merge adjacent quoted strings into their concatenated content.
/// `"b"'u''n'` → `bun`, `'a'"d"'d'` → `add`.  Single isolated quoted
/// strings and bare text are kept verbatim.
fn flatten_adjacent_quotes(input: &str) -> String {
    // Merge runs of 2+ immediately-adjacent quoted strings.
    // "b"'u''n' → bun, 'a'"d"'d' → add.  Single isolated quoted
    // strings and bare text are kept verbatim.
    lazy_static::lazy_static! {
        static ref QUOTED: Regex = Regex::new(
            r#"(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')"#
        ).unwrap();
    }

    let mut result = input.to_string();
    loop {
        // Find the *first* run of 2+ adjacent quoted tokens.
        let mut run_start: Option<usize> = None;
        let mut run_end: Option<usize> = None;
        let mut merged = String::new();
        let mut segments: usize = 0;

        for m in QUOTED.find_iter(&result) {
            let is_adjacent = run_end.map(|e| e == m.start()).unwrap_or(false);

            if run_start.is_some() && !is_adjacent {
                // Previous run ended; if it had >1 segment, we're done scanning.
                if segments > 1 {
                    break;
                }
                // Reset and start fresh.
                run_start = None;
                merged.clear();
                segments = 0;
            }

            let q = m.as_str();
            let inner = &q[1..q.len() - 1];
            if run_start.is_none() {
                run_start = Some(m.start());
            }
            merged.push_str(inner);
            segments += 1;
            run_end = Some(m.end());
        }

        if let (Some(start), Some(end)) = (run_start, run_end) {
            if segments > 1 {
                result.replace_range(start..end, &merged);
                continue; // re-scan with new string
            }
        }
        break;
    }

    result
}

/// Strip all single and double quotes from text.  This runs after ANSI-C
/// resolution and adjacent-quote flattening so that bare characters between
/// quoted segments coalesce (e.g. `"a"d"d"` → `add`, `'c'"d"` → `cd`).  The
/// original text is still scanned verbatim by the rule engine, so stripping
/// quotes in the deobfuscated copy cannot hide information.
fn strip_quotes(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' || bytes[i] == b'\'' {
            i += 1;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Strip null bytes and non-printable characters, then lowercase.  Whitespace
/// and structural punctuation are preserved so paths like
/// `/usr/lib/systemd/systemd-foo` do not collapse into command-shaped blobs
/// that would match rule engine patterns.
fn normalize_case_and_bytes(input: &str) -> String {
    input
        .chars()
        .filter(|c| *c == '\n' || *c == '\t' || (' ' <= *c && *c <= '~'))
        .collect::<String>()
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_hex_escape() {
        assert_eq!(resolve_ansi_c("$'\\x63'"), "'c'");
    }

    #[test]
    fn resolve_octal_escape() {
        assert_eq!(resolve_ansi_c("$'\\141'"), "'a'");
        assert_eq!(resolve_ansi_c("$'\\143'"), "'c'");
    }

    #[test]
    fn resolve_hex_plus_octal() {
        assert_eq!(resolve_ansi_c("$'\\141\\x6e'"), "'an'");
    }

    #[test]
    fn resolve_standard_escapes() {
        assert_eq!(resolve_ansi_c("$'\\n'"), "'\n'");
        assert_eq!(resolve_ansi_c("$'\\t'"), "'\t'");
        assert_eq!(resolve_ansi_c("$'\\\\'"), "'\\'");
    }

    #[test]
    fn bare_text_unchanged() {
        assert_eq!(resolve_ansi_c("hello"), "hello");
    }

    #[test]
    fn flatten_simple_adjacent() {
        assert_eq!(flatten_adjacent_quotes("\"b\"'u''n'"), "bun");
        assert_eq!(flatten_adjacent_quotes("'a'\"d\"'d'"), "add");
    }

    #[test]
    fn flatten_keeps_spacing() {
        // Space between runs — each run is merged independently.
        let input = "\"b\"'u' 'a'\"d\"'d'";
        assert_eq!(flatten_adjacent_quotes(input), "bu add");
    }

    #[test]
    fn flatten_single_quote_kept() {
        assert_eq!(flatten_adjacent_quotes("\"hello\""), "\"hello\"");
        assert_eq!(flatten_adjacent_quotes("'world'"), "'world'");
    }

    #[test]
    fn strip_bare_characters_between_quotes() {
        // Bare 'd' between "a" and "d" should coalesce via strip_quotes.
        assert_eq!(strip_quotes("\"a\"d\"d\""), "add");
        assert_eq!(strip_quotes("'c'\"d\""), "cd");
    }

    #[test]
    fn deobfuscate_bare_between_quotes() {
        // "a"d"d" → add (deobfuscation full pipeline).
        let input = "\"a\"d\"d\" evil";
        let got = deobfuscate_shell_text(input).unwrap();
        assert_eq!(got, "add evil");
    }

    #[test]
    fn normalize_lowercases_and_strips_null() {
        assert_eq!(normalize_case_and_bytes("BuN aDd"), "bun add");
        assert_eq!(normalize_case_and_bytes("b\u{0}u\u{0}n add"), "bun add");
        assert_eq!(
            normalize_case_and_bytes("Npm Install Evil"),
            "npm install evil"
        );
    }

    #[test]
    fn normalize_preserves_path_structure() {
        // Paths are lowercased but structure (hyphens, slashes) stays intact.
        let input = "/usr/lib/systemd/systemd-foo";
        assert_eq!(normalize_case_and_bytes(input), input);
        assert_eq!(
            normalize_case_and_bytes("/usr/lib/SystemD/systemd-IniTd"),
            "/usr/lib/systemd/systemd-initd"
        );
    }

    #[test]
    fn normalize_strips_nonprintable() {
        assert_eq!(normalize_case_and_bytes("bun\x07\x1b add"), "bun add");
    }

    #[test]
    fn full_pipeline_lowercases_obfuscated_command() {
        // Mixed-case command in install script should be caught after normalization.
        let input = "$'\\x63'D /tmp && \"B\"'u''N' AdD nextfile-js";
        let got = deobfuscate_shell_text(input).unwrap();
        assert!(got.contains("bun add"));
        assert!(got.contains("cd /tmp"));
    }

    #[test]
    fn flatten_double_empty_quote() {
        // "" is an empty double-quoted string. "i" and "" are adjacent → "i".
        // "c" is separated by a space so it stays isolated.
        assert_eq!(flatten_adjacent_quotes("\"i\"\"\" \"c\""), "i \"c\"");
    }

    #[test]
    fn full_deobfuscate_nextfile_style() {
        // Read the actual obfuscated fixture file.
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../tests/fixtures/malicious/nextfile-js-obfuscated/htbrowser-bin-deps.install",
        );
        let content = std::fs::read_to_string(&fixture).unwrap();
        let got = deobfuscate_shell_text(&content).unwrap();
        // The deobfuscated version should contain the unobfuscated command.
        assert!(got.contains("cd /tmp"));
        assert!(got.contains("bun add"));
        assert!(got.contains("nextfile-js"));
    }

    #[test]
    fn deobfuscate_no_change_returns_none() {
        assert!(deobfuscate_shell_text("make install").is_none());
        assert!(deobfuscate_shell_text("build() { make }").is_none());
    }

    #[test]
    fn deobfuscate_multiline() {
        let input = "post_install() {\n  $'\\x63''d' /tmp\n}";
        let got = deobfuscate_shell_text(input).unwrap();
        assert!(got.contains("cd /tmp"));
    }

    #[test]
    fn track_simple_assignment() {
        let text = "CMD=bun\n$CMD add evil";
        let got = deobfuscate_shell_text(text).unwrap();
        assert!(got.contains("bun add evil"));
    }

    #[test]
    fn track_braced_reference() {
        let text = "PKG=evil\nbun add ${PKG}";
        let got = deobfuscate_shell_text(text).unwrap();
        assert!(got.contains("bun add evil"));
    }

    #[test]
    fn resolve_variable_no_change_for_untracked() {
        // $HOME has no tracked assignment, but normalization lowercases it.
        let text = "ls $HOME";
        let got = deobfuscate_shell_text(text).unwrap();
        assert!(got.contains("ls $home"));
    }

    #[test]
    fn resolve_quoted_assignment() {
        let text = "CMD='bun'\n$CMD add pkg";
        let got = deobfuscate_shell_text(text).unwrap();
        assert!(got.contains("bun add pkg"));
    }

    #[test]
    fn resolve_double_quoted_assignment() {
        let text = "CMD=\"bun\"\n$CMD add pkg";
        let got = deobfuscate_shell_text(text).unwrap();
        assert!(got.contains("bun add pkg"));
    }

    #[test]
    fn ignores_comment_assignments() {
        let text = "# CMD=evil\n$CMD add";
        let got = deobfuscate_shell_text(text).unwrap();
        // The deobfuscated output must not resolve $CMD from the commented
        // assignment.  "evil" may appear in the lowercased comment line but
        // must not appear on the second line (the actual command).
        assert!(
            !got.contains("add evil"),
            "comment assignment must not resolve; got: {got:?}"
        );
    }
}
