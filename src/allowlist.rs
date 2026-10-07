//! Caller allowlist for `dank-askpass`.
//!
//! `dank-askpass` is exec'd directly by the program that wants a credential:
//! ssh and sudo exec it themselves, gpg-agent execs it as its pinentry, and
//! rosecd's prompt wrapper execs it for passphrase prompts. That parent is
//! resolved from `/proc/<pid>/exe`, and when an allowlist is configured the
//! prompt is refused unless the caller matches.
//!
//! This is a same-user policy gate, not a sandbox: the caller controls its
//! own environment and the allowlist file, so a malicious process running as
//! the same user can always edit the list to admit itself. What it buys is
//! the same thing rosec's allowlist buys: a program that is *not* supposed to
//! summon a password dialog cannot make one appear — accidentally, or as a
//! phish — unless a human has deliberately put it on the list first.

use std::path::Path;

/// One allowlist entry, kept verbatim so `contains('/')` stays meaningful
/// (a stored path normalised on read would blur the basename/path split).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern(String);

impl Pattern {
    /// Builds an entry from one line; `None` for blanks and comments (which
    /// may trail the entry, so `firefox # the browser` lists `firefox`).
    fn from_line(line: &str) -> Option<Self> {
        let entry = line.split('#').next().unwrap_or_default().trim();
        (!entry.is_empty()).then(|| Self(entry.to_string()))
    }

    /// An entry without a slash is a glob on the executable name; with a
    /// slash it is a glob on the full path from `/proc/<pid>/exe`.
    fn matches(&self, exe: &Path) -> bool {
        let has_slash = self.0.contains('/');
        if has_slash {
            glob_match(&self.0, &exe.to_string_lossy())
        } else {
            let Some(name) = exe.file_name() else {
                return false;
            };
            glob_match(&self.0, &name.to_string_lossy())
        }
    }
}

/// Reads the allowlist file. A missing or unreadable file degrades to no
/// entries, which makes the allowlist inert: the caller that forgot to write
/// the list must not be locked out of every subsequent prompt, and calls
/// without any configure the gate off entirely.
pub fn load(path: Option<&Path>) -> Vec<Pattern> {
    let Some(path) = path else {
        return Vec::new();
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines().filter_map(Pattern::from_line).collect()
}

/// True when the resolved caller is on the list. An empty list allows
/// nothing, but callers are expected to skip the check entirely in that case
/// (see `askpass.rs`); failing closed here is the safe fallback.
pub fn allows(patterns: &[Pattern], exe: &Path) -> bool {
    patterns.iter().any(|pattern| pattern.matches(exe))
}

/// Glob with `*` (any run of characters, including `/`) and `?` (one
/// character). Iterative, no recursion, `Pattern` never sees NULs.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut star_ti) = (None, 0usize);

    while ti < t.len() {
        if pi < p.len() && (p[pi] == t[ti] || p[pi] == '?') {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(sp) = star {
            // Back up to the last star and let it swallow one more character.
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    // Trailing stars match nothing.
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn p(entry: &str) -> Pattern {
        Pattern(entry.to_string())
    }

    #[test]
    fn glob_star_spans_slashes() {
        let m = |pat: &str, text: &str| glob_match(pat, text);
        assert!(m("*/bin/firefox", "/nix/store/abc-firefox/bin/firefox"));
        assert!(m(
            "/nix/store/*firefox*/bin/firefox",
            "/nix/store/abc-firefox-121/bin/firefox"
        ));
        assert!(m("*", "/anything/at/all"));
        assert!(m("firefox*", "firefox-esr"));
        assert!(!m("firefox", "firefox-esr"));
        assert!(!m(
            "*/bin/firefox",
            "/nix/store/abc-firefox/bin/firefox-esr"
        ));
    }

    #[test]
    fn glob_question_matches_one_character() {
        assert!(glob_match("firefox-??8", "firefox-118"));
        assert!(glob_match("firefox-?8", "firefox-18"));
        assert!(!glob_match("firefox-?8", "firefox-118"));
        assert!(!glob_match("firefox-?8", "firefox-118x"));
    }

    #[test]
    fn glob_does_not_treat_any_character_specially() {
        assert!(glob_match("[", "["));
        assert!(glob_match("a.b", "a.b"));
        assert!(!glob_match("a.b", "axb"));
    }

    #[test]
    fn entry_without_a_slash_matches_the_executable_name() {
        let exe = PathBuf::from("/nix/store/abc-firefox/bin/firefox");
        assert!(p("firefox").matches(&exe));
        assert!(p("firefox*").matches(&exe));
        assert!(!p("chromium").matches(&exe));
    }

    #[test]
    fn entry_with_a_slash_matches_the_full_path() {
        let exe = PathBuf::from("/nix/store/abc-firefox/bin/firefox");
        assert!(p("/nix/store/abc-firefox/bin/firefox").matches(&exe));
        assert!(p("*/bin/firefox").matches(&exe));
        assert!(!p("/nix/store/def-chromium/bin/chromium").matches(&exe));
    }

    #[test]
    fn lines_keep_only_the_meaningful_part() {
        assert_eq!(Pattern::from_line("  firefox  "), Some(p("firefox")));
        assert_eq!(
            Pattern::from_line("firefox # the browser"),
            Some(p("firefox"))
        );
        assert_eq!(Pattern::from_line(""), None);
        assert_eq!(Pattern::from_line("   "), None);
        assert_eq!(Pattern::from_line("# comment"), None);
    }

    #[test]
    fn load_skips_blank_lines_and_comments() {
        let dir = std::env::temp_dir().join(format!("dank-allowlist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("allowlist.txt");
        std::fs::write(&path, "firefox\n# browser\n\n  ssh  \n").unwrap();
        let patterns = load(Some(&path));
        assert_eq!(patterns, vec![p("firefox"), p("ssh")]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_missing_file_yields_no_entries() {
        assert!(load(Some(Path::new("/nonexistent/allowlist"))).is_empty());
        assert!(load(None).is_empty());
    }

    #[test]
    fn allows_is_an_or() {
        let patterns = vec![p("firefox"), p("*/bin/gpg-agent")];
        assert!(allows(&patterns, Path::new("/usr/bin/firefox")));
        assert!(allows(&patterns, Path::new("/nix/store/abc/bin/gpg-agent")));
        assert!(!allows(&patterns, Path::new("/usr/bin/ssh")));
        assert!(!allows(&[], Path::new("/usr/bin/ssh")));
    }
}
