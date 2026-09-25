//! `SmbPath` — validated, normalized SMB path used between dispatcher and
//! backend.
//!
//! Construction is exclusively from a `&[u16]` (UTF-16LE-decoded) buffer, per
//! spec §7. The protocol layer turns wire bytes into `&[u16]`; this module
//! turns `&[u16]` into a path that backends can blindly trust.

use std::str::FromStr;

use crate::error::{SmbError, SmbResult};

/// A validated, component-list path, plus an optional named-stream
/// selector on the final component (MS-FSCC §2.1.5 "Alternate Data
/// Streams"). No `..`, no Windows-forbidden chars outside the stream
/// selector. Always relative to the share root — the empty path is the
/// root.
///
/// `components` identifies the underlying file exactly as if the stream
/// selector weren't present — routing, authorization, and directory
/// containment all operate on the file identity, not the stream. Only
/// `ShareBackend::open` needs to look at `stream`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SmbPath {
    components: Vec<String>,
    stream: Option<String>,
}

impl SmbPath {
    /// The share root.
    pub fn root() -> Self {
        Self::default()
    }

    /// Construct from a UTF-16 code-unit slice (already decoded from UTF-16LE
    /// wire bytes).
    pub fn from_utf16(units: &[u16]) -> SmbResult<Self> {
        // 1. Convert to UTF-8 lossily — but reject if conversion produced any
        //    replacement characters that didn't exist in the input. We test
        //    the round-trip: invalid surrogates are rejected.
        let s = decode_utf16_strict(units)?;
        s.parse()
    }

    /// Named stream on the final component, if any (e.g. `"AFP_AfpInfo"` for
    /// `file.txt:AFP_AfpInfo`, or `file.txt:AFP_AfpInfo:$DATA`). `None` for
    /// the file's own primary data stream — including the explicit
    /// `file.txt::$DATA` form, which MS-SMB2 treats as equivalent to no
    /// stream at all.
    pub fn stream_name(&self) -> Option<&str> {
        self.stream.as_deref()
    }

    fn parse_components(s: &str) -> SmbResult<Self> {
        // Strip a leading separator (clients sometimes prefix `\` or `/`).
        let trimmed = s
            .strip_prefix('\\')
            .or_else(|| s.strip_prefix('/'))
            .unwrap_or(s);
        if trimmed.is_empty() {
            return Ok(Self::root());
        }

        // 2. Reject forbidden characters anywhere in the path. `:` is
        //    handled separately below (allowed only in the final
        //    component, as a stream selector).
        for ch in trimmed.chars() {
            if ch == '\0' || ('\u{0001}'..='\u{001F}').contains(&ch) {
                return Err(SmbError::NameInvalid);
            }
            match ch {
                '<' | '>' | '"' | '|' | '?' | '*' => return Err(SmbError::NameInvalid),
                _ => {}
            }
        }

        // 3. Split on `\` or `/`; reject `..` and empty components; skip `.`.
        let mut components = Vec::new();
        let mut raw_parts: Vec<&str> = trimmed.split(['\\', '/']).collect();
        let last = raw_parts.pop().ok_or(SmbError::NameInvalid)?;

        // A `:` may only appear in the final path component (the stream
        // selector). Any earlier component containing one names a stream on
        // a directory, which v1 doesn't support.
        for raw in &raw_parts {
            if raw.contains(':') {
                return Err(SmbError::NameInvalid);
            }
        }

        let (last_name, stream) = split_stream_selector(last)?;

        for raw in raw_parts {
            if raw.is_empty() {
                // Doubled separator like `foo\\bar` — reject.
                return Err(SmbError::NameInvalid);
            }
            if raw == "." {
                continue;
            }
            if raw == ".." {
                return Err(SmbError::NameInvalid);
            }
            // 4. Reject reserved DOS device names.
            if is_reserved_dos_name(raw) {
                return Err(SmbError::NameInvalid);
            }
            components.push(raw.to_string());
        }

        if last_name.is_empty() {
            // Doubled separator, or a bare `:stream` with no file name —
            // both reject; a stream needs a named host file.
            return Err(SmbError::NameInvalid);
        }
        if last_name == "." {
            if stream.is_some() {
                return Err(SmbError::NameInvalid);
            }
            // `.` alone (with no preceding components) is the root.
        } else {
            if last_name == ".." {
                return Err(SmbError::NameInvalid);
            }
            if is_reserved_dos_name(last_name) {
                return Err(SmbError::NameInvalid);
            }
            components.push(last_name.to_string());
        }

        Ok(Self { components, stream })
    }

    /// Path components in order. Empty for the root.
    pub fn components(&self) -> &[String] {
        &self.components
    }

    /// Is this the share root?
    pub fn is_root(&self) -> bool {
        self.components.is_empty()
    }

    /// Return the parent path, or `None` if this is the root.
    pub fn parent(&self) -> Option<SmbPath> {
        if self.is_root() {
            return None;
        }
        let mut parent = self.components.clone();
        parent.pop();
        Some(SmbPath {
            components: parent,
            stream: None,
        })
    }

    /// Return the last component, if any.
    pub fn file_name(&self) -> Option<&str> {
        self.components.last().map(|s| s.as_str())
    }

    /// Append a single, already-validated last component to this path.
    pub fn join(&self, last: &str) -> SmbResult<SmbPath> {
        // Run `last` through the same validator (treating it as a single-
        // component path); its stream selector, if any, becomes this path's.
        let extra = last.parse::<SmbPath>()?;
        let mut out = self.clone();
        out.components.extend(extra.components);
        out.stream = extra.stream;
        Ok(out)
    }

    /// Render as a backslash-separated string. Empty for root.
    pub fn display_backslash(&self) -> String {
        self.components.join("\\")
    }
}

impl FromStr for SmbPath {
    type Err = SmbError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_components(s)
    }
}

impl std::fmt::Display for SmbPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_root() {
            f.write_str("\\")
        } else {
            f.write_str(&self.display_backslash())
        }
    }
}

/// Split a final path component into its file name and an optional stream
/// selector (MS-FSCC §2.1.5): `name[:stream[:type]]`. `type`, if present,
/// must be `$DATA` (case-insensitive) — v1 doesn't support other stream
/// types (e.g. `$INDEX_ALLOCATION`). An empty stream name paired with an
/// absent or `$DATA` type (`name::$DATA`, or a bare trailing `name:`) means
/// "the primary data stream", i.e. no stream at all. A stream named `.` or
/// `..` is rejected here: a backend that stores streams as files would
/// otherwise see a relative component in the stream name.
fn split_stream_selector(last: &str) -> SmbResult<(&str, Option<String>)> {
    let Some((name, rest)) = last.split_once(':') else {
        return Ok((last, None));
    };
    let (stream, ty) = match rest.split_once(':') {
        Some((stream, ty)) => (stream, Some(ty)),
        None => (rest, None),
    };
    if let Some(ty) = ty
        && !ty.eq_ignore_ascii_case("$DATA")
    {
        return Err(SmbError::NameInvalid);
    }
    if stream == "." || stream == ".." {
        return Err(SmbError::NameInvalid);
    }
    if stream.is_empty() {
        Ok((name, None))
    } else {
        Ok((name, Some(stream.to_string())))
    }
}

fn is_reserved_dos_name(s: &str) -> bool {
    // Strip extension before checking, e.g. "CON.txt" is also reserved.
    let stem = match s.rsplit_once('.') {
        Some((stem, _)) => stem,
        None => s,
    };
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL") || matches_com_or_lpt(&upper)
}

fn matches_com_or_lpt(s: &str) -> bool {
    if s.len() != 4 {
        return false;
    }
    let bytes = s.as_bytes();
    let prefix = &bytes[..3];
    let last = bytes[3] as char;
    if !matches!(last, '1'..='9') {
        return false;
    }
    prefix == b"COM" || prefix == b"LPT"
}

fn decode_utf16_strict(units: &[u16]) -> SmbResult<String> {
    // Reject unpaired surrogates explicitly. `String::from_utf16` does this
    // already; we surface its error as NameInvalid.
    String::from_utf16(units).map_err(|_| SmbError::NameInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn root_paths() {
        assert!("".parse::<SmbPath>().unwrap().is_root());
        assert!("\\".parse::<SmbPath>().unwrap().is_root());
        assert!("/".parse::<SmbPath>().unwrap().is_root());
        assert!(SmbPath::from_utf16(&utf16("")).unwrap().is_root());
    }

    #[test]
    fn simple_paths_split() {
        let p = "dir\\sub\\file.txt".parse::<SmbPath>().unwrap();
        assert_eq!(p.components(), &["dir", "sub", "file.txt"]);
        assert_eq!(p.display_backslash(), "dir\\sub\\file.txt");
        assert!(!p.is_root());
        assert_eq!(p.file_name(), Some("file.txt"));
    }

    #[test]
    fn forward_slash_accepted() {
        let p = "a/b/c".parse::<SmbPath>().unwrap();
        assert_eq!(p.components(), &["a", "b", "c"]);
    }

    #[test]
    fn dot_components_skipped() {
        let p = "a\\.\\b".parse::<SmbPath>().unwrap();
        assert_eq!(p.components(), &["a", "b"]);
    }

    #[test]
    fn parent_returns_one_component_less() {
        let p = "a\\b\\c".parse::<SmbPath>().unwrap();
        let parent = p.parent().unwrap();
        assert_eq!(parent.components(), &["a", "b"]);
        let grand = parent.parent().unwrap();
        assert_eq!(grand.components(), &["a"]);
        let root = grand.parent().unwrap();
        assert!(root.is_root());
        assert!(root.parent().is_none());
    }

    #[test]
    fn join_appends_component() {
        let p = "a".parse::<SmbPath>().unwrap();
        let q = p.join("b").unwrap();
        assert_eq!(q.components(), &["a", "b"]);
    }

    #[test]
    fn rejects_double_dot() {
        assert!("a\\..\\b".parse::<SmbPath>().is_err());
        assert!("..".parse::<SmbPath>().is_err());
    }

    #[test]
    fn rejects_double_separator() {
        assert!("a\\\\b".parse::<SmbPath>().is_err());
    }

    #[test]
    fn rejects_forbidden_chars() {
        // `:` is deliberately absent here — it's the stream selector, see
        // the `stream_selector_*` tests below.
        for bad in ["a<b", "a>b", "a\"b", "a|b", "a?b", "a*b"] {
            assert!(bad.parse::<SmbPath>().is_err(), "{bad}");
        }
    }

    #[test]
    fn stream_selector_parses_off_the_final_component() {
        let p = "file.txt:AFP_AfpInfo".parse::<SmbPath>().unwrap();
        assert_eq!(p.components(), &["file.txt"]);
        assert_eq!(p.stream_name(), Some("AFP_AfpInfo"));
    }

    #[test]
    fn stream_selector_works_under_a_directory() {
        let p = "dir\\file.txt:com.apple.ResourceFork"
            .parse::<SmbPath>()
            .unwrap();
        assert_eq!(p.components(), &["dir", "file.txt"]);
        assert_eq!(p.stream_name(), Some("com.apple.ResourceFork"));
    }

    #[test]
    fn stream_selector_accepts_explicit_data_type_suffix() {
        let p = "file.txt:AFP_AfpInfo:$DATA".parse::<SmbPath>().unwrap();
        assert_eq!(p.components(), &["file.txt"]);
        assert_eq!(p.stream_name(), Some("AFP_AfpInfo"));
    }

    #[test]
    fn stream_selector_type_suffix_is_case_insensitive() {
        let p = "file.txt:AFP_AfpInfo:$data".parse::<SmbPath>().unwrap();
        assert_eq!(p.stream_name(), Some("AFP_AfpInfo"));
    }

    #[test]
    fn bare_data_type_suffix_means_no_stream() {
        // `file.txt::$DATA` explicitly names the primary data stream —
        // MS-SMB2 treats this as equivalent to no stream selector at all.
        let p = "file.txt::$DATA".parse::<SmbPath>().unwrap();
        assert_eq!(p.components(), &["file.txt"]);
        assert_eq!(p.stream_name(), None);
    }

    #[test]
    fn trailing_bare_colon_means_no_stream() {
        let p = "file.txt:".parse::<SmbPath>().unwrap();
        assert_eq!(p.components(), &["file.txt"]);
        assert_eq!(p.stream_name(), None);
    }

    #[test]
    fn rejects_unsupported_stream_type() {
        assert!(
            "file.txt:stream:$INDEX_ALLOCATION"
                .parse::<SmbPath>()
                .is_err()
        );
    }

    #[test]
    fn rejects_stream_selector_on_a_non_final_component() {
        assert!("dir:stream\\file.txt".parse::<SmbPath>().is_err());
    }

    #[test]
    fn rejects_dot_and_dot_dot_stream_names() {
        for p in [
            "file.txt:.",
            "file.txt:..",
            "file.txt:.:$DATA",
            "dir\\file.txt:..:$DATA",
        ] {
            assert!(
                matches!(p.parse::<SmbPath>(), Err(SmbError::NameInvalid)),
                "{p}"
            );
        }
        // A dot inside an ordinary stream name is not special.
        assert_eq!(
            "file.txt:com.apple.provenance"
                .parse::<SmbPath>()
                .unwrap()
                .stream_name(),
            Some("com.apple.provenance")
        );
    }

    #[test]
    fn rejects_bare_stream_with_no_file_name() {
        assert!(":stream".parse::<SmbPath>().is_err());
    }

    #[test]
    fn plain_paths_have_no_stream() {
        assert_eq!("file.txt".parse::<SmbPath>().unwrap().stream_name(), None);
        assert_eq!(SmbPath::root().stream_name(), None);
    }

    #[test]
    fn rejects_control_chars() {
        let s = format!("a{}b", '\u{0001}');
        assert!(s.parse::<SmbPath>().is_err());
        let s = format!("a{}b", '\u{0000}');
        assert!(s.parse::<SmbPath>().is_err());
    }

    #[test]
    fn rejects_reserved_dos_names() {
        for bad in [
            "CON", "con", "PRN", "AUX", "NUL", "COM1", "LPT9", "Con.txt", "NUL.dat",
        ] {
            assert!(bad.parse::<SmbPath>().is_err(), "{bad}");
        }
    }

    #[test]
    fn allows_lookalike_names() {
        // Not reserved.
        assert!("CON1".parse::<SmbPath>().is_ok());
        assert!("LPT".parse::<SmbPath>().is_ok());
        assert!("LPT0".parse::<SmbPath>().is_ok()); // 0 is not in the 1-9 range
        assert!("NUL_FILE.txt".parse::<SmbPath>().is_ok());
    }

    #[test]
    fn rejects_unpaired_surrogate() {
        let units: [u16; 2] = [0xD800, 0x0061]; // unpaired high surrogate
        assert!(SmbPath::from_utf16(&units).is_err());
    }

    #[test]
    fn round_trip_via_utf16() {
        let p = SmbPath::from_utf16(&utf16("a\\b")).unwrap();
        assert_eq!(p.components(), &["a", "b"]);
    }
}
