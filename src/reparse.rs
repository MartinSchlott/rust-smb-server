//! `IO_REPARSE_TAG_SYMLINK` reparse-point encoding and decoding
//! (MS-FSCC §2.1.2.1).
//!
//! A symlink presented to an SMB client is a reparse point: the directory
//! entry carries `FILE_ATTRIBUTE_REPARSE_POINT` and the tag in its `EaSize`
//! field, and `FSCTL_GET_REPARSE_POINT` returns the `SYMLINK_REPARSE_BUFFER`
//! below. The buffer's two name fields are UTF-16LE with `\` separators; this
//! module is the single `/`↔`\` conversion point, taking and returning POSIX
//! form (`/`) to match the rest of the crate's path handling.

use crate::error::{SmbError, SmbResult};

/// `IO_REPARSE_TAG_SYMLINK` — the only tag this module encodes or accepts.
pub const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;

/// `SYMLINK_FLAG_RELATIVE` — set when the target is relative.
pub const SYMLINK_FLAG_RELATIVE: u32 = 0x0000_0001;

/// Fixed size, in bytes, of the `SYMLINK_REPARSE_BUFFER` header plus the four
/// name-offset/length fields and `Flags` — everything before `PathBuffer`.
const SYMLINK_REPARSE_FIXED: usize = 8 + 12;

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn invalid_data() -> SmbError {
    SmbError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "malformed symlink reparse buffer",
    ))
}

/// Encodes `target` (POSIX form) as an `IO_REPARSE_TAG_SYMLINK` reparse
/// buffer. `SubstituteName` and `PrintName` are identical; the length fields
/// are in bytes and the print name follows the substitute name.
pub fn encode_symlink_reparse(target: &str) -> Vec<u8> {
    let wire = target.replace('/', "\\");
    let name = utf16le(&wire);
    let name_len = name.len() as u16;
    let flags = if target.starts_with('/') {
        0
    } else {
        SYMLINK_FLAG_RELATIVE
    };
    // SubstituteName (name_len) + PrintName (name_len).
    let reparse_data_length = 12 + 2 * name_len;

    let mut out = Vec::with_capacity(SYMLINK_REPARSE_FIXED + name.len() * 2);
    out.extend_from_slice(&IO_REPARSE_TAG_SYMLINK.to_le_bytes());
    out.extend_from_slice(&reparse_data_length.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    out.extend_from_slice(&0u16.to_le_bytes()); // SubstituteNameOffset
    out.extend_from_slice(&name_len.to_le_bytes()); // SubstituteNameLength
    out.extend_from_slice(&name_len.to_le_bytes()); // PrintNameOffset
    out.extend_from_slice(&name_len.to_le_bytes()); // PrintNameLength
    out.extend_from_slice(&flags.to_le_bytes()); // Flags
    out.extend_from_slice(&name); // SubstituteName
    out.extend_from_slice(&name); // PrintName
    out
}

/// Decodes a `SYMLINK_REPARSE_BUFFER`, returning the `SubstituteName` in POSIX
/// form (`/` separators).
///
/// Rejects a wrong tag, a truncated or internally out-of-range buffer, an
/// odd-length name, invalid UTF-16, and a `SubstituteName` starting with the
/// NT namespace prefix `\??\` — no macOS client sends that form, and passing
/// it through would name a path the host cannot resolve.
pub fn decode_symlink_reparse(buf: &[u8]) -> SmbResult<String> {
    if buf.len() < SYMLINK_REPARSE_FIXED {
        return Err(invalid_data());
    }
    let tag = u32::from_le_bytes(buf[0..4].try_into().expect("4 bytes"));
    if tag != IO_REPARSE_TAG_SYMLINK {
        return Err(invalid_data());
    }
    let data_len = u16::from_le_bytes(buf[4..6].try_into().expect("2 bytes")) as usize;
    // `ReparseDataLength` covers the offset/length fields and `Flags` (12
    // bytes) plus the path buffer. The declared region must fit the input.
    if data_len < 12 || buf.len() < SYMLINK_REPARSE_FIXED + (data_len - 12) {
        return Err(invalid_data());
    }
    let data = &buf[8..8 + data_len];
    let sub_off = u16::from_le_bytes(data[0..2].try_into().expect("2 bytes")) as usize;
    let sub_len = u16::from_le_bytes(data[2..4].try_into().expect("2 bytes")) as usize;
    // The path buffer starts after the 12 fixed data bytes; the substitute
    // name must lie wholly inside it and be a whole number of UTF-16 units.
    let path_len = data_len - 12;
    if sub_off + sub_len > path_len || !sub_len.is_multiple_of(2) {
        return Err(invalid_data());
    }
    let start = 12 + sub_off;
    let name_bytes = &data[start..start + sub_len];
    let units: Vec<u16> = name_bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let wire = String::from_utf16(&units).map_err(|_| invalid_data())?;
    if wire.starts_with("\\??\\") {
        return Err(invalid_data());
    }
    Ok(wire.replace('\\', "/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_relative_target() {
        let encoded = encode_symlink_reparse("../pkg/bin/cli.js");
        assert_eq!(
            decode_symlink_reparse(&encoded).unwrap(),
            "../pkg/bin/cli.js"
        );
    }

    #[test]
    fn round_trips_an_absolute_target() {
        let encoded = encode_symlink_reparse("/etc/hosts");
        assert_eq!(decode_symlink_reparse(&encoded).unwrap(), "/etc/hosts");
    }

    #[test]
    fn round_trips_a_non_ascii_target() {
        let target = "../päckchen/übersicht.js";
        let encoded = encode_symlink_reparse(target);
        assert_eq!(decode_symlink_reparse(&encoded).unwrap(), target);
    }

    #[test]
    fn absolute_target_clears_the_relative_flag() {
        let rel = encode_symlink_reparse("../a");
        let abs = encode_symlink_reparse("/a");
        // Flags follows the four offset/length fields: 8 header + 12 = 16.
        let flags = |b: &[u8]| u32::from_le_bytes(b[16..20].try_into().unwrap());
        assert_eq!(flags(&rel), SYMLINK_FLAG_RELATIVE);
        assert_eq!(flags(&abs), 0);
    }

    /// The exact buffer the macOS client sent in the spike's Run 2 for
    /// `ln -s ../pkg/bin/cli.js` (RESULTS document): tag `0xA000000C`,
    /// `ReparseDataLength = 0x50`, SubstituteName at offset 0 and PrintName
    /// at `0x22`, each `0x22` bytes, `Flags = 1`.
    #[test]
    fn matches_the_spikes_measured_ln_s_input() {
        let expected: Vec<u8> = {
            let name: Vec<u8> = "..\\pkg\\bin\\cli.js"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect();
            assert_eq!(name.len(), 0x22);
            let mut b = Vec::new();
            b.extend_from_slice(&0xA000_000Cu32.to_le_bytes());
            b.extend_from_slice(&0x50u16.to_le_bytes());
            b.extend_from_slice(&0u16.to_le_bytes());
            b.extend_from_slice(&0u16.to_le_bytes()); // SubstituteNameOffset
            b.extend_from_slice(&0x22u16.to_le_bytes()); // SubstituteNameLength
            b.extend_from_slice(&0x22u16.to_le_bytes()); // PrintNameOffset
            b.extend_from_slice(&0x22u16.to_le_bytes()); // PrintNameLength
            b.extend_from_slice(&1u32.to_le_bytes()); // Flags
            b.extend_from_slice(&name);
            b.extend_from_slice(&name);
            b
        };
        assert_eq!(
            encode_symlink_reparse("../pkg/bin/cli.js"),
            expected,
            "the encoder must reproduce the client's own buffer byte for byte"
        );
        assert_eq!(
            decode_symlink_reparse(&expected).unwrap(),
            "../pkg/bin/cli.js"
        );
    }

    #[test]
    fn rejects_a_wrong_tag() {
        let mut encoded = encode_symlink_reparse("../a");
        encoded[0..4].copy_from_slice(&0xA000_0003u32.to_le_bytes());
        assert!(decode_symlink_reparse(&encoded).is_err());
    }

    #[test]
    fn rejects_a_truncated_buffer() {
        let encoded = encode_symlink_reparse("../a");
        assert!(decode_symlink_reparse(&encoded[..encoded.len() - 1]).is_err());
    }

    #[test]
    fn rejects_an_out_of_range_substitute_name() {
        let mut encoded = encode_symlink_reparse("../a");
        // SubstituteNameLength beyond the path buffer.
        encoded[10..12].copy_from_slice(&0xFFFFu16.to_le_bytes());
        assert!(decode_symlink_reparse(&encoded).is_err());
    }

    #[test]
    fn rejects_the_nt_namespace_prefix() {
        let encoded = encode_symlink_reparse("\\??\\C:\\target");
        assert!(decode_symlink_reparse(&encoded).is_err());
    }
}
