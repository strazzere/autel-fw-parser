/// Slice the data to include only up to the end of the ZIP's EOCD record
/// Returns None if no valid EOCD marker is found
pub fn slice_to_eocd(data: &[u8]) -> Option<&[u8]> {
    for i in (0..=data.len().saturating_sub(22)).rev() {
        if data.len() >= i + 4 && &data[i..i + 4] == b"PK\x05\x06" && data.len() >= i + 22 {
            let comment_len = u16::from_le_bytes([data[i + 20], data[i + 21]]) as usize;
            let end = i + 22 + comment_len;
            if end <= data.len() {
                return Some(&data[..end]);
            } else {
                return Some(data);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slice_to_eocd_basic() {
        // Minimal EOCD: PK\x05\x06 + 18 bytes + 2 bytes comment length (0)
        let mut data = vec![b'P', b'K', 0x03, 0x04]; // Local file header
        data.extend_from_slice(&[0u8; 100]); // Some content
        data.extend_from_slice(b"PK\x05\x06"); // EOCD signature
        data.extend_from_slice(&[0u8; 18]); // EOCD fields
        data.extend_from_slice(&[0x00, 0x00]); // Comment length = 0

        let result = slice_to_eocd(&data);
        assert!(result.is_some());
        let slice = result.unwrap();
        // EOCD is at position 104, so slice should be 104 + 22 = 126 bytes
        let eocd_pos = 4 + 100; // local header + content
        let expected_len = eocd_pos + 22; // EOCD is 22 bytes with no comment
        assert_eq!(slice.len(), expected_len);
    }

    #[test]
    fn test_slice_to_eocd_with_comment() {
        let mut data = vec![b'P', b'K', 0x03, 0x04];
        data.extend_from_slice(&[0u8; 50]);
        data.extend_from_slice(b"PK\x05\x06"); // EOCD signature (4 bytes)
        data.extend_from_slice(&[0u8; 16]); // EOCD fields before comment length (16 bytes)
        data.extend_from_slice(&[0x05, 0x00]); // Comment length = 5 (2 bytes) - part of 22-byte EOCD
        data.extend_from_slice(b"hello"); // Comment (5 bytes)

        let result = slice_to_eocd(&data);
        assert!(result.is_some());
        let slice = result.unwrap();
        // EOCD is at position 54 (4 + 50), with 22 bytes header + 5 byte comment
        let eocd_pos = 4 + 50;
        let expected_len = eocd_pos + 22 + 5; // EOCD (22 bytes) + comment (5 bytes)
        assert_eq!(slice.len(), expected_len);
    }

    #[test]
    fn test_slice_to_eocd_not_found() {
        let data = b"This is not a ZIP file at all";
        let result = slice_to_eocd(data);
        assert!(result.is_none());
    }

    #[test]
    fn test_slice_to_eocd_too_short() {
        let data = b"PK\x05\x06short"; // Less than 22 bytes after signature
        let result = slice_to_eocd(data);
        assert!(result.is_none());
    }

    #[test]
    fn test_slice_to_eocd_multiple_markers() {
        // Should find the last EOCD marker
        let mut data = vec![];
        data.extend_from_slice(b"PK\x05\x06"); // First (fake) EOCD
        data.extend_from_slice(&[0u8; 18]);
        data.extend_from_slice(&[0x00, 0x00]);
        data.extend_from_slice(&[0u8; 50]); // Padding
        data.extend_from_slice(b"PK\x05\x06"); // Second (real) EOCD
        data.extend_from_slice(&[0u8; 18]);
        data.extend_from_slice(&[0x00, 0x00]);

        let result = slice_to_eocd(&data);
        assert!(result.is_some());
    }
}
