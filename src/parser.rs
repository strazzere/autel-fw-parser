use crate::file_entry::FileEntry;

/// Find a quoted tag in the buffer starting from the given position
/// Returns the position and the tag bytes (including quotes)
pub fn find_tag(buffer: &[u8], start: usize) -> Option<(usize, &'_ [u8])> {
    let len = buffer.len();
    let mut i = start;

    while i < len.saturating_sub(3) {
        if buffer[i] == b'"' && buffer[i + 1] == b'<' {
            for j in i + 2..len.saturating_sub(1) {
                if buffer[j] == b'>' && buffer.get(j + 1) == Some(&b'"') {
                    return Some((i, &buffer[i..=j + 1]));
                }
            }
            i += 2;
        } else {
            i += 1;
        }
    }

    None
}

/// Extract filename and header data from fileinfo section
pub fn extract_filename(info_data: &[u8]) -> (Option<String>, Option<&[u8; 4]>) {
    if info_data.len() < 8 {
        return (None, None);
    }

    let name_len =
        u32::from_be_bytes([info_data[0], info_data[1], info_data[2], info_data[3]]) as usize;
    let header_bytes = info_data.get(4..8).and_then(|b| b.try_into().ok());

    if info_data.len() < 8 + name_len {
        return (None, header_bytes);
    }

    let name_bytes = &info_data[8..8 + name_len];
    let filename = std::str::from_utf8(name_bytes)
        .ok()
        .map(|s| s.trim_matches('"').to_string());

    (filename, header_bytes)
}

/// Parse all file entries from an Autel container buffer
pub fn parse_file_entries(buffer: &[u8]) -> Vec<FileEntry<'_>> {
    let mut entries = Vec::new();
    let mut pos = 0;

    while pos < buffer.len() {
        let (start, tag_bytes) = match find_tag(buffer, pos) {
            Some(res) => res,
            None => break,
        };

        let tag_str = match std::str::from_utf8(tag_bytes) {
            Ok(s) => s.trim_matches('"'),
            Err(_) => {
                pos = start + 1;
                continue;
            }
        };

        if tag_str != "<filetransfer>" {
            pos = start + tag_bytes.len();
            continue;
        }

        let (info_start, info_tag_bytes) = match find_tag(buffer, start + tag_bytes.len()) {
            Some(res) => res,
            None => break,
        };
        let info_tag_str = std::str::from_utf8(info_tag_bytes)
            .unwrap_or("")
            .trim_matches('"');
        if info_tag_str != "<fileinfo>" {
            pos = info_start + info_tag_bytes.len();
            continue;
        }

        let info_data_start = info_start + info_tag_bytes.len();
        let next_tag_after_info = find_tag(buffer, info_data_start)
            .map(|(i, _)| i)
            .unwrap_or(buffer.len());
        let info_data = &buffer[info_data_start..next_tag_after_info];

        let (filename, header_data) = extract_filename(info_data);

        let (content_start, content_tag_bytes) = match find_tag(buffer, next_tag_after_info) {
            Some(res) => res,
            None => break,
        };
        let content_tag_str = std::str::from_utf8(content_tag_bytes)
            .unwrap_or("")
            .trim_matches('"');
        if content_tag_str != "<filecontent>" {
            pos = content_start + content_tag_bytes.len();
            continue;
        }

        let content_data_start = content_start + content_tag_bytes.len();

        // Read the declared content length first to properly skip over binary content
        // Format: 4 bytes (big-endian length) + 4 bytes (meta) + content
        let (content_length, content_meta, content, content_data, next_tag_after_content): (
            usize,
            Option<&[u8; 4]>,
            &[u8],
            &[u8],
            usize,
        ) = if buffer.len() >= content_data_start + 8 {
            let len = u32::from_be_bytes([
                buffer[content_data_start],
                buffer[content_data_start + 1],
                buffer[content_data_start + 2],
                buffer[content_data_start + 3],
            ]) as usize;
            let meta = buffer
                .get(content_data_start + 4..content_data_start + 8)
                .and_then(|b| b.try_into().ok());

            // Calculate where content should end based on declared length
            let content_end = content_data_start + 8 + len;
            let actual_content_end = content_end.min(buffer.len());

            let content = &buffer[content_data_start + 8..actual_content_end];
            let content_data = &buffer[content_data_start..actual_content_end];

            if actual_content_end < content_end {
                eprintln!(
                    "Warning: Declared content length ({}) exceeds available data ({})",
                    len,
                    buffer.len().saturating_sub(content_data_start + 8)
                );
            }

            (len, meta, content, content_data, actual_content_end)
        } else {
            (
                0,
                None,
                &[][..],
                &buffer[content_data_start..content_data_start.min(buffer.len())],
                content_data_start,
            )
        };

        entries.push(FileEntry {
            filename,
            header_data,
            content_length,
            content_meta,
            content,
            raw_content_data: content_data,
            content_data_offset: content_data_start,
        });

        pos = next_tag_after_content;
    }

    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_tag_basic() {
        let buffer = b"prefix\"<filetransfer>\"suffix";
        let result = find_tag(buffer, 0);
        assert!(result.is_some());
        let (pos, tag) = result.unwrap();
        assert_eq!(pos, 6);
        assert_eq!(tag, b"\"<filetransfer>\"");
    }

    #[test]
    fn test_find_tag_at_start() {
        let buffer = b"\"<test>\"rest of data";
        let result = find_tag(buffer, 0);
        assert!(result.is_some());
        let (pos, tag) = result.unwrap();
        assert_eq!(pos, 0);
        assert_eq!(tag, b"\"<test>\"");
    }

    #[test]
    fn test_find_tag_with_offset() {
        let buffer = b"\"<first>\"some data\"<second>\"more";
        let result = find_tag(buffer, 9);
        assert!(result.is_some());
        let (pos, tag) = result.unwrap();
        assert_eq!(pos, 18);
        assert_eq!(tag, b"\"<second>\"");
    }

    #[test]
    fn test_find_tag_not_found() {
        let buffer = b"no tags in this buffer";
        let result = find_tag(buffer, 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_find_tag_incomplete() {
        let buffer = b"\"<incomplete";
        let result = find_tag(buffer, 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_find_tag_empty_buffer() {
        let buffer: &[u8] = b"";
        let result = find_tag(buffer, 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_find_tag_nested_quotes() {
        let buffer = b"\"<outer>\"\"<inner>\"";
        let result = find_tag(buffer, 0);
        assert!(result.is_some());
        let (pos, tag) = result.unwrap();
        assert_eq!(pos, 0);
        assert_eq!(tag, b"\"<outer>\"");
    }

    #[test]
    fn test_extract_filename_basic() {
        // Format: 4 bytes name length (big-endian) + 4 bytes header + name
        let mut data = vec![
            0x00, 0x00, 0x00, 0x0a, // length = 10
            0xfd, 0xce, 0x69, 0x48, // header bytes
        ];
        data.extend_from_slice(b"test.json\x00");

        let (filename, header) = extract_filename(&data);
        assert_eq!(filename, Some("test.json\x00".to_string()));
        assert_eq!(header, Some(&[0xfd, 0xce, 0x69, 0x48]));
    }

    #[test]
    fn test_extract_filename_strips_quotes() {
        let mut data = vec![
            0x00, 0x00, 0x00, 0x0b, // length = 11 (for "test.json" with quotes)
            0x01, 0x02, 0x03, 0x04, // header bytes
        ];
        data.extend_from_slice(b"\"test.json\"");

        let (filename, _) = extract_filename(&data);
        assert_eq!(filename, Some("test.json".to_string()));
    }

    #[test]
    fn test_extract_filename_too_short() {
        let data = vec![0x00, 0x00, 0x00, 0x05]; // only 4 bytes
        let (filename, header) = extract_filename(&data);
        assert!(filename.is_none());
        assert!(header.is_none());
    }

    #[test]
    fn test_extract_filename_incomplete_name() {
        let data = vec![
            0x00, 0x00, 0x00, 0x20, // length = 32 (but we won't provide that many)
            0x01, 0x02, 0x03, 0x04, // header bytes
            b't', b'e', b's', b't', // only 4 chars
        ];

        let (filename, header) = extract_filename(&data);
        assert!(filename.is_none());
        assert_eq!(header, Some(&[0x01, 0x02, 0x03, 0x04]));
    }

    #[test]
    fn test_extract_filename_zero_length() {
        let data = vec![
            0x00, 0x00, 0x00, 0x00, // length = 0
            0xaa, 0xbb, 0xcc, 0xdd, // header bytes
        ];

        let (filename, header) = extract_filename(&data);
        assert_eq!(filename, Some("".to_string()));
        assert_eq!(header, Some(&[0xaa, 0xbb, 0xcc, 0xdd]));
    }

    fn build_test_container(filename: &str, content: &[u8]) -> Vec<u8> {
        let mut buffer = Vec::new();

        // "<filetransfer>" tag
        buffer.extend_from_slice(b"\"<filetransfer>\"");

        // "<fileinfo>" tag
        buffer.extend_from_slice(b"\"<fileinfo>\"");

        // File info: 4 bytes name length + 4 bytes header + name
        let name_bytes = filename.as_bytes();
        buffer.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
        buffer.extend_from_slice(&[0xfd, 0xce, 0x69, 0x48]); // header data
        buffer.extend_from_slice(name_bytes);

        // "<filecontent>" tag
        buffer.extend_from_slice(b"\"<filecontent>\"");

        // Content: 4 bytes length + 4 bytes meta + content
        buffer.extend_from_slice(&(content.len() as u32).to_be_bytes());
        buffer.extend_from_slice(&[0x33, 0xa8, 0x3b, 0x1f]); // content meta
        buffer.extend_from_slice(content);

        buffer
    }

    #[test]
    fn test_parse_single_entry() {
        let content = b"test content data";
        let buffer = build_test_container("test.txt", content);

        let entries = parse_file_entries(&buffer);
        assert_eq!(entries.len(), 1);

        let entry = &entries[0];
        assert_eq!(entry.filename, Some("test.txt".to_string()));
        assert_eq!(entry.content, content);
        assert_eq!(entry.header_data, Some(&[0xfd, 0xce, 0x69, 0x48]));
        assert_eq!(entry.content_meta, Some(&[0x33, 0xa8, 0x3b, 0x1f]));
    }

    #[test]
    fn test_parse_multiple_entries() {
        let mut buffer = build_test_container("file1.txt", b"content one");
        buffer.extend_from_slice(&build_test_container(
            "file2.json",
            b"{\"key\":\"value\"}",
        ));
        buffer.extend_from_slice(&build_test_container("file3.bin", &[0xde, 0xad, 0xbe, 0xef]));

        let entries = parse_file_entries(&buffer);
        assert_eq!(entries.len(), 3);

        assert_eq!(entries[0].filename, Some("file1.txt".to_string()));
        assert_eq!(entries[1].filename, Some("file2.json".to_string()));
        assert_eq!(entries[2].filename, Some("file3.bin".to_string()));
    }

    #[test]
    fn test_parse_empty_content() {
        let buffer = build_test_container("empty.txt", b"");

        let entries = parse_file_entries(&buffer);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].content.len(), 0);
    }

    #[test]
    fn test_parse_no_entries() {
        let buffer = b"random data without any tags";
        let entries = parse_file_entries(buffer);
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_parse_with_prefix_data() {
        let mut buffer = vec![0u8; 100]; // Padding before container
        buffer.extend_from_slice(&build_test_container("test.txt", b"content"));

        let entries = parse_file_entries(&buffer);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename, Some("test.txt".to_string()));
    }

    #[test]
    fn test_parse_large_content() {
        let large_content = vec![0xABu8; 10000];
        let buffer = build_test_container("large.bin", &large_content);

        let entries = parse_file_entries(&buffer);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].content.len(), 10000);
        assert!(entries[0].content.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn test_parse_binary_content_with_tag_like_bytes() {
        // Content that looks like it might contain tags
        let tricky_content = b"data with \"<fake>\" tag inside";
        let buffer = build_test_container("tricky.bin", tricky_content);

        let entries = parse_file_entries(&buffer);
        assert_eq!(entries.len(), 1);
        // The content should be read by length, not by searching for tags
        assert_eq!(entries[0].content, tricky_content);
    }
}
