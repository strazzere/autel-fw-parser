mod display;
mod file_entry;
mod file_types;
mod parser;
mod processor;
mod zip_utils;

use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use processor::process_file;

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <input_file> [output_dir]", args[0]);
        std::process::exit(1);
    }

    let input_path = &args[1];
    let output_dir = args.get(2).map(|s| s.as_str());

    let mut file = File::open(input_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let input_filename = Path::new(input_path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("output");

    process_file(&buffer, Some(input_filename), output_dir, 0)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::file_types::{detect_file_type, FileType};
    use crate::parser::parse_file_entries;

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
    fn test_detect_and_parse_container() {
        let content = b"{\"test\": true}";
        let buffer = build_test_container("config.json", content);

        // Should detect as Autel container
        assert_eq!(detect_file_type(&buffer, None), FileType::AutelContainer);

        // Should parse correctly
        let entries = parse_file_entries(&buffer);
        assert_eq!(entries.len(), 1);

        // Extracted content should be detected as JSON
        assert_eq!(
            detect_file_type(entries[0].content, Some("config.json")),
            FileType::Json
        );
    }
}
