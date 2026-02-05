use std::collections::HashMap;

use crate::file_entry::FileEntry;

/// Print a hexdump preview of data with indentation
pub fn print_hexdump_preview_indented(data: &[u8], max_lines: usize, indent: &str) {
    let mut offset = 0;

    for chunk in data.chunks(16).take(max_lines) {
        print!("{}  {:08x}  ", indent, offset);
        for i in 0..16 {
            if i < chunk.len() {
                print!("{:02x} ", chunk[i]);
            } else {
                print!("   ");
            }

            if i == 7 {
                print!(" ");
            }
        }

        print!(" |");
        for &b in chunk {
            let c = if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            };
            print!("{}", c);
        }
        println!("|");

        offset += 16;
    }

    if data.len() > max_lines * 16 {
        println!(
            "{}  ... ({} more bytes)",
            indent,
            data.len() - max_lines * 16
        );
    }
}

/// Summarize the header and content metadata across entries
pub fn summarize_metadata(entries: &[FileEntry], indent: &str) {
    let mut pairs: HashMap<(String, String), Vec<String>> = HashMap::new();

    for entry in entries {
        let header = entry
            .header_data
            .map(|h| format!("{:02x?}", h))
            .unwrap_or("[none]".to_string());
        let content_meta = entry
            .content_meta
            .map(|m| format!("{:02x?}", m))
            .unwrap_or("[none]".to_string());

        let ext = entry
            .filename
            .as_ref()
            .and_then(|f| f.rsplit('.').next())
            .unwrap_or("<none>")
            .to_lowercase();

        pairs.entry((header, content_meta)).or_default().push(ext);
    }

    println!();
    println!("{}=== Header + Content Meta Summary ===", indent);
    for ((header, meta), exts) in pairs {
        let mut counts = HashMap::new();
        for ext in exts {
            *counts.entry(ext).or_insert(0) += 1;
        }
        let summary_str: Vec<_> = counts
            .iter()
            .map(|(k, v)| format!("{}.{}", v, k))
            .collect();
        println!("{}{} + {} → {}", indent, header, meta, summary_str.join(", "));
    }
}
