// ../evo/EVO_FW_V1.5.8.bin
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use zip::read::ZipArchive;
use std::io::Cursor;
use std::path::Path;
use std::env;

#[derive(Debug)]
struct FileEntry<'a> {
    filename: Option<String>,
    header_data: Option<&'a [u8; 4]>,
    content_length: usize,
    content_meta: Option<&'a [u8; 4]>,
    content: &'a [u8],
    raw_content_data: &'a [u8],
    content_data_offset: usize,
}

fn main() -> io::Result<()> {
  let args: Vec<String> = env::args().collect();
  if args.len() < 2 {
      eprintln!("Usage: {} <input_file> [output_dir]", args[0]);
      std::process::exit(1);
  }

  let input_path = &args[1];
  let output_dir = args.get(2);
  let mut file = File::open(input_path)?;
  let mut buffer = Vec::new();
  file.read_to_end(&mut buffer)?;

  let entries = parse_file_entries(&buffer);

  if let Some(out_dir) = output_dir {
      fs::create_dir_all(out_dir)?;
  }

  for (i, entry) in entries.iter().enumerate() {
      println!("=== File Entry {} ===", i + 1);
      println!("Filename: {}", entry.filename.as_deref().unwrap_or("<unknown>"));
      if let Some(header_data) = entry.header_data {
          println!("Header data: {:02x?}", header_data);
      }
      if let Some(content_meta) = entry.content_meta {
          println!("Content meta: {:02x?}", content_meta);
      }
      println!("Declared size: {}", entry.content_length);
      println!("Actual content bytes: {}", entry.content.len());

      if let Some(filename) = &entry.filename {
          if let Some(out_dir) = output_dir {
              // Write raw file content to output directory
              let output_path = Path::new(out_dir).join(filename);
              if let Some(parent) = output_path.parent() {
                  fs::create_dir_all(parent)?;
              }
              let mut out_file = File::create(&output_path)?;
              out_file.write_all(entry.content)?;
          }

          if entry.content.len() >= 12 && &entry.raw_content_data[8..12] == b"PK\x03\x04" {
              let zip_abs_start = entry.content_data_offset + 8;
              let zip_abs_end = zip_abs_start + entry.content_length;
              if buffer.len() >= zip_abs_end {
                  let full_zip_slice = &buffer[zip_abs_start..zip_abs_end];
                  println!("Scanning for EOCD in declared range: {} bytes", full_zip_slice.len());
                  if let Some(zip_slice) = slice_to_eocd(full_zip_slice) {
                      let reader = Cursor::new(zip_slice);
                      match ZipArchive::new(reader) {
                          Ok(mut archive) => {
                              println!("ZIP content:");
                              if let Some(out_dir) = output_dir {
                                  let extract_dir = Path::new(out_dir).join(
                                      Path::new(filename)
                                          .file_stem()
                                          .unwrap_or_default()
                                  );
                                  fs::create_dir_all(&extract_dir)?;

                                  for i in 0..archive.len() {
                                      if let Ok(mut file) = archive.by_index(i) {
                                          let outpath = extract_dir.join(file.name());
                                          if let Some(parent) = outpath.parent() {
                                              fs::create_dir_all(parent)?;
                                          }
                                          let mut outfile = File::create(&outpath)?;
                                          io::copy(&mut file, &mut outfile)?;
                                          println!(" - {} ({} bytes)", file.name(), file.size());
                                      }
                                  }
                              } else {
                                  for i in 0..archive.len() {
                                      if let Ok(file) = archive.by_index(i) {
                                          println!(" - {} ({} bytes)", file.name(), file.size());
                                      }
                                  }
                              }
                          }
                          Err(err) => {
                              println!("Failed to read zip archive: {}", err);
                              show_zip_debug(entry);
                          }
                      }
                  } else {
                      println!("Could not find EOCD marker, invalid zip format?");
                      show_zip_debug(entry);
                  }
              } else {
                  println!("Content too short for declared zip range : {} > {}", buffer.len(), zip_abs_end);
                  show_zip_debug(entry);
              }
          } else if filename.ends_with(".json") {
              if let Ok(s) = std::str::from_utf8(entry.content) {
                  match serde_json::from_str::<serde_json::Value>(s) {
                      Ok(json) => println!("Pretty JSON:\n{}", serde_json::to_string_pretty(&json).unwrap_or_else(|_| s.to_string())),
                      Err(_) => println!("Maybe JSON:\n{}", s),
                  }
              }
          } else if let Ok(s) = std::str::from_utf8(entry.content) {
              println!("Text content:\n{}", s);
          } else {
              println!("Binary preview:");
              print_hexdump_preview(entry.content, 5);
          }
      }
  }

  summarize_metadata(&entries);

  Ok(())
}

fn slice_to_eocd(data: &[u8]) -> Option<&[u8]> {
    for i in (0..=data.len().saturating_sub(22)).rev() {
        if &data[i..i + 4] == b"PK\x05\x06" {
            let comment_len = u16::from_le_bytes([data[i + 20], data[i + 21]]) as usize;
            let end = i + 22 + comment_len;
            if end <= data.len() {
                return Some(&data[..end]);
            } else {
                return Some(&data[..]);
            }
        }
    }
    None
}

fn show_zip_debug(entry: &FileEntry) {
    let start = &entry.raw_content_data[8..8 + 4.min(entry.raw_content_data.len().saturating_sub(8))];
    let end = &entry.raw_content_data[entry.raw_content_data.len().saturating_sub(4)..];
    let start_offset = entry.content_data_offset + 8;
    let end_offset = entry.content_data_offset + entry.raw_content_data.len();
    println!("Zip start: {:02x?} | ASCII: {} | Offset: 0x{:x}", start, to_ascii(start), start_offset);
    println!("Zip end: {:02x?} | ASCII: {} | Offset: 0x{:x}", end, to_ascii(end), end_offset);
}

fn to_ascii(data: &[u8]) -> String {
    data.iter()
        .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
        .collect()
}

fn summarize_metadata(entries: &[FileEntry]) {
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
            .and_then(|f| f.split('.').last())
            .unwrap_or("<none>")
            .to_lowercase();

        pairs.entry((header, content_meta)).or_default().push(ext);
    }

    println!("\n=== Header + Content Meta Summary ===");
    for ((header, meta), exts) in pairs {
        let mut counts = HashMap::new();
        for ext in exts {
            *counts.entry(ext).or_insert(0) += 1;
        }
        let summary_str: Vec<_> = counts.iter().map(|(k, v)| format!("{}.{}", v, k)).collect();
        println!("{} + {} → {}", header, meta, summary_str.join(", "));
    }
}

fn parse_file_entries(buffer: &[u8]) -> Vec<FileEntry> {
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
        let info_tag_str = std::str::from_utf8(info_tag_bytes).unwrap_or("").trim_matches('"');
        if info_tag_str != "<fileinfo>" {
            pos = info_start + info_tag_bytes.len();
            continue;
        }

        let info_data_start = info_start + info_tag_bytes.len();
        let next_tag_after_info = find_tag(buffer, info_data_start).map(|(i, _)| i).unwrap_or(buffer.len());
        let info_data = &buffer[info_data_start..next_tag_after_info];

        let (filename, header_data) = extract_filename(info_data);

        let (content_start, content_tag_bytes) = match find_tag(buffer, next_tag_after_info) {
            Some(res) => res,
            None => break,
        };
        let content_tag_str = std::str::from_utf8(content_tag_bytes).unwrap_or("").trim_matches('"');
        if content_tag_str != "<filecontent>" {
            pos = content_start + content_tag_bytes.len();
            continue;
        }

        let content_data_start = content_start + content_tag_bytes.len();
        let next_tag_after_content = find_tag(buffer, content_data_start).map(|(i, _)| i).unwrap_or(buffer.len());
        let content_data = &buffer[content_data_start..next_tag_after_content];

        let (content_length, content_meta, content): (usize, Option<&[u8; 4]>, &[u8]) = if content_data.len() >= 8 {
            let len = u32::from_be_bytes([content_data[0], content_data[1], content_data[2], content_data[3]]) as usize;
            let meta = content_data.get(4..8).and_then(|b| b.try_into().ok());
            let content_end = 8 + len;
            let content = if content_end <= content_data.len() {
                &content_data[8..content_end]
            } else {
                println!(
                    "Warning: Declared content length ({}) exceeds available data ({}), slicing what is available.",
                    len,
                    content_data.len().saturating_sub(8)
                );
                &content_data[8..]
            };
            (len, meta, content)
        } else {
            (0, None, &[][..])
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

fn extract_filename(info_data: &[u8]) -> (Option<String>, Option<&[u8; 4]>) {
    if info_data.len() < 8 {
        return (None, None);
    }

    let name_len = u32::from_be_bytes([info_data[0], info_data[1], info_data[2], info_data[3]]) as usize;
    let header_bytes = info_data.get(4..8).and_then(|b| b.try_into().ok());

    if info_data.len() < 8 + name_len {
        return (None, header_bytes);
    }

    let name_bytes = &info_data[8..8 + name_len];
    let filename = std::str::from_utf8(name_bytes).ok().map(|s| s.trim_matches('"').to_string());

    (filename, header_bytes)
}

fn find_tag(buffer: &[u8], start: usize) -> Option<(usize, &'_ [u8])> {
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

fn print_hexdump_preview(data: &[u8], max_lines: usize) {
    let mut offset = 0;

    for chunk in data.chunks(16).take(max_lines) {
        print!("{:08x}  ", offset);
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
            let c = if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' };
            print!("{}", c);
        }
        println!("|");

        offset += 16;
    }

    if data.len() > max_lines * 16 {
        println!("... ({} more bytes)", data.len() - max_lines * 16);
    }
}
