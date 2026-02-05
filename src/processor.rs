use std::fs::{self, File};
use std::io::{self, Cursor, Read, Write};
use std::path::Path;
use zip::read::ZipArchive;

use crate::display::{print_hexdump_preview_indented, summarize_metadata};
use crate::file_types::{detect_file_type, file_type_name, FileType};
use crate::parser::parse_file_entries;
use crate::zip_utils::slice_to_eocd;

/// Process a file based on its detected type
pub fn process_file(
    data: &[u8],
    filename: Option<&str>,
    output_dir: Option<&str>,
    depth: usize,
) -> io::Result<()> {
    let indent = "  ".repeat(depth);
    let file_type = detect_file_type(data, filename);

    println!(
        "{}[{}] {} ({} bytes)",
        indent,
        file_type_name(&file_type),
        filename.unwrap_or("<unknown>"),
        data.len()
    );

    match file_type {
        FileType::AutelContainer => {
            process_autel_container(data, filename, output_dir, depth)?;
        }
        FileType::Zip => {
            process_zip(data, filename, output_dir, depth)?;
        }
        FileType::Gzip => {
            // Write the file but note we can't recursively parse gzip without adding flate2
            if let Some(out_dir) = output_dir {
                if let Some(fname) = filename {
                    let output_path = Path::new(out_dir).join(fname);
                    if let Some(parent) = output_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    let mut out_file = File::create(&output_path)?;
                    out_file.write_all(data)?;
                }
            }
            println!(
                "{}  → Gzip file saved (decompression not implemented)",
                indent
            );
        }
        FileType::Json => {
            if let Some(out_dir) = output_dir {
                if let Some(fname) = filename {
                    let output_path = Path::new(out_dir).join(fname);
                    if let Some(parent) = output_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    let mut out_file = File::create(&output_path)?;
                    out_file.write_all(data)?;
                }
            }
            if let Ok(s) = std::str::from_utf8(data) {
                match serde_json::from_str::<serde_json::Value>(s) {
                    Ok(json) => {
                        let pretty =
                            serde_json::to_string_pretty(&json).unwrap_or_else(|_| s.to_string());
                        for line in pretty.lines().take(20) {
                            println!("{}  {}", indent, line);
                        }
                        if pretty.lines().count() > 20 {
                            println!(
                                "{}  ... ({} more lines)",
                                indent,
                                pretty.lines().count() - 20
                            );
                        }
                    }
                    Err(_) => println!("{}  (invalid JSON)", indent),
                }
            }
        }
        FileType::Text => {
            if let Some(out_dir) = output_dir {
                if let Some(fname) = filename {
                    let output_path = Path::new(out_dir).join(fname);
                    if let Some(parent) = output_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    let mut out_file = File::create(&output_path)?;
                    out_file.write_all(data)?;
                }
            }
            if let Ok(s) = std::str::from_utf8(data) {
                for line in s.lines().take(5) {
                    println!("{}  {}", indent, line);
                }
                if s.lines().count() > 5 {
                    println!("{}  ... ({} more lines)", indent, s.lines().count() - 5);
                }
            }
        }
        FileType::UpgGimbal
        | FileType::UpgFcs
        | FileType::UpgBms
        | FileType::UpgEsc
        | FileType::UpgRcMcu
        | FileType::GpsBin => {
            // These are binary firmware files we can extract but not parse further
            if let Some(out_dir) = output_dir {
                if let Some(fname) = filename {
                    let output_path = Path::new(out_dir).join(fname);
                    if let Some(parent) = output_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    let mut out_file = File::create(&output_path)?;
                    out_file.write_all(data)?;
                }
            }
            println!(
                "{}  → Binary firmware file (no further parsing available)",
                indent
            );
            print_hexdump_preview_indented(data, 3, &indent);
        }
        FileType::Unknown => {
            if let Some(out_dir) = output_dir {
                if let Some(fname) = filename {
                    let output_path = Path::new(out_dir).join(fname);
                    if let Some(parent) = output_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    let mut out_file = File::create(&output_path)?;
                    out_file.write_all(data)?;
                }
            }
            println!("{}  → Unknown file format (no parser available)", indent);
            print_hexdump_preview_indented(data, 3, &indent);
        }
    }

    Ok(())
}

/// Process an Autel container format file
pub fn process_autel_container(
    data: &[u8],
    container_name: Option<&str>,
    output_dir: Option<&str>,
    depth: usize,
) -> io::Result<()> {
    let indent = "  ".repeat(depth);
    let entries = parse_file_entries(data);

    if entries.is_empty() {
        println!("{}  → No file entries found in container", indent);
        return Ok(());
    }

    println!("{}  → Found {} file entries", indent, entries.len());

    // Create output directory named after the container
    let extract_dir = if let Some(out_dir) = output_dir {
        let dir_name = container_name
            .map(|n| {
                Path::new(n)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(n)
            })
            .unwrap_or("extracted");
        let extract_path = Path::new(out_dir).join(dir_name);
        fs::create_dir_all(&extract_path)?;
        Some(extract_path)
    } else {
        None
    };

    for (i, entry) in entries.iter().enumerate() {
        let filename = entry.filename.as_deref();
        println!();
        println!(
            "{}  === Entry {}/{}: {} ===",
            indent,
            i + 1,
            entries.len(),
            filename.unwrap_or("<unknown>")
        );

        if let Some(header_data) = entry.header_data {
            println!("{}  Header: {:02x?}", indent, header_data);
        }
        if let Some(content_meta) = entry.content_meta {
            println!("{}  Meta: {:02x?}", indent, content_meta);
        }
        println!("{}  Size: {} bytes", indent, entry.content.len());

        let sub_output_dir = extract_dir
            .as_ref()
            .map(|p| p.to_string_lossy().to_string());

        // Recursively process the extracted content
        process_file(entry.content, filename, sub_output_dir.as_deref(), depth + 1)?;
    }

    // Print summary
    summarize_metadata(&entries, &indent);

    Ok(())
}

/// Process a ZIP archive file
pub fn process_zip(
    data: &[u8],
    zip_name: Option<&str>,
    output_dir: Option<&str>,
    depth: usize,
) -> io::Result<()> {
    let indent = "  ".repeat(depth);

    // Try to find valid ZIP by scanning for EOCD
    let zip_slice = match slice_to_eocd(data) {
        Some(slice) => slice,
        None => {
            println!(
                "{}  → Could not find valid ZIP structure (no EOCD marker)",
                indent
            );
            // Still save the raw file
            if let Some(out_dir) = output_dir {
                if let Some(fname) = zip_name {
                    let output_path = Path::new(out_dir).join(fname);
                    if let Some(parent) = output_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    let mut out_file = File::create(&output_path)?;
                    out_file.write_all(data)?;
                }
            }
            return Ok(());
        }
    };

    let reader = Cursor::new(zip_slice);
    let mut archive = match ZipArchive::new(reader) {
        Ok(a) => a,
        Err(e) => {
            println!("{}  → Failed to read ZIP archive: {}", indent, e);
            return Ok(());
        }
    };

    println!("{}  → Contains {} files", indent, archive.len());

    // Create extraction directory named after the ZIP
    let extract_dir = if let Some(out_dir) = output_dir {
        let dir_name = zip_name
            .map(|n| {
                Path::new(n)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(n)
            })
            .unwrap_or("zip_contents");
        let extract_path = Path::new(out_dir).join(dir_name);
        fs::create_dir_all(&extract_path)?;
        Some(extract_path)
    } else {
        None
    };

    // Also save the raw ZIP file
    if let Some(out_dir) = output_dir {
        if let Some(fname) = zip_name {
            let output_path = Path::new(out_dir).join(fname);
            if let Some(parent) = output_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut out_file = File::create(&output_path)?;
            out_file.write_all(data)?;
        }
    }

    for i in 0..archive.len() {
        let mut file = match archive.by_index(i) {
            Ok(f) => f,
            Err(_) => continue,
        };

        let file_name = file.name().to_string();
        let file_size = file.size() as usize;

        // Skip directories
        if file_name.ends_with('/') {
            continue;
        }

        // Read file contents
        let mut contents = Vec::with_capacity(file_size);
        if file.read_to_end(&mut contents).is_err() {
            println!("{}  - {} (read error)", indent, file_name);
            continue;
        }

        // Determine sub output directory
        let sub_output = extract_dir.as_ref().map(|p| {
            let file_path = Path::new(&file_name);
            if let Some(parent) = file_path.parent() {
                if !parent.as_os_str().is_empty() {
                    return p.join(parent).to_string_lossy().to_string();
                }
            }
            p.to_string_lossy().to_string()
        });

        // Get just the filename without directory
        let just_filename = Path::new(&file_name)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&file_name);

        // Check if this file can be recursively processed
        let file_type = detect_file_type(&contents, Some(&file_name));

        if file_type == FileType::AutelContainer || file_type == FileType::Zip {
            println!();
            // Recursively process
            process_file(
                &contents,
                Some(just_filename),
                sub_output.as_deref(),
                depth + 1,
            )?;
        } else {
            // Just extract, don't recurse for non-container types
            println!(
                "{}  - {} ({} bytes) [{}]",
                indent,
                file_name,
                file_size,
                file_type_name(&file_type)
            );

            if let Some(ref extract_path) = extract_dir {
                let outpath = extract_path.join(&file_name);
                if let Some(parent) = outpath.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut outfile = File::create(&outpath)?;
                outfile.write_all(&contents)?;
            }
        }
    }

    Ok(())
}
