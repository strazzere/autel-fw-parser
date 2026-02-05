/// File type enumeration for detected firmware formats
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum FileType {
    AutelContainer, // "<filetransfer>" format
    Zip,
    Gzip,
    Json,
    UpgGimbal, // 34 12 ef be
    UpgFcs,    // 55 50 46 53 "UPFS"
    UpgBms,    // 02 aa 55 aa
    UpgEsc,    // 00 00 00 00 xx
    UpgRcMcu,  // 34 12 ef be 0e
    GpsBin,    // @TD1050x
    Text,
    Unknown,
}

/// Detect the file type based on magic bytes and filename
pub fn detect_file_type(data: &[u8], filename: Option<&str>) -> FileType {
    if data.len() < 4 {
        return FileType::Unknown;
    }

    // Check for Autel container format
    if data.len() >= 16 {
        if let Some(pos) = data
            .windows(14)
            .position(|w| w == b"\"<filetransfer>\"".as_slice().get(..14).unwrap_or(&[]))
        {
            if pos < 100 {
                return FileType::AutelContainer;
            }
        }
        // Also check without quotes
        for i in 0..100.min(data.len().saturating_sub(16)) {
            if &data[i..i + 2] == b"\"<" {
                if let Ok(s) = std::str::from_utf8(&data[i..i + 16.min(data.len() - i)]) {
                    if s.contains("<filetransfer>") {
                        return FileType::AutelContainer;
                    }
                }
            }
        }
    }

    // Check magic bytes
    if &data[0..4] == b"PK\x03\x04" {
        return FileType::Zip;
    }

    if data.len() >= 2 && data[0..2] == [0x1f, 0x8b] {
        return FileType::Gzip;
    }

    if data[0..4] == [0x34, 0x12, 0xef, 0xbe] {
        if data.len() >= 5 && data[4] == 0x0e {
            return FileType::UpgRcMcu;
        }
        return FileType::UpgGimbal;
    }

    if &data[0..4] == b"UPFS" {
        return FileType::UpgFcs;
    }

    if data[0..4] == [0x02, 0xaa, 0x55, 0xaa] {
        return FileType::UpgBms;
    }

    if data[0..4] == [0x00, 0x00, 0x00, 0x00] && data.len() >= 5 {
        // ESC firmware has 00 00 00 00 followed by ESC ID (0x14-0x17)
        if data[4] >= 0x14 && data[4] <= 0x17 {
            return FileType::UpgEsc;
        }
    }

    if data.len() >= 8 && &data[0..8] == b"@TD1050x" {
        return FileType::GpsBin;
    }

    // Check by filename extension
    if let Some(name) = filename {
        if name.ends_with(".json") {
            return FileType::Json;
        }
        if name.ends_with(".zip") {
            return FileType::Zip;
        }
    }

    // Check if it's valid UTF-8 text
    if std::str::from_utf8(data).is_ok() {
        // Check if it looks like JSON
        let trimmed = data
            .iter()
            .position(|&b| !b.is_ascii_whitespace())
            .unwrap_or(0);
        if data.len() > trimmed && (data[trimmed] == b'{' || data[trimmed] == b'[') {
            return FileType::Json;
        }
        return FileType::Text;
    }

    FileType::Unknown
}

/// Get a human-readable name for a file type
pub fn file_type_name(ft: &FileType) -> &'static str {
    match ft {
        FileType::AutelContainer => "Autel Container",
        FileType::Zip => "ZIP Archive",
        FileType::Gzip => "Gzip Compressed",
        FileType::Json => "JSON",
        FileType::UpgGimbal => "UPG (Gimbal)",
        FileType::UpgFcs => "UPG (Flight Control System)",
        FileType::UpgBms => "UPG (Battery Management)",
        FileType::UpgEsc => "UPG (ESC)",
        FileType::UpgRcMcu => "UPG (RC MCU)",
        FileType::GpsBin => "GPS Binary",
        FileType::Text => "Text",
        FileType::Unknown => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_zip_by_magic() {
        let zip_data = b"PK\x03\x04some zip content here";
        assert_eq!(detect_file_type(zip_data, None), FileType::Zip);
    }

    #[test]
    fn test_detect_zip_by_extension() {
        let data = b"not a real zip but has extension";
        assert_eq!(detect_file_type(data, Some("file.zip")), FileType::Zip);
    }

    #[test]
    fn test_detect_gzip() {
        let gzip_data = &[0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00];
        assert_eq!(detect_file_type(gzip_data, None), FileType::Gzip);
    }

    #[test]
    fn test_detect_upg_gimbal() {
        let gimbal_data = &[0x34, 0x12, 0xef, 0xbe, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(detect_file_type(gimbal_data, None), FileType::UpgGimbal);
    }

    #[test]
    fn test_detect_upg_rc_mcu() {
        let rc_mcu_data = &[0x34, 0x12, 0xef, 0xbe, 0x0e, 0x00, 0x00, 0x00];
        assert_eq!(detect_file_type(rc_mcu_data, None), FileType::UpgRcMcu);
    }

    #[test]
    fn test_detect_upg_fcs() {
        let fcs_data = b"UPFSsome fcs firmware data";
        assert_eq!(detect_file_type(fcs_data, None), FileType::UpgFcs);
    }

    #[test]
    fn test_detect_upg_bms() {
        let bms_data = &[0x02, 0xaa, 0x55, 0xaa, 0x0a, 0x00, 0x00, 0x00];
        assert_eq!(detect_file_type(bms_data, None), FileType::UpgBms);
    }

    #[test]
    fn test_detect_upg_esc() {
        let esc_data_14 = &[0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00];
        let esc_data_15 = &[0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00];
        let esc_data_16 = &[0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00];
        let esc_data_17 = &[0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00];

        assert_eq!(detect_file_type(esc_data_14, None), FileType::UpgEsc);
        assert_eq!(detect_file_type(esc_data_15, None), FileType::UpgEsc);
        assert_eq!(detect_file_type(esc_data_16, None), FileType::UpgEsc);
        assert_eq!(detect_file_type(esc_data_17, None), FileType::UpgEsc);
    }

    #[test]
    fn test_detect_esc_boundary() {
        let not_esc_low = &[0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00];
        let not_esc_high = &[0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00];

        assert_ne!(detect_file_type(not_esc_low, None), FileType::UpgEsc);
        assert_ne!(detect_file_type(not_esc_high, None), FileType::UpgEsc);
    }

    #[test]
    fn test_detect_gps_bin() {
        let gps_data = b"@TD1050xsome gps firmware data here";
        assert_eq!(detect_file_type(gps_data, None), FileType::GpsBin);
    }

    #[test]
    fn test_detect_json_by_extension() {
        let data = b"plain text content";
        assert_eq!(detect_file_type(data, Some("config.json")), FileType::Json);
    }

    #[test]
    fn test_detect_json_by_content_object() {
        let json_data = b"{\"key\": \"value\"}";
        assert_eq!(detect_file_type(json_data, None), FileType::Json);
    }

    #[test]
    fn test_detect_json_by_content_array() {
        let json_data = b"[1, 2, 3]";
        assert_eq!(detect_file_type(json_data, None), FileType::Json);
    }

    #[test]
    fn test_detect_json_with_whitespace() {
        let json_data = b"  \n  {\"key\": \"value\"}";
        assert_eq!(detect_file_type(json_data, None), FileType::Json);
    }

    #[test]
    fn test_detect_text() {
        let text_data = b"Hello, this is plain text content.";
        assert_eq!(detect_file_type(text_data, None), FileType::Text);
    }

    #[test]
    fn test_detect_autel_container() {
        let container_data = b"some padding\"<filetransfer>\"\"<fileinfo>\"more data";
        assert_eq!(
            detect_file_type(container_data, None),
            FileType::AutelContainer
        );
    }

    #[test]
    fn test_detect_unknown_binary() {
        let binary_data = &[0xde, 0xad, 0xbe, 0xef, 0x00, 0xff, 0x80, 0x7f];
        assert_eq!(detect_file_type(binary_data, None), FileType::Unknown);
    }

    #[test]
    fn test_detect_too_short() {
        let short_data = &[0x01, 0x02, 0x03];
        assert_eq!(detect_file_type(short_data, None), FileType::Unknown);
    }

    #[test]
    fn test_detect_empty() {
        let empty_data: &[u8] = &[];
        assert_eq!(detect_file_type(empty_data, None), FileType::Unknown);
    }

    #[test]
    fn test_file_type_names() {
        assert_eq!(file_type_name(&FileType::AutelContainer), "Autel Container");
        assert_eq!(file_type_name(&FileType::Zip), "ZIP Archive");
        assert_eq!(file_type_name(&FileType::Gzip), "Gzip Compressed");
        assert_eq!(file_type_name(&FileType::Json), "JSON");
        assert_eq!(file_type_name(&FileType::UpgGimbal), "UPG (Gimbal)");
        assert_eq!(
            file_type_name(&FileType::UpgFcs),
            "UPG (Flight Control System)"
        );
        assert_eq!(file_type_name(&FileType::UpgBms), "UPG (Battery Management)");
        assert_eq!(file_type_name(&FileType::UpgEsc), "UPG (ESC)");
        assert_eq!(file_type_name(&FileType::UpgRcMcu), "UPG (RC MCU)");
        assert_eq!(file_type_name(&FileType::GpsBin), "GPS Binary");
        assert_eq!(file_type_name(&FileType::Text), "Text");
        assert_eq!(file_type_name(&FileType::Unknown), "Unknown");
    }

    #[test]
    fn test_real_world_magic_bytes() {
        // Gimbal firmware
        let gimbal = &[0x34, 0x12, 0xef, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(
            detect_file_type(gimbal, Some("gimbal.upg")),
            FileType::UpgGimbal
        );

        // FCS firmware
        let fcs = b"UPFS\x00\x00\x01\x00\x00\x75\x0e\x00";
        assert_eq!(detect_file_type(fcs, Some("fcs.upg")), FileType::UpgFcs);

        // BMS firmware
        let bms = &[0x02, 0xaa, 0x55, 0xaa, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(detect_file_type(bms, Some("bms.upg")), FileType::UpgBms);

        // GPS binary
        let gps = b"@TD1050x\x1a\xd4\x33\xf2\xe0\x0d\x00\x00";
        assert_eq!(detect_file_type(gps, Some("gps.bin")), FileType::GpsBin);
    }
}
