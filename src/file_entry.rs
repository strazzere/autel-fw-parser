/// Represents a parsed file entry from an Autel container
#[derive(Debug)]
pub struct FileEntry<'a> {
    pub filename: Option<String>,
    pub header_data: Option<&'a [u8; 4]>,
    pub content_meta: Option<&'a [u8; 4]>,
    pub content: &'a [u8],
    // Fields below are kept for potential future use (debugging, raw access)
    #[allow(dead_code)]
    pub content_length: usize,
    #[allow(dead_code)]
    pub raw_content_data: &'a [u8],
    #[allow(dead_code)]
    pub content_data_offset: usize,
}
