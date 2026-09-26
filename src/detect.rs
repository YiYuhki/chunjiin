//! 매직 바이트와 내부 구조로 파일 형식을 판별한다. 확장자는 신뢰하지 않는다.

use std::io::Cursor;

pub const OLE_MAGIC: &[u8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Pdf,
    Docx,
    Xlsx,
    Pptx,
    /// 한컴오피스 OWPML 문서
    Hwpx,
    /// 한글 5.x 바이너리 문서
    Hwp,
    /// Word/Excel/PowerPoint 97-2003 바이너리 문서
    Doc,
    Xls,
    Ppt,
    /// 레거시 doc/xls/ppt/hwp 또는 암호화된 OOXML
    Ole,
    Zip,
    /// 단독 이미지 파일
    Png,
    Jpeg,
    Gif,
    Bmp,
    /// 텍스트 (허용 확장자일 때만, 엔진이 확장자로 결정)
    Text,
    Csv,
    Tsv,
    Unknown,
}

impl FileType {
    pub fn name(self) -> &'static str {
        match self {
            FileType::Pdf => "pdf",
            FileType::Docx => "docx",
            FileType::Xlsx => "xlsx",
            FileType::Pptx => "pptx",
            FileType::Hwpx => "hwpx",
            FileType::Hwp => "hwp",
            FileType::Doc => "doc",
            FileType::Xls => "xls",
            FileType::Ppt => "ppt",
            FileType::Ole => "ole",
            FileType::Zip => "zip",
            FileType::Png => "png",
            FileType::Jpeg => "jpeg",
            FileType::Gif => "gif",
            FileType::Bmp => "bmp",
            FileType::Text => "text",
            FileType::Csv => "csv",
            FileType::Tsv => "tsv",
            FileType::Unknown => "unknown",
        }
    }

    /// 재조합 결과물의 확장자 (매크로/템플릿/쇼 형식은 일반 문서 형식으로)
    /// 재조합 결과물의 형식 (BMP 는 PNG 로 바뀐다)
    pub fn output_type(self) -> FileType {
        match self {
            FileType::Bmp => FileType::Png,
            t => t,
        }
    }

    pub fn output_extension(self) -> Option<&'static str> {
        match self {
            FileType::Pdf => Some("pdf"),
            FileType::Docx => Some("docx"),
            FileType::Xlsx => Some("xlsx"),
            FileType::Pptx => Some("pptx"),
            FileType::Hwpx => Some("hwpx"),
            FileType::Hwp => Some("hwp"),
            FileType::Doc => Some("doc"),
            FileType::Xls => Some("xls"),
            FileType::Ppt => Some("ppt"),
            FileType::Zip => Some("zip"),
            FileType::Png | FileType::Bmp => Some("png"),
            FileType::Jpeg => Some("jpg"),
            FileType::Gif => Some("gif"),
            _ => None,
        }
    }

    /// 해당 형식으로 정상 간주되는 확장자
    pub fn accepts_extension(self, ext: &str) -> bool {
        let list: &[&str] = match self {
            FileType::Pdf => &["pdf"],
            FileType::Docx => &["docx", "docm", "dotx", "dotm"],
            FileType::Xlsx => &["xlsx", "xlsm", "xltx", "xltm", "xlam"],
            FileType::Pptx => &["pptx", "pptm", "potx", "potm", "ppsx", "ppsm", "ppam"],
            FileType::Hwpx => &["hwpx"],
            FileType::Hwp => &["hwp"],
            FileType::Doc => &["doc", "dot"],
            FileType::Xls => &["xls", "xlt", "xla"],
            FileType::Ppt => &["ppt", "pot", "pps"],
            FileType::Ole => &[
                "doc", "dot", "xls", "xlt", "ppt", "pot", "pps", "hwp", "msg",
            ],
            FileType::Zip => &["zip"],
            FileType::Png => &["png"],
            FileType::Jpeg => &["jpg", "jpeg", "jpe", "jfif"],
            FileType::Gif => &["gif"],
            FileType::Bmp => &["bmp", "dib"],
            FileType::Text => &["txt", "log"],
            FileType::Csv => &["csv"],
            FileType::Tsv => &["tsv", "tab"],
            FileType::Unknown => &[],
        };
        list.contains(&ext)
    }
}

pub fn extension_of(filename: &str) -> String {
    let base = filename.rsplit(['/', '\\']).next().unwrap_or(filename);
    match base.rsplit_once('.') {
        Some((_, ext)) => ext.to_ascii_lowercase(),
        None => String::new(),
    }
}

/// 내용으로 판별하고, 판별되지 않으면 허용된 텍스트 확장자인 경우에만 텍스트로 본다
pub fn detect_named(data: &[u8], filename: &str, allow_text: bool) -> FileType {
    match detect(data) {
        FileType::Unknown
            if allow_text && !data.starts_with(b"MZ") && !data.starts_with(b"\x7fELF") =>
        {
            match crate::text::kind_for_extension(&extension_of(filename)) {
                Some(crate::text::Kind::Text) => FileType::Text,
                Some(crate::text::Kind::Delimited('\t')) => FileType::Tsv,
                Some(_) => FileType::Csv,
                None => FileType::Unknown,
            }
        }
        t => t,
    }
}

pub fn detect(data: &[u8]) -> FileType {
    let head = &data[..data.len().min(1024)];
    if find(head, b"%PDF-").is_some() {
        return FileType::Pdf;
    }
    if data.starts_with(OLE_MAGIC) {
        use crate::legacy::Kind;
        return match crate::legacy::classify(data) {
            Kind::Hwp => FileType::Hwp,
            Kind::Doc => FileType::Doc,
            Kind::Xls => FileType::Xls,
            Kind::Ppt => FileType::Ppt,
            Kind::EncryptedOoxml | Kind::Other => FileType::Ole,
        };
    }
    if data.starts_with(b"PK\x03\x04") {
        return detect_zip(data);
    }
    match crate::imaging::ImageKind::sniff(data) {
        Some(crate::imaging::ImageKind::Png) => FileType::Png,
        Some(crate::imaging::ImageKind::Jpeg) => FileType::Jpeg,
        Some(crate::imaging::ImageKind::Gif) => FileType::Gif,
        Some(crate::imaging::ImageKind::Bmp) => FileType::Bmp,
        None => FileType::Unknown,
    }
}

fn detect_zip(data: &[u8]) -> FileType {
    let Ok(mut archive) = zip::ZipArchive::new(Cursor::new(data)) else {
        return FileType::Unknown;
    };
    if let Ok(mut f) = archive.by_name("mimetype") {
        let mut head = Vec::new();
        use std::io::Read;
        if (&mut f).take(64).read_to_end(&mut head).is_ok()
            && head.trim_ascii().starts_with(b"application/hwp+zip")
        {
            return FileType::Hwpx;
        }
    }
    let names: Vec<&str> = archive.file_names().collect();
    if !names.contains(&"[Content_Types].xml") {
        return FileType::Zip;
    }
    if names.iter().any(|n| n.starts_with("word/")) {
        FileType::Docx
    } else if names.iter().any(|n| n.starts_with("xl/")) {
        FileType::Xlsx
    } else if names.iter().any(|n| n.starts_with("ppt/")) {
        FileType::Pptx
    } else {
        FileType::Zip
    }
}

pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

pub fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).rposition(|w| w == needle)
}
