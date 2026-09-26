//! 레거시 OLE 복합 파일 문서(HWP 5.x, doc, xls, ppt) 재조합.
//!
//! 원본 복합 파일을 수정하지 않고 새 복합 파일을 만들어 허용된 스트림만 조립한다.
//! 스트림 내부는 오프셋이 바뀌지 않는 제자리 무력화 또는 (오프셋이 없는 HWP 레코드의 경우)
//! 레코드 재구성으로 처리하며, 안전하게 떼어낼 수 없는 능동 콘텐츠는 차단한다.

pub mod cfbx;
pub mod doc;
pub mod hwp;
pub mod ppt;
pub mod xls;

use std::io::Cursor;

/// OLE 복합 파일의 문서 종류
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Hwp,
    Doc,
    Xls,
    Ppt,
    /// 암호화된 OOXML (EncryptedPackage)
    EncryptedOoxml,
    Other,
}

pub fn classify(data: &[u8]) -> Kind {
    let Ok(cf) = cfb::CompoundFile::open(Cursor::new(data)) else {
        return Kind::Other;
    };
    let has = |p: &str| cf.exists(p);
    if has("/EncryptedPackage") {
        Kind::EncryptedOoxml
    } else if has("/FileHeader") && (has("/BodyText") || has("/ViewText")) {
        Kind::Hwp
    } else if has("/WordDocument") {
        Kind::Doc
    } else if has("/Workbook") || has("/Book") {
        Kind::Xls
    } else if has("/PowerPoint Document") {
        Kind::Ppt
    } else {
        Kind::Other
    }
}
