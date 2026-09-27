//! OOXML 재조합 허용 목록: 관계 유형 → 콘텐츠 형식, 네임스페이스, 위험 관계 분류.

use crate::report::Severity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocKind {
    Word,
    Excel,
    PowerPoint,
}

/// 재조합 대상 파트의 콘텐츠 형식
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartType {
    Xml(&'static str),
    Vml,
    Image,
    /// 차트 데이터용 내장 OOXML 패키지 (재귀적으로 재조합)
    Package,
}

pub const CHART_CT: &str = "application/vnd.openxmlformats-officedocument.drawingml.chart+xml";

pub const VML_CT: &str = "application/vnd.openxmlformats-officedocument.vmlDrawing";

pub const PKG_REL_NS: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
pub const CT_NS: &str = "http://schemas.openxmlformats.org/package/2006/content-types";

const REL_TYPE_BASES: &[&str] = &[
    "http://schemas.openxmlformats.org/",
    "http://purl.oclc.org/ooxml/",
    "http://schemas.microsoft.com/office/",
];

/// 관계 유형 URI 를 분해한다. (짧은 이름, Microsoft 확장 여부)
pub fn rel_short_name(rel_type: &str) -> Option<(&str, bool)> {
    if !REL_TYPE_BASES.iter().any(|b| rel_type.starts_with(b)) {
        return None;
    }
    let idx = rel_type.rfind("/relationships/")?;
    let short = &rel_type[idx + "/relationships/".len()..];
    Some((short, rel_type.starts_with("http://schemas.microsoft.com/")))
}

/// 허용된 내부 관계면 대상 파트 형식을 돌려준다. 목록에 없으면 None (= 재조합에서 제외).
pub fn allowed_rel(
    kind: DocKind,
    rel_type: &str,
    from_root: bool,
    source: Option<PartType>,
) -> Option<PartType> {
    use PartType::*;
    let (short, microsoft) = rel_short_name(rel_type)?;

    // 차트의 원본 데이터 통합 문서만 내장 패키지로 허용한다
    if short == "package" {
        return (source == Some(Xml(CHART_CT))).then_some(Package);
    }

    if from_root {
        return match short {
            "officeDocument" => Some(Xml(main_content_type(kind))),
            "metadata/core-properties" => Some(Xml(
                "application/vnd.openxmlformats-package.core-properties+xml",
            )),
            "extended-properties" => Some(Xml(
                "application/vnd.openxmlformats-officedocument.extended-properties+xml",
            )),
            "metadata/thumbnail" => Some(Image),
            _ => None,
        };
    }

    let common = match short {
        "theme" => Some(Xml(
            "application/vnd.openxmlformats-officedocument.theme+xml",
        )),
        "themeOverride" => Some(Xml(
            "application/vnd.openxmlformats-officedocument.themeOverride+xml",
        )),
        "image" => Some(Image),
        "chart" => Some(Xml(CHART_CT)),
        "chartUserShapes" => Some(Xml(
            "application/vnd.openxmlformats-officedocument.drawingml.chartshapes+xml",
        )),
        "chartStyle" => Some(Xml("application/vnd.ms-office.chartstyle+xml")),
        "chartColorStyle" => Some(Xml("application/vnd.ms-office.chartcolorstyle+xml")),
        "diagramData" => Some(Xml(
            "application/vnd.openxmlformats-officedocument.drawingml.diagramData+xml",
        )),
        "diagramLayout" => Some(Xml(
            "application/vnd.openxmlformats-officedocument.drawingml.diagramLayout+xml",
        )),
        "diagramQuickStyle" => Some(Xml(
            "application/vnd.openxmlformats-officedocument.drawingml.diagramStyle+xml",
        )),
        "diagramColors" => Some(Xml(
            "application/vnd.openxmlformats-officedocument.drawingml.diagramColors+xml",
        )),
        "diagramDrawing" => Some(Xml(
            "application/vnd.ms-office.drawingml.diagramDrawing+xml",
        )),
        "vmlDrawing" => Some(Vml),
        _ => None,
    };
    if common.is_some() {
        return common;
    }

    match kind {
        DocKind::Word => {
            let w = |x: &'static str| Some(Xml(x));
            match short {
                "styles" => w("application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"),
                "stylesWithEffects" => w("application/vnd.ms-word.stylesWithEffects+xml"),
                "settings" => w("application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"),
                "webSettings" => w("application/vnd.openxmlformats-officedocument.wordprocessingml.webSettings+xml"),
                "fontTable" => w("application/vnd.openxmlformats-officedocument.wordprocessingml.fontTable+xml"),
                "numbering" => w("application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"),
                "footnotes" => w("application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml"),
                "endnotes" => w("application/vnd.openxmlformats-officedocument.wordprocessingml.endnotes+xml"),
                "comments" if !microsoft => w("application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml"),
                "header" => w("application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"),
                "footer" => w("application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"),
                "commentsExtended" => w("application/vnd.openxmlformats-officedocument.wordprocessingml.commentsExtended+xml"),
                "commentsIds" => w("application/vnd.openxmlformats-officedocument.wordprocessingml.commentsIds+xml"),
                "commentsExtensible" => w("application/vnd.openxmlformats-officedocument.wordprocessingml.commentsExtensible+xml"),
                "people" => w("application/vnd.openxmlformats-officedocument.wordprocessingml.people+xml"),
                "glossaryDocument" => w("application/vnd.openxmlformats-officedocument.wordprocessingml.document.glossary+xml"),
                _ => None,
            }
        }
        DocKind::Excel => {
            let x = |t: &'static str| Some(Xml(t));
            match short {
                "worksheet" => x("application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"),
                "chartsheet" => x("application/vnd.openxmlformats-officedocument.spreadsheetml.chartsheet+xml"),
                "sharedStrings" => x("application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"),
                "styles" => x("application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"),
                "calcChain" => x("application/vnd.openxmlformats-officedocument.spreadsheetml.calcChain+xml"),
                "table" => x("application/vnd.openxmlformats-officedocument.spreadsheetml.table+xml"),
                "comments" if !microsoft => x("application/vnd.openxmlformats-officedocument.spreadsheetml.comments+xml"),
                "pivotTable" => x("application/vnd.openxmlformats-officedocument.spreadsheetml.pivotTable+xml"),
                "pivotCacheDefinition" => x("application/vnd.openxmlformats-officedocument.spreadsheetml.pivotCacheDefinition+xml"),
                "pivotCacheRecords" => x("application/vnd.openxmlformats-officedocument.spreadsheetml.pivotCacheRecords+xml"),
                "sheetMetadata" => x("application/vnd.openxmlformats-officedocument.spreadsheetml.sheetMetadata+xml"),
                "drawing" => x("application/vnd.openxmlformats-officedocument.drawing+xml"),
                "threadedComment" => x("application/vnd.ms-excel.threadedcomments+xml"),
                "person" => x("application/vnd.ms-excel.person+xml"),
                _ => None,
            }
        }
        DocKind::PowerPoint => {
            let p = |t: &'static str| Some(Xml(t));
            match short {
                "slide" => p("application/vnd.openxmlformats-officedocument.presentationml.slide+xml"),
                "slideLayout" => p("application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"),
                "slideMaster" => p("application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"),
                "notesSlide" => p("application/vnd.openxmlformats-officedocument.presentationml.notesSlide+xml"),
                "notesMaster" => p("application/vnd.openxmlformats-officedocument.presentationml.notesMaster+xml"),
                "handoutMaster" => p("application/vnd.openxmlformats-officedocument.presentationml.handoutMaster+xml"),
                "presProps" => p("application/vnd.openxmlformats-officedocument.presentationml.presProps+xml"),
                "viewProps" => p("application/vnd.openxmlformats-officedocument.presentationml.viewProps+xml"),
                "tableStyles" => p("application/vnd.openxmlformats-officedocument.presentationml.tableStyles+xml"),
                "commentAuthors" => p("application/vnd.openxmlformats-officedocument.presentationml.commentAuthors+xml"),
                "comments" if !microsoft => p("application/vnd.openxmlformats-officedocument.presentationml.comments+xml"),
                _ => None,
            }
        }
    }
}

/// 재조합 결과 메인 파트 형식. 매크로/템플릿/쇼 형식은 항상 일반 문서 형식으로 만든다.
pub fn main_content_type(kind: DocKind) -> &'static str {
    match kind {
        DocKind::Word => {
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
        }
        DocKind::Excel => {
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
        }
        DocKind::PowerPoint => {
            "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"
        }
    }
}

/// 재조합에서 제외된 관계를 보고용으로 분류한다.
pub fn classify_dropped(short: &str, external: bool) -> (&'static str, Severity, &'static str) {
    match short {
        "vbaProject" | "wordVbaData" | "vbaProjectSignature" => {
            ("macro", Severity::Critical, "VBA 매크로")
        }
        "xlMacrosheet" | "xlIntlMacrosheet" => (
            "xlm-macro",
            Severity::Critical,
            "Excel 4.0(XLM) 매크로 시트",
        ),
        "attachedTemplate" => (
            "template-injection",
            Severity::Critical,
            "원격/첨부 템플릿(템플릿 인젝션)",
        ),
        "oleObject" if external => ("external-object", Severity::High, "외부 OLE 개체 링크"),
        "oleObject" | "package" => (
            "embedded-object",
            Severity::High,
            "OLE 개체/임베디드 패키지",
        ),
        "control" | "activeXControlBinary" => ("activex", Severity::High, "ActiveX 컨트롤"),
        "externalLink" | "externalLinkPath" => (
            "external-link",
            Severity::High,
            "외부 통합 문서 링크(DDE 가능)",
        ),
        "frame" => ("external-frame", Severity::High, "외부 프레임"),
        "subDocument" => ("external-document", Severity::High, "하위 문서"),
        "aFChunk" => (
            "alt-chunk",
            Severity::Medium,
            "altChunk(외부 형식 삽입 콘텐츠)",
        ),
        "extensibility" | "ui/extensibility" => (
            "customui",
            Severity::Medium,
            "리본 사용자 지정(매크로 콜백)",
        ),
        "connections" | "queryTable" => ("data-connection", Severity::Medium, "외부 데이터 연결"),
        "keyMapCustomizations" => ("macro", Severity::Medium, "키 매핑(매크로 연결)"),
        "font" => ("embedded-font", Severity::Low, "임베디드 글꼴"),
        "image" if external => (
            "external-resource",
            Severity::Medium,
            "외부 이미지(추적/NTLM 해시 유출 가능)",
        ),
        "hyperlink" => ("dangerous-link", Severity::High, "허용되지 않은 하이퍼링크"),
        "custom-properties" => ("metadata", Severity::Info, "사용자 정의 문서 속성"),
        "customXml" | "customXmlProps" => ("custom-xml", Severity::Info, "사용자 정의 XML 데이터"),
        "printerSettings" => ("binary-part", Severity::Info, "프린터 설정 바이너리"),
        _ if external => ("external-resource", Severity::Medium, "외부 참조"),
        _ => ("unlisted-part", Severity::Low, "허용 목록 외 파트"),
    }
}

/// 재조합 문서에 남길 수 있는 XML 네임스페이스 (표준 OOXML, Microsoft Office 확장, VML, Dublin Core)
pub fn namespace_allowed(ns: &str) -> bool {
    ns.is_empty()
        || ns.starts_with("http://schemas.openxmlformats.org/")
        || ns.starts_with("http://purl.oclc.org/ooxml/")
        || ns.starts_with("http://schemas.microsoft.com/office/")
        || ns.starts_with("urn:schemas-microsoft-com:")
        || ns.starts_with("http://purl.org/dc/")
        || ns == "http://www.w3.org/2001/XMLSchema-instance"
        || ns == crate::xml::XML_NS
        || ns == crate::xml::XMLNS_NS
}

pub fn is_rel_attr_ns(ns: &str) -> bool {
    ns == "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
        || ns == "http://purl.oclc.org/ooxml/officeDocument/relationships"
}

pub fn is_word_ns(ns: &str) -> bool {
    ns == "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
        || ns == "http://purl.oclc.org/ooxml/wordprocessingml/main"
}

pub fn is_sheet_ns(ns: &str) -> bool {
    ns == "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
        || ns == "http://purl.oclc.org/ooxml/spreadsheetml/main"
}

pub fn is_pres_ns(ns: &str) -> bool {
    ns == "http://schemas.openxmlformats.org/presentationml/2006/main"
        || ns == "http://purl.oclc.org/ooxml/presentationml/main"
}

pub const VML_OFFICE_NS: &str = "urn:schemas-microsoft-com:office:office";
