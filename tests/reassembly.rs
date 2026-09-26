mod common;

use std::collections::HashSet;

use cdr::{CdrResult, Engine, Policy, Status};
use common::*;
use lopdf::{Document, Object};

fn cats(r: &CdrResult) -> HashSet<String> {
    r.findings.iter().map(|f| f.category.clone()).collect()
}

fn assert_cats(r: &CdrResult, expected: &[&str]) {
    let c = cats(r);
    for e in expected {
        assert!(c.contains(*e), "탐지 분류 누락: {e}\n{:#?}", r.findings);
    }
}

// ============================================================================ Word

#[test]
fn docm_is_reassembled_as_docx() {
    let r = Engine::default().process(&malicious_docm(), "보고서.docm");
    assert_eq!(r.status, Status::Sanitized, "{}", r.reason);
    assert_eq!(r.output_filename.as_deref(), Some("보고서.docx"));
    assert_cats(
        &r,
        &[
            "macro",
            "embedded-object",
            "template-injection",
            "dangerous-link",
            "dde",
            "external-resource",
            "alt-chunk",
            "orphan-part",
            "foreign-xml",
            "metadata",
            "active-content",
        ],
    );

    let parts = unzip(r.output.as_ref().unwrap());
    let names: Vec<&str> = parts.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names[0], "[Content_Types].xml");
    // 허용 목록으로 조립된 파트만 존재
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(
        sorted,
        vec![
            "[Content_Types].xml",
            "_rels/.rels",
            "docProps/app.xml",
            "docProps/core.xml",
            "word/_rels/document.xml.rels",
            "word/document.xml",
            "word/media/image1.png",
            "word/settings.xml",
            "word/styles.xml",
        ]
    );

    let ct = part(&parts, "[Content_Types].xml");
    assert!(ct.contains("wordprocessingml.document.main+xml"));
    assert!(
        !ct.contains("macroEnabled") && !ct.contains("vbaProject") && !ct.contains("oleObject")
    );

    let doc = part(&parts, "word/document.xml");
    assert!(doc.contains("안전한 본문 &amp; 기호"));
    assert!(doc.contains("정상 링크") && doc.contains("악성 링크"));
    assert!(doc.contains(r#"<w:hyperlink r:id="rId3">"#));
    assert!(!doc.contains("rId4"));
    assert!(!doc.contains("DDEAUTO") && !doc.contains("INCLUDEPICTURE"));
    assert!(doc.contains("PAGE"));
    assert!(!doc.contains("OLEObject") && !doc.contains("altChunk") && !doc.contains("o:href"));
    assert!(!doc.contains("evil:payload") && !doc.contains("숨겨진 데이터"));
    assert!(doc.contains(r#"<a:blip r:embed="rId6"/>"#) && !doc.contains("rId7"));

    let rels = part(&parts, "word/_rels/document.xml.rels");
    assert!(rels.contains("https://example.com/"));
    for bad in ["file://", "vbaProject", "10.0.0.1", "oleObject", "aFChunk"] {
        assert!(!rels.contains(bad), "{bad}");
    }
    let settings = part(&parts, "word/settings.xml");
    assert!(
        !settings.contains("attachedTemplate")
            && !settings.contains("docVars")
            && settings.contains("zoom")
    );

    let core = part(&parts, "docProps/core.xml");
    assert!(core.contains("보고서") && !core.contains("홍길동") && !core.contains("attacker"));
    let app = part(&parts, "docProps/app.xml");
    assert!(!app.contains("HyperlinkBase") && !app.contains("ACME"));

    let png = &parts
        .iter()
        .find(|(n, _)| n == "word/media/image1.png")
        .unwrap()
        .1;
    assert!(
        png.ends_with(b"IEND\xaeB`\x82"),
        "덧붙은 데이터가 남아 있음"
    );
}

#[test]
fn reassembled_docx_is_clean_on_second_pass() {
    let engine = Engine::default();
    let first = engine.process(&malicious_docm(), "a.docm");
    let second = engine.process(first.output.as_ref().unwrap(), "a.docx");
    assert_eq!(second.status, Status::Clean, "{:#?}", second.findings);
}

#[test]
fn remove_hyperlinks_policy() {
    let engine = Engine::new(Policy {
        remove_hyperlinks: true,
        ..Policy::default()
    });
    let r = engine.process(&malicious_docm(), "a.docm");
    let parts = unzip(r.output.as_ref().unwrap());
    assert!(!part(&parts, "word/_rels/document.xml.rels").contains("example.com"));
    assert!(cats(&r).contains("hyperlink"));
}

#[test]
fn xxe_is_blocked() {
    let r = Engine::default().process(&xxe_docx(), "x.docx");
    assert_eq!(r.status, Status::Blocked);
    assert!(r.reason.contains("DOCTYPE"), "{}", r.reason);
}

// ============================================================================ Excel

#[test]
fn xlsm_is_reassembled_as_xlsx() {
    let r = Engine::default().process(&malicious_xlsm(), "매출.xlsm");
    assert_eq!(r.status, Status::Sanitized, "{}", r.reason);
    assert_eq!(r.output_filename.as_deref(), Some("매출.xlsx"));
    assert_cats(
        &r,
        &[
            "xlm-macro",
            "external-link",
            "data-connection",
            "auto-exec",
            "dde",
        ],
    );

    let parts = unzip(r.output.as_ref().unwrap());
    assert!(!parts.iter().any(|(n, _)| n.contains("macrosheets")
        || n.contains("externalLinks")
        || n.contains("connections")));
    let wb = part(&parts, "xl/workbook.xml");
    assert!(
        !wb.contains("Auto_Open") && !wb.contains("externalReferences") && !wb.contains("Macro1")
    );
    assert!(wb.contains(r#"name="Data""#) && wb.contains(r#"name="Sheet1""#));
    let sheet = part(&parts, "xl/worksheets/sheet1.xml");
    assert!(sheet.contains("SUM(1,2)") && !sheet.contains("cmd|") && !sheet.contains("WEBSERVICE"));
    assert!(sheet.contains("<v>0</v>"));
    assert!(part(&parts, "[Content_Types].xml").contains("spreadsheetml.sheet.main+xml"));
}

// ============================================================================ PowerPoint

#[test]
fn ppsm_is_reassembled_as_pptx() {
    let r = Engine::default().process(&malicious_ppsm(), "deck.ppsm");
    assert_eq!(r.status, Status::Sanitized, "{}", r.reason);
    assert_eq!(r.output_filename.as_deref(), Some("deck.pptx"));
    let parts = unzip(r.output.as_ref().unwrap());
    let slide = part(&parts, "ppt/slides/slide1.xml");
    assert!(!slide.contains("ppaction://program") && !slide.contains("ppaction://macro"));
    assert!(slide.contains("hlinkshowjump"));
    assert!(!slide.contains("oleObj") && !slide.contains("graphicFrame"));
    assert!(!parts.iter().any(|(n, _)| n.contains("embeddings")));
    assert!(part(&parts, "[Content_Types].xml").contains("presentationml.presentation.main+xml"));
    assert!(!parts
        .iter()
        .any(|(n, _)| n == "ppt/slides/_rels/slide1.xml.rels"));
}

// ============================================================================ PDF

#[test]
fn pdf_is_rebuilt_from_scratch() {
    let src = malicious_pdf();
    let r = Engine::default().process(&src, "문서.pdf");
    assert_eq!(r.status, Status::Sanitized, "{}", r.reason);
    assert_cats(
        &r,
        &[
            "javascript",
            "launch",
            "auto-exec",
            "embedded-file",
            "dangerous-link",
            "xfa",
            "hidden-data",
            "content-stream",
        ],
    );
    assert_eq!(r.stats.get("pages"), Some(&2));
    assert_eq!(r.stats.get("annotations_flattened"), Some(&1));
    assert_eq!(r.stats.get("links_rebuilt"), Some(&2));

    let out = r.output.as_ref().unwrap();
    assert!(!out.windows(14).any(|w| w == b"HIDDEN-PAYLOAD"));
    assert!(!out.windows(15).any(|w| w == b"evil executable"));

    let doc = Document::load_mem(out).unwrap();
    let catalog = doc.catalog().unwrap();
    let keys: HashSet<Vec<u8>> = catalog.iter().map(|(k, _)| k.clone()).collect();
    let expected: HashSet<Vec<u8>> = [b"Type".to_vec(), b"Pages".to_vec(), b"Outlines".to_vec()]
        .into_iter()
        .collect();
    assert_eq!(keys, expected, "카탈로그는 Pages/Outlines 만 가져야 함");

    for obj in doc.objects.values() {
        let dict = match obj {
            Object::Dictionary(d) => d,
            Object::Stream(s) => &s.dict,
            _ => continue,
        };
        for k in [
            b"JS".as_slice(),
            b"AA",
            b"OpenAction",
            b"EF",
            b"XFA",
            b"AcroForm",
            b"Names",
        ] {
            assert!(!dict.has(k), "금지 키 존재: {}", String::from_utf8_lossy(k));
        }
        if let Ok(s) = dict.get(b"S").and_then(Object::as_name) {
            assert!(
                s == b"URI",
                "허용되지 않은 액션: {}",
                String::from_utf8_lossy(s)
            );
        }
    }

    let pages = doc.get_pages();
    let page1 = pages[&1];
    let content = String::from_utf8_lossy(&doc.get_page_content(page1)).to_string();
    assert!(content.contains("Page One"));
    assert!(!content.contains("PS") && !content.contains("evil"));
    assert!(content.contains("BMC") && !content.contains("BDC"));
    assert!(content.contains("CdrAnnot1 Do"));

    let annots = doc.get_page_annotations(page1).unwrap();
    assert_eq!(annots.len(), 2);
    let mut uris = Vec::new();
    let mut gotos = 0;
    for a in annots {
        if let Ok(action) = a.get(b"A").and_then(Object::as_dict) {
            uris.push(
                String::from_utf8_lossy(action.get(b"URI").unwrap().as_str().unwrap()).to_string(),
            );
        }
        if let Ok(dest) = a.get(b"Dest").and_then(Object::as_array) {
            assert_eq!(dest[0].as_reference().unwrap(), pages[&2]);
            gotos += 1;
        }
    }
    assert_eq!(uris, vec!["https://example.com/".to_string()]);
    assert_eq!(gotos, 1);
}

#[test]
fn clean_pdf_stays_clean() {
    let r = Engine::default().process(&clean_pdf(), "ok.pdf");
    assert_eq!(r.status, Status::Clean, "{:#?}", r.findings);
    let doc = Document::load_mem(r.output.as_ref().unwrap()).unwrap();
    let text = doc.extract_text(&[1]).unwrap();
    assert!(text.contains("Hello CDR"), "{text}");
}

#[test]
fn reassembled_pdf_is_clean_on_second_pass() {
    let engine = Engine::default();
    let first = engine.process(&malicious_pdf(), "a.pdf");
    let second = engine.process(first.output.as_ref().unwrap(), "a.pdf");
    assert_eq!(second.status, Status::Clean, "{:#?}", second.findings);
}

// ============================================================================ 공통

#[test]
fn type_mismatch_is_reported_and_corrected() {
    let r = Engine::default().process(&clean_pdf(), "invoice.docx");
    assert!(cats(&r).contains("type-mismatch"));
    assert_eq!(r.output_filename.as_deref(), Some("invoice.pdf"));
}

#[test]
fn unsupported_inputs_are_blocked() {
    let e = Engine::default();
    assert_eq!(
        e.process(b"MZ\x90\x00\x03\x00\x00\x00", "setup.pdf").status,
        Status::Blocked
    );
    assert_eq!(
        e.process(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00\x00", "old.doc")
            .status,
        Status::Blocked
    );
    assert_eq!(e.process(b"just text", "a.txt").status, Status::Blocked);
    assert_eq!(
        e.process(b"%PDF-1.7\n garbage", "broken.pdf").status,
        Status::Blocked
    );
}

#[test]
fn zip_path_traversal_is_blocked() {
    let data = make_zip(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("word/document.xml", b"<x/>"),
        ("../../evil.sh", b"rm -rf /"),
    ]);
    let r = Engine::default().process(&data, "t.docx");
    assert_eq!(r.status, Status::Blocked);
}

#[test]
fn zip_bomb_is_blocked() {
    let big = vec![0u8; 20 * 1024 * 1024];
    let data = make_zip(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("word/document.xml", &big),
    ]);
    let r = Engine::default().process(&data, "bomb.docx");
    assert_eq!(r.status, Status::Blocked);
    assert!(r.reason.contains("압축"), "{}", r.reason);
}

#[test]
fn size_limit() {
    let engine = Engine::new(Policy {
        max_file_size: 10,
        ..Policy::default()
    });
    assert_eq!(
        engine.process(&clean_pdf(), "a.pdf").status,
        Status::Blocked
    );
}

#[test]
fn chart_workbook_is_reassembled_recursively() {
    let root_rels = format!(
        r#"<?xml version="1.0"?><Relationships xmlns="{PR}"><Relationship Id="rId1" Type="{REL}/officeDocument" Target="ppt/presentation.xml"/></Relationships>"#
    );
    let pres_rels = format!(
        r#"<?xml version="1.0"?><Relationships xmlns="{PR}"><Relationship Id="rId2" Type="{REL}/slide" Target="slides/slide1.xml"/></Relationships>"#
    );
    let pres = format!(
        r#"<?xml version="1.0"?><p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:r="{R}"><p:sldIdLst><p:sldId id="256" r:id="rId2"/></p:sldIdLst></p:presentation>"#
    );
    let slide = format!(
        r#"<?xml version="1.0"?><p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:r="{R}"><p:cSld><p:spTree/></p:cSld></p:sld>"#
    );
    let slide_rels = format!(
        r#"<?xml version="1.0"?><Relationships xmlns="{PR}"><Relationship Id="rId1" Type="{REL}/chart" Target="../charts/chart1.xml"/></Relationships>"#
    );
    let chart = format!(
        r#"<?xml version="1.0"?><c:chartSpace xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" xmlns:r="{R}"><c:externalData r:id="rId1"/></c:chartSpace>"#
    );
    let chart_rels = format!(
        r#"<?xml version="1.0"?><Relationships xmlns="{PR}"><Relationship Id="rId1" Type="{REL}/package" Target="../embeddings/Data.xlsm"/></Relationships>"#
    );
    let inner = malicious_xlsm();
    let data = make_zip(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("_rels/.rels", root_rels.as_bytes()),
        ("ppt/presentation.xml", pres.as_bytes()),
        ("ppt/_rels/presentation.xml.rels", pres_rels.as_bytes()),
        ("ppt/slides/slide1.xml", slide.as_bytes()),
        ("ppt/slides/_rels/slide1.xml.rels", slide_rels.as_bytes()),
        ("ppt/charts/chart1.xml", chart.as_bytes()),
        ("ppt/charts/_rels/chart1.xml.rels", chart_rels.as_bytes()),
        ("ppt/embeddings/Data.xlsm", &inner),
    ]);
    let r = Engine::default().process(&data, "chart.pptx");
    assert_eq!(r.status, Status::Sanitized, "{}", r.reason);
    assert!(r
        .findings
        .iter()
        .any(|f| f.category == "xlm-macro" && f.location.starts_with("ppt/embeddings/Data.xlsm!")));
    let parts = unzip(r.output.as_ref().unwrap());
    let rels = part(&parts, "ppt/charts/_rels/chart1.xml.rels");
    assert!(rels.contains("../embeddings/Data.xlsx"), "{rels}");
    assert!(part(&parts, "ppt/charts/chart1.xml").contains("externalData"));
    let embedded = &parts
        .iter()
        .find(|(n, _)| n == "ppt/embeddings/Data.xlsx")
        .unwrap()
        .1;
    let inner_parts = unzip(embedded);
    assert!(!inner_parts.iter().any(|(n, _)| n.contains("macrosheets")));
    assert!(part(&parts, "[Content_Types].xml").contains("spreadsheetml.sheet\""));
}
