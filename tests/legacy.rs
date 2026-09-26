mod common;

use std::collections::HashSet;

use cdr::{CdrResult, Engine, Status};
use common::legacy::*;

fn cats(r: &CdrResult) -> HashSet<String> {
    r.findings.iter().map(|f| f.category.clone()).collect()
}

fn assert_cats(r: &CdrResult, expected: &[&str]) {
    let c = cats(r);
    for e in expected {
        assert!(c.contains(*e), "탐지 분류 누락: {e}\n{:#?}", r.findings);
    }
}

fn names(streams: &[(String, Vec<u8>)]) -> Vec<String> {
    let mut v: Vec<String> = streams
        .iter()
        .map(|(n, _)| n.replace('\u{5}', "\\5").replace('\u{1}', "\\1"))
        .collect();
    v.sort();
    v
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

// ============================================================================ HWP 5

#[test]
fn hwp_is_reassembled() {
    let r = Engine::default().process(&malicious_hwp(1 | 8), "공문.hwp");
    assert_eq!(
        r.status,
        Status::Sanitized,
        "{} {:#?}",
        r.reason,
        r.findings
    );
    assert_eq!(r.output_filename.as_deref(), Some("공문.hwp"));
    assert_cats(
        &r,
        &[
            "macro",
            "postscript",
            "embedded-object",
            "dangerous-link",
            "external-resource",
            "metadata",
        ],
    );

    let out = read_cfb(r.output.as_ref().unwrap());
    assert_eq!(
        names(&out),
        vec![
            "BinData/BIN0001.png",
            "BodyText/Section0",
            "DocInfo",
            "FileHeader",
            "PrvText"
        ]
    );

    let header = stream(&out, "FileHeader").unwrap();
    let props = u32::from_le_bytes(header[36..40].try_into().unwrap());
    assert_eq!(props & 8, 0, "스크립트 비트가 남아 있음");
    assert_eq!(props & 1, 1);

    let docinfo = inflate(stream(&out, "DocInfo").unwrap());
    assert!(!contains(&docinfo, &utf16("10.0.0.1")));
    assert!(contains(&docinfo, &utf16("png")));

    let body = inflate(stream(&out, "BodyText/Section0").unwrap());
    assert!(contains(&body, &utf16("안전한 본문")));
    assert!(!contains(&body, &utf16("attacker")));
    assert!(contains(&body, &utf16("https\\://example.com/")));
    assert!(
        contains(&body, &utf16("www.daum.net")),
        "스킴 없는 한컴 링크는 http 로 간주해 유지"
    );

    let png = inflate(stream(&out, "BinData/BIN0001.png").unwrap());
    assert!(
        png.ends_with(b"IEND\xaeB`\x82"),
        "이미지 뒤 덧붙은 데이터가 남아 있음"
    );
    assert!(!String::from_utf16_lossy(
        &stream(&out, "PrvText")
            .unwrap()
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect::<Vec<_>>()
    )
    .contains('\u{7}'));
}

#[test]
fn hwp_uncompressed_is_reassembled() {
    let r = Engine::default().process(&malicious_hwp(0), "a.hwp");
    assert_eq!(r.status, Status::Sanitized, "{}", r.reason);
    let out = read_cfb(r.output.as_ref().unwrap());
    let body = stream(&out, "BodyText/Section0").unwrap();
    assert!(contains(body, &utf16("안전한 본문")) && !contains(body, &utf16("attacker")));
}

#[test]
fn hwp_second_pass_is_clean() {
    let engine = Engine::default();
    let first = engine.process(&malicious_hwp(1 | 8), "a.hwp");
    let second = engine.process(first.output.as_ref().unwrap(), "a.hwp");
    assert_eq!(second.status, Status::Clean, "{:#?}", second.findings);
}

#[test]
fn hwp_encrypted_and_distribution_are_blocked() {
    for flag in [2u32, 4, 16] {
        let r = Engine::default().process(&malicious_hwp(1 | flag), "a.hwp");
        assert_eq!(r.status, Status::Blocked, "flag {flag}");
    }
}

// ============================================================================ DOC

#[test]
fn doc_is_reassembled() {
    let r = Engine::default().process(&malicious_doc(1 << 9 | 1), "보고서.doc");
    assert_eq!(
        r.status,
        Status::Sanitized,
        "{} {:#?}",
        r.reason,
        r.findings
    );
    assert_cats(
        &r,
        &[
            "macro",
            "embedded-object",
            "template-injection",
            "dde",
            "hidden-data",
            "macro-enabled-format",
        ],
    );
    assert!(r
        .findings
        .iter()
        .any(|f| f.category == "template-injection" && f.severity == cdr::Severity::Critical));

    let out = read_cfb(r.output.as_ref().unwrap());
    assert_eq!(names(&out), vec!["1Table", "WordDocument", "\\1CompObj"]);
    let word = stream(&out, "WordDocument").unwrap();
    let text = &word[0x400..];
    assert_eq!(
        text.len(),
        DOC_TEXT.len(),
        "본문 길이(오프셋)가 바뀌면 안 됨"
    );
    assert!(!contains(text, b"DDEAUTO") && !contains(text, b"file://evil"));
    assert!(
        contains(text, b"result")
            && contains(text, b" PAGE ")
            && contains(text, b"HYPERLINK \\l \"_Toc1\"")
    );
    assert!(contains(text, b"bad"), "필드 결과 텍스트는 유지");
    let flags = u16::from_le_bytes([word[0x0A], word[0x0B]]);
    assert_eq!(flags & 1, 0, ".dot 표시가 남아 있음");
    for pair in [24usize, 32] {
        let at = 154 + pair * 8 + 4;
        assert_eq!(
            &word[at..at + 4],
            &[0, 0, 0, 0],
            "FIB 항목 {pair} 가 비워지지 않음"
        );
    }
}

#[test]
fn doc_second_pass_is_clean() {
    let engine = Engine::default();
    let first = engine.process(&malicious_doc(1 << 9), "a.doc");
    let second = engine.process(first.output.as_ref().unwrap(), "a.doc");
    assert_eq!(second.status, Status::Clean, "{:#?}", second.findings);
}

#[test]
fn doc_encrypted_is_blocked() {
    let r = Engine::default().process(&malicious_doc(1 << 9 | 1 << 8), "a.doc");
    assert_eq!(r.status, Status::Blocked);
}

// ============================================================================ XLS

#[test]
fn xls_vba_is_not_reassembled() {
    let r = Engine::default().process(&xls(0, &[obproj()]), "매출.xls");
    assert_eq!(r.status, Status::Sanitized, "{}", r.reason);
    assert_cats(&r, &["macro", "metadata"]);
    let out = read_cfb(r.output.as_ref().unwrap());
    assert_eq!(names(&out), vec!["Workbook"]);
}

#[test]
fn xls_xlm_macro_sheet_and_encryption_are_blocked() {
    let e = Engine::default();
    let r = e.process(&xls(1, &[]), "a.xls");
    assert_eq!(r.status, Status::Blocked);
    assert!(r.reason.contains("XLM"), "{}", r.reason);
    assert_eq!(
        e.process(&xls(0, &[filepass()]), "a.xls").status,
        Status::Blocked
    );
}

// ============================================================================ PPT

#[test]
fn ppt_actions_are_neutralized_in_place() {
    let src = ppt(false);
    let r = Engine::default().process(&src, "deck.ppt");
    assert_eq!(
        r.status,
        Status::Sanitized,
        "{} {:#?}",
        r.reason,
        r.findings
    );
    assert_cats(&r, &["auto-exec", "dangerous-link"]);

    let out = read_cfb(r.output.as_ref().unwrap());
    assert_eq!(
        names(&out),
        vec!["Current User", "Pictures", "PowerPoint Document"]
    );
    let before = stream(&read_cfb(&src), "PowerPoint Document")
        .unwrap()
        .to_vec();
    let doc = stream(&out, "PowerPoint Document").unwrap();
    assert_eq!(
        doc.len(),
        before.len(),
        "스트림 길이(오프셋)가 바뀌면 안 됨"
    );
    assert!(!contains(doc, &utf16("file://evil")) && contains(doc, &utf16("https://example.com/")));

    // InteractiveInfoAtom 의 동작 바이트: 프로그램(2)/매크로(1)/위험 링크(4→0) 는 0, 정상 링크와 이동은 유지
    let actions: Vec<u8> = doc
        .windows(8)
        .enumerate()
        .filter(|(_, w)| w[2..8] == [0xF3, 0x0F, 16, 0, 0, 0])
        .map(|(i, _)| doc[i + 8 + 8])
        .collect();
    assert_eq!(actions, vec![0, 0, 0, 4, 3]);
}

#[test]
fn ppt_with_embedded_ole_is_blocked() {
    let r = Engine::default().process(&ppt(true), "a.ppt");
    assert_eq!(r.status, Status::Blocked);
    assert!(r.reason.contains("OLE"), "{}", r.reason);
}
