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

fn neutralizing() -> Engine {
    Engine::new(cdr::Policy {
        neutralize_embedded_ole: true,
        ..cdr::Policy::default()
    })
}

#[test]
fn xls_embedded_ole_is_blocked_by_default() {
    let r = Engine::default().process(&xls(0, &[obproj()]), "매출.xls");
    assert_eq!(r.status, Status::Blocked);
    assert!(r.reason.contains("--neutralize-ole"), "{}", r.reason);
}

#[test]
fn xls_vba_and_ole_are_not_reassembled() {
    let r = neutralizing().process(&xls(0, &[obproj()]), "매출.xls");
    assert_eq!(r.status, Status::Sanitized, "{}", r.reason);
    assert_cats(&r, &["macro", "metadata", "embedded-object"]);
    let out = r.output.as_ref().unwrap();
    assert_eq!(names(&read_cfb(out)), vec!["Workbook"]);
    // 빈 MBD 저장소는 남아 있음 (시트의 개체 참조 유지)
    let c = cfb::CompoundFile::open(std::io::Cursor::new(out.as_slice())).unwrap();
    assert!(c.is_storage("/MBD0001A2B3"));
    let second = neutralizing().process(out, "a.xls");
    assert_eq!(second.status, Status::Clean, "{:#?}", second.findings);
}

#[test]
fn xls_xlm_macro_sheet_and_encryption_are_blocked() {
    // 임베디드 OLE 는 대체 모드로 통과시켜 BIFF 판정까지 도달하게 한다
    let e = neutralizing();
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
fn ppt_with_embedded_ole_is_blocked_by_default() {
    let r = Engine::default().process(&ppt(true), "a.ppt");
    assert_eq!(r.status, Status::Blocked);
    assert!(r.reason.contains("OLE"), "{}", r.reason);
}

#[test]
fn ppt_embedded_ole_is_replaced_with_empty_storage() {
    let src = ppt(true);
    let r = neutralizing().process(&src, "a.ppt");
    assert_eq!(r.status, Status::Sanitized, "{}", r.reason);
    assert!(r
        .findings
        .iter()
        .any(|f| f.description.contains("빈 개체로 대체")));
    let out = read_cfb(r.output.as_ref().unwrap());
    let doc = stream(&out, "PowerPoint Document").unwrap();
    assert_eq!(
        doc.len(),
        stream(&read_cfb(&src), "PowerPoint Document")
            .unwrap()
            .len()
    );
    assert!(!contains(doc, b"payload") && !contains(doc, &[b'A'; 64]));

    // 대체된 저장소는 스트림이 하나도 없는 정상 OLE 복합 파일
    let at = doc
        .windows(4)
        .position(|w| w == [0x10, 0x00, 0x11, 0x10])
        .unwrap();
    let len = u32::from_le_bytes(doc[at + 4..at + 8].try_into().unwrap()) as usize;
    let body = &doc[at + 8..at + 8 + len];
    let mut raw = Vec::new();
    std::io::Read::read_to_end(&mut flate2::read::ZlibDecoder::new(&body[4..]), &mut raw).unwrap();
    let c = cfb::CompoundFile::open(std::io::Cursor::new(raw)).unwrap();
    assert_eq!(c.walk().filter(|e| !e.is_root()).count(), 0);

    let second = neutralizing().process(r.output.as_ref().unwrap(), "a.ppt");
    assert_eq!(second.status, Status::Clean, "{:#?}", second.findings);
}

#[test]
fn legacy_output_is_deterministic() {
    // 저장소 시각을 고정하므로 같은 입력은 항상 같은 바이트로 재조합된다
    let e = neutralizing();
    for (name, data) in [
        ("a.hwp", malicious_hwp(1 | 8)),
        ("a.doc", malicious_doc(1 << 9)),
        ("a.xls", xls(0, &[obproj()])),
        ("a.ppt", ppt(true)),
    ] {
        let a = e.process(&data, name).output.expect(name);
        std::thread::sleep(std::time::Duration::from_millis(20));
        let b = e.process(&data, name).output.expect(name);
        assert!(a == b, "{name}: 출력이 실행마다 다름");
    }
}

#[test]
fn ppt_pictures_are_reencoded_and_references_patched() {
    // 그림 스트림: [숨긴 데이터][PNG(뒤에 페이로드)][메타파일] - FBSE 가 PNG 와 메타파일을 가리킴
    let png = common::png_with_payload();
    let blip = |rtype: u16, instance: u16, data: &[u8]| {
        let mut body = vec![0xAB; 16];
        body.push(0xFF);
        body.extend(data);
        ppt_rec(0, instance, rtype, &body)
    };
    let hidden = b"HIDDEN-PAYLOAD-BETWEEN-BLIPS".to_vec();
    let png_rec = blip(0xF01E, 0x6E0, &png);
    let meta_rec = ppt_rec(0, 0x216, 0xF01B, &[0x11; 60]);
    let mut pictures = hidden.clone();
    pictures.extend(&png_rec);
    pictures.extend(&meta_rec);
    let fbse = |size: usize, fo: usize| {
        let mut b = vec![6u8, 6];
        b.extend([0u8; 16]);
        b.extend(0u16.to_le_bytes());
        b.extend((size as u32).to_le_bytes());
        b.extend(1u32.to_le_bytes());
        b.extend((fo as u32).to_le_bytes());
        b.extend([0u8; 4]);
        ppt_rec(2, 6, 0xF007, &b)
    };
    let mut store = fbse(png_rec.len(), hidden.len());
    store.extend(fbse(meta_rec.len(), hidden.len() + png_rec.len()));
    let dgg = ppt_rec(0xF, 0, 0xF000, &ppt_rec(0xF, 2, 0xF001, &store));
    let doc = ppt_rec(0xF, 0, 0x03E8, &ppt_rec(0xF, 0, 0x040B, &dgg));
    let src = cfb(&[
        ("PowerPoint Document", &doc),
        ("Current User", &[0u8; 28]),
        ("Pictures", &pictures),
    ]);

    let r = Engine::default().process(&src, "a.ppt");
    assert_eq!(
        r.status,
        Status::Sanitized,
        "{} {:#?}",
        r.reason,
        r.findings
    );
    assert_cats(&r, &["hidden-data"]);
    let out = read_cfb(r.output.as_ref().unwrap());
    let pics = stream(&out, "Pictures").unwrap();
    let new_doc = stream(&out, "PowerPoint Document").unwrap();
    assert_eq!(new_doc.len(), doc.len());
    assert!(!contains(pics, b"HIDDEN-PAYLOAD") && !contains(pics, b"<?php"));

    // FBSE 가 새 위치·크기를 가리키고, 가리킨 곳의 PNG 가 정상 디코딩된다
    let fbse_at: Vec<usize> = new_doc
        .windows(4)
        .enumerate()
        .filter(|(_, w)| *w == [0x62, 0x00, 0x07, 0xF0])
        .map(|(i, _)| i + 8)
        .collect();
    assert_eq!(fbse_at.len(), 2);
    let field = |at: usize| u32::from_le_bytes(new_doc[at..at + 4].try_into().unwrap()) as usize;
    let (size, fo) = (field(fbse_at[0] + 20), field(fbse_at[0] + 28));
    assert_eq!(fo, 0);
    let rec = &pics[fo..fo + size];
    assert_eq!(&rec[2..4], &0xF01Eu16.to_le_bytes());
    image::load_from_memory(&rec[8 + 17..]).expect("재인코딩된 PNG");
    // 메타파일은 그대로, 새 위치로
    let (size, fo) = (field(fbse_at[1] + 20), field(fbse_at[1] + 28));
    assert_eq!(&pics[fo..fo + size], meta_rec.as_slice());
    assert_eq!(fo + size, pics.len());

    let again = Engine::default().process(r.output.as_ref().unwrap(), "a.ppt");
    assert_eq!(again.status, Status::Clean, "{:#?}", again.findings);
}

/// OfficeArt PNG 그림 레코드 (식별자 16 + 태그 1 + PNG)
fn png_blip(png: &[u8]) -> Vec<u8> {
    let mut body = vec![0xCD; 16];
    body.push(0xFF);
    body.extend(png);
    ppt_rec(0, 0x6E0, 0xF01E, &body)
}

#[test]
fn doc_and_xls_pictures_are_reencoded_in_place() {
    let png = common::png_with_payload();
    let blip = png_blip(&png);

    // doc: Data 스트림 안의 그림 (앞뒤에 다른 데이터)
    let mut data = b"PICF-HEADER-PLACEHOLDER".to_vec();
    data.extend(&blip);
    data.extend(b"TAIL");
    let mut streams = read_cfb(&malicious_doc(1 << 9));
    streams.push(("Data".into(), data.clone()));
    let refs: Vec<(&str, &[u8])> = streams
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    let r = Engine::default().process(&cfb(&refs), "a.doc");
    assert_ne!(r.status, Status::Blocked, "{}", r.reason);
    let out = read_cfb(r.output.as_ref().unwrap());
    let new_data = stream(&out, "Data").unwrap();
    assert_eq!(new_data.len(), data.len(), "길이(오프셋) 보존");
    assert!(new_data.starts_with(b"PICF-HEADER-PLACEHOLDER") && new_data.ends_with(b"TAIL"));
    assert!(!contains(new_data, b"<?php"));
    let img_at = 23 + 8 + 17;
    image::load_from_memory(&new_data[img_at..new_data.len() - 4]).expect("재인코딩된 PNG");

    // xls: 그리기 그룹 레코드 안의 그림은 재인코딩, 레코드 경계를 넘는 그림은 건드리지 않음
    let mut spanning = biff(0x00EB, &blip[..blip.len() / 2]);
    spanning.extend(biff(0x003C, &blip[blip.len() / 2..]));
    let src = xls(0, &[biff(0x00EB, &blip), spanning.clone()]);
    let r = neutralizing().process(&src, "a.xls");
    assert_eq!(r.status, Status::Sanitized, "{}", r.reason);
    let before = stream(&read_cfb(&src), "Workbook").unwrap().to_vec();
    let wb = stream(&read_cfb(r.output.as_ref().unwrap()), "Workbook")
        .unwrap()
        .to_vec();
    assert_eq!(wb.len(), before.len());
    let first = before.windows(4).position(|w| w == b"<?ph").unwrap();
    assert!(
        !contains(&wb[..first + 16], b"<?php"),
        "레코드 안의 그림은 재조합"
    );
    assert!(contains(&wb, &spanning), "경계를 넘는 그림은 원본 유지");
    assert_eq!(
        r.findings.iter().filter(|f| f.category == "image").count(),
        0
    );
}
