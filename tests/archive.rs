//! 일반 ZIP 압축 파일과 단독 이미지 재조합

mod common;

use cdr::{CdrResult, Engine, Policy, Status};
use common::*;

fn names(zip: &[u8]) -> Vec<String> {
    let mut v: Vec<String> = unzip(zip).into_iter().map(|(n, _)| n).collect();
    v.sort();
    v
}

fn member<'a>(parts: &'a [(String, Vec<u8>)], name: &str) -> &'a [u8] {
    &parts
        .iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("항목 없음: {name}"))
        .1
}

fn archive_findings(r: &CdrResult) -> Vec<String> {
    r.findings
        .iter()
        .filter(|f| f.category == "archive-member")
        .map(|f| format!("{} {}", f.location, f.description))
        .collect()
}

#[test]
fn archive_members_are_reassembled_and_bad_ones_dropped() {
    let inner = make_zip(&[("nested/report.pdf", &malicious_pdf())]);
    let src = make_zip(&[
        ("docs/보고서.docm", &malicious_docm()),
        ("img/photo.png", &png_with_payload()),
        ("tools/setup.exe", b"MZ\x90\x00 not allowed"),
        ("clean.pdf", &clean_pdf()),
        ("inner.zip", &inner),
    ]);
    let r = Engine::default().process(&src, "첨부.zip");
    assert_eq!(
        r.status,
        Status::Sanitized,
        "{} {:#?}",
        r.reason,
        r.findings
    );
    assert_eq!(r.output_filename.as_deref(), Some("첨부.zip"));
    let out = r.output.as_ref().unwrap();
    assert_eq!(
        names(out),
        vec![
            "clean.pdf",
            "docs/보고서.docx",
            "img/photo.png",
            "inner.zip"
        ]
    );
    let dropped = archive_findings(&r);
    assert_eq!(dropped.len(), 1, "{dropped:?}");
    assert!(dropped[0].starts_with("tools/setup.exe"), "{dropped:?}");
    // 항목의 탐지 내용이 위치와 함께 올라온다
    assert!(r
        .findings
        .iter()
        .any(|f| f.category == "macro" && f.location.starts_with("docs/보고서.docm")));

    let parts = unzip(out);
    assert!(!member(&parts, "img/photo.png")
        .windows(5)
        .any(|w| w == b"<?php"));
    let nested = unzip(member(&parts, "inner.zip"));
    assert_eq!(nested.len(), 1);
    assert!(!nested[0].1.windows(10).any(|w| w == b"JavaScript"));

    // 재조합 결과를 다시 넣으면 더 제거할 것이 없다
    let again = Engine::default().process(out, "첨부.zip");
    assert_ne!(again.status, Status::Blocked, "{}", again.reason);
    assert!(archive_findings(&again).is_empty());
}

#[test]
fn strict_mode_blocks_whole_archive() {
    let src = make_zip(&[("a.pdf", &clean_pdf()), ("b.exe", b"MZ\x90\x00")]);
    let strict = Engine::new(Policy {
        strict_archives: true,
        ..Policy::default()
    });
    let r = strict.process(&src, "a.zip");
    assert_eq!(r.status, Status::Blocked);
    assert!(r.reason.contains("b.exe"), "{}", r.reason);
    let disabled = Engine::new(Policy {
        allow_archives: false,
        ..Policy::default()
    });
    assert_eq!(disabled.process(&src, "a.zip").status, Status::Blocked);
}

#[test]
fn nesting_depth_and_budget_are_enforced() {
    // 압축 안의 압축 안의 압축: 가장 안쪽은 제외
    let deepest = make_zip(&[("x.pdf", &clean_pdf())]);
    let middle = make_zip(&[("deep.zip", &deepest), ("m.pdf", &clean_pdf())]);
    let outer = make_zip(&[("middle.zip", &middle)]);
    let r = Engine::default().process(&outer, "o.zip");
    assert_eq!(r.status, Status::Sanitized, "{}", r.reason);
    let parts = unzip(r.output.as_ref().unwrap());
    assert_eq!(names(member(&parts, "middle.zip")), vec!["m.pdf"]);
    assert!(archive_findings(&r).iter().any(|f| f.contains("deep.zip")));

    // 중첩 압축의 해제량은 바깥 압축의 남은 예산 안에서만 허용
    let mut x = 0x1234_5678_9ABC_DEF0u64;
    let noise: Vec<u8> = (0..3 * 1024 * 1024)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    let inner = make_zip(&[("a.pdf", &clean_pdf()), ("big.bin", &noise)]);
    let outer = make_zip(&[("inner.zip", &inner), ("ok.pdf", &clean_pdf())]);
    let small = Engine::new(Policy {
        max_zip_total: 4 * 1024 * 1024,
        ..Policy::default()
    });
    let r = small.process(&outer, "o.zip");
    let dropped = archive_findings(&r);
    assert!(
        r.status == Status::Blocked
            || dropped
                .iter()
                .any(|f| f.contains("inner.zip") && f.contains("총량")),
        "{} {dropped:?}",
        r.reason
    );
}

#[test]
fn standalone_images_are_reencoded() {
    let r = Engine::default().process(&png_with_payload(), "사진.png");
    assert_eq!(r.status, Status::Clean, "{:#?}", r.findings);
    let out = r.output.unwrap();
    assert!(!out.windows(5).any(|w| w == b"<?php"));
    image::load_from_memory(&out).unwrap();

    // BMP 는 PNG 로, 확장자 위장은 교정
    let mut bmp = Vec::new();
    image::RgbImage::from_pixel(3, 3, image::Rgb([1, 2, 3]))
        .write_to(&mut std::io::Cursor::new(&mut bmp), image::ImageFormat::Bmp)
        .unwrap();
    let r = Engine::default().process(&bmp, "그림.jpg");
    assert_ne!(r.status, Status::Blocked, "{}", r.reason);
    assert_eq!(r.output_filename.as_deref(), Some("그림.png"));
    assert!(r.findings.iter().any(|f| f.category == "type-mismatch"));

    let off = Engine::new(Policy {
        allow_images: false,
        ..Policy::default()
    });
    assert_eq!(
        off.process(&png_with_payload(), "a.png").status,
        Status::Blocked
    );
}
