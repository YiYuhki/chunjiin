//! PDF 인라인 이미지(`BI … ID … EI`) 재조합.

mod common;

use cdr::{Engine, Status};
use common::pdf_inline::{inline_image_content, pdf_with_content};
use lopdf::Document;

/// 결과물 첫 쪽 콘텐츠의 인라인 이미지들: (머리 사전 문자열, 표본)
fn inline_images(pdf: &[u8]) -> (Vec<(String, Vec<u8>)>, Vec<u8>) {
    let doc = Document::load_mem(pdf).unwrap();
    let page = *doc.get_pages().values().next().unwrap();
    let content = doc.get_page_content(page);
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(i) = find(&content[at..], b"BI\n") {
        let start = at + i + 3;
        let id = start + find(&content[start..], b" ID\n").unwrap();
        let head = String::from_utf8_lossy(&content[start..id]).to_string();
        let num = |k: &str| -> usize {
            let p = head.find(&format!("/{k} ")).unwrap() + k.len() + 2;
            head[p..]
                .split_whitespace()
                .next()
                .unwrap()
                .parse()
                .unwrap()
        };
        let comps = if head.contains("/IM true") || head.contains("/DeviceGray") {
            1
        } else if head.contains("/DeviceCMYK") {
            4
        } else {
            3
        };
        let len = (num("W") * comps * num("BPC")).div_ceil(8) * num("H");
        let data = content[id + 4..id + 4 + len].to_vec();
        assert_eq!(
            &content[id + 4 + len..id + 4 + len + 3],
            b"\nEI",
            "표본 길이 불일치"
        );
        out.push((head, data));
        at = id + 4 + len;
    }
    (out, content)
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

#[test]
fn filtered_inline_images_are_decoded() {
    let c = inline_image_content();
    let rgb = [255u8, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 0];
    let r = Engine::default().process(&pdf_with_content(&c), "a.pdf");
    assert_eq!(
        r.status,
        Status::Sanitized,
        "{} {:#?}",
        r.reason,
        r.findings
    );
    assert_eq!(r.stats.get("pdf_inline_images"), Some(&5), "{:?}", r.stats);
    let out = r.output.clone().unwrap();
    let (images, content) = inline_images(&out);
    assert_eq!(images.len(), 5);
    assert!(images.iter().all(|(h, _)| !h.contains("/F")), "필터가 남음");
    // 1) 예측자까지 풀린 RGB
    assert!(images[0].0.contains("/DeviceRGB"));
    assert_eq!(images[0].1, rgb);
    // 2) 8x8 RGB 화소, 파란색
    assert_eq!(images[1].1.len(), 8 * 8 * 3);
    assert!(images[1].1.chunks(3).all(|p| p[2] > 200 && p[0] < 60));
    assert!(find(&out, b"<?php").is_none());
    // 3) 검정(0) 줄과 흰(1) 줄
    assert!(images[2].0.contains("/IM true"));
    assert_eq!(images[2].1, [0, 0, 0xFF, 0xFF, 0, 0, 0xFF, 0xFF]);
    // 4) 1 → 파랑, 0 → 빨강
    assert!(images[3].0.contains("/DeviceRGB") && images[3].0.contains("/BPC 8"));
    let expect: Vec<u8> = (0..8)
        .flat_map(|x| if x % 2 == 0 { [0, 0, 255] } else { [255, 0, 0] })
        .collect();
    assert_eq!(images[3].1, expect);
    // 5) 표본 그대로
    assert_eq!(images[4].1, b" \n\r\x00");
    // 6) JBIG2 는 빠지고 뒤의 선은 남는다
    assert!(find(&content, b"99 99 l").is_some());
    assert!(r
        .findings
        .iter()
        .any(|f| f.description.contains("인라인 이미지")));

    let again = Engine::default().process(&out, "a.pdf");
    assert_eq!(again.status, Status::Clean, "{:#?}", again.findings);
    assert_eq!(again.stats.get("pdf_inline_images"), Some(&5));
}

#[test]
fn inline_image_limits() {
    // 선언 크기가 화소 한도를 넘으면 빼고, 필터 없는 데이터가 모자라면 뺀다
    let c = b"BI /W 100000 /H 100000 /BPC 8 /CS /G ID xx\nEI 0 0 m 1 1 l S\nBI /W 10 /H 10 /BPC 8 /CS /G ID short\nEI 2 2 m 3 3 l S";
    let r = Engine::default().process(&pdf_with_content(c), "a.pdf");
    assert_ne!(r.status, Status::Blocked, "{}", r.reason);
    let (images, content) = inline_images(r.output.as_ref().unwrap());
    assert!(images.is_empty());
    assert!(find(&content, b"1 1 l").is_some() && find(&content, b"3 3 l").is_some());
}
