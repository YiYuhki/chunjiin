//! PDF 인라인 이미지(`BI … ID … EI`) 재조합.

mod common;

use cdr::{Engine, Status};
use common::pdf_inline::{inline_image_content, pdf_with_content};
use lopdf::{Document, Stream};

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
        let comps = if head.contains("/IM true")
            || head.contains("/DeviceGray")
            || head.contains("/CS0")
            || head.contains("/Sep0")
        {
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
    assert_eq!(r.stats.get("pdf_inline_images"), Some(&7), "{:?}", r.stats);
    let out = r.output.clone().unwrap();
    let (images, content) = inline_images(&out);
    assert_eq!(images.len(), 7);
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
    // 7) 리소스 색 공간은 이름을 유지하고 표본을 그대로
    assert!(images[5].0.contains("/CS /CS0") && images[5].0.contains("/BPC 1"));
    assert_eq!(images[5].1, [0xA5]);
    assert!(images[6].0.contains("/CS /Sep0"));
    assert_eq!(images[6].1, [0x40, 0xC0]);
    assert!(r
        .findings
        .iter()
        .any(|f| f.description.contains("인라인 이미지")));

    let again = Engine::default().process(&out, "a.pdf");
    assert_eq!(again.status, Status::Clean, "{:#?}", again.findings);
    assert_eq!(again.stats.get("pdf_inline_images"), Some(&7));
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

/// 이미지 XObject 하나를 그리는 PDF
fn pdf_with_image(image: Stream) -> Vec<u8> {
    use lopdf::dictionary;
    let mut doc = Document::with_version("1.7");
    let pages_id = doc.new_object_id();
    let img_id = doc.add_object(image);
    let content_id = doc.add_object(Stream::new(
        dictionary! {},
        b"q 100 0 0 100 10 10 cm /Im0 Do Q".to_vec(),
    ));
    let page = doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "Contents" => content_id,
        "Resources" => dictionary! { "XObject" => dictionary! { "Im0" => img_id } },
    });
    doc.objects.insert(
        pages_id,
        lopdf::Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => vec![page.into()], "Count" => 1,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        }),
    );
    let catalog = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    doc.trailer.set("Root", catalog);
    let mut out = Vec::new();
    doc.save_to(&mut out).unwrap();
    out
}

fn output_image(pdf: &[u8]) -> Stream {
    let doc = Document::load_mem(pdf).unwrap();
    doc.objects
        .values()
        .find_map(|o| match o {
            lopdf::Object::Stream(s)
                if s.dict.get(b"Subtype").and_then(|v| v.as_name()).ok() == Some(b"Image") =>
            {
                Some(s.clone())
            }
            _ => None,
        })
        .expect("이미지 없음")
}

#[test]
fn image_xobject_codecs_are_reencoded() {
    use lopdf::dictionary;
    // JPEG: 뒤에 덧붙은 데이터가 사라지고 JPEG 으로 다시 압축된다
    let img = image::RgbImage::from_pixel(16, 8, image::Rgb([10, 200, 30]));
    let mut jpeg = std::io::Cursor::new(Vec::new());
    img.write_to(&mut jpeg, image::ImageFormat::Jpeg).unwrap();
    let mut data = jpeg.into_inner();
    data.extend(b"<?php system($_GET[c]); ?>");
    let s = Stream::new(
        dictionary! {
            "Type" => "XObject", "Subtype" => "Image", "Width" => 16, "Height" => 8,
            "ColorSpace" => "DeviceRGB", "BitsPerComponent" => 8, "Filter" => "DCTDecode",
        },
        data,
    );
    let r = Engine::default().process(&pdf_with_image(s), "a.pdf");
    assert_ne!(r.status, Status::Blocked, "{}", r.reason);
    let out = r.output.unwrap();
    assert!(find(&out, b"<?php").is_none());
    let img = output_image(&out);
    assert_eq!(
        img.dict.get(b"Filter").unwrap().as_name().unwrap(),
        b"DCTDecode"
    );
    let px = image::load_from_memory(&img.content).unwrap().to_rgb8();
    assert_eq!((px.width(), px.height()), (16, 8));
    assert!(px.pixels().all(|p| p[1] > 150 && p[0] < 60));
    assert_eq!(r.stats.get("pdf_images_reencoded"), Some(&1));

    // CCITT G3 1차원(EOL 없음, PDF 기본값): 1비트 표본으로 풀린다
    let mut bits = String::new();
    for _ in 0..2 {
        bits += "1000"; // 흰 3
        bits += "11"; // 검정 2
        bits += "1000"; // 흰 3
    }
    while !bits.len().is_multiple_of(8) {
        bits.push('0');
    }
    let fax: Vec<u8> = bits
        .as_bytes()
        .chunks(8)
        .map(|c| c.iter().fold(0u8, |a, &b| (a << 1) | (b - b'0')))
        .collect();
    let s = Stream::new(
        dictionary! {
            "Type" => "XObject", "Subtype" => "Image", "Width" => 8, "Height" => 2,
            "ImageMask" => true, "Filter" => "CCITTFaxDecode",
            "DecodeParms" => dictionary! { "K" => 0, "Columns" => 8 },
        },
        fax,
    );
    let r = Engine::default().process(&pdf_with_image(s), "b.pdf");
    assert_ne!(r.status, Status::Blocked, "{}", r.reason);
    let img = output_image(r.output.as_ref().unwrap());
    let plain = img.get_plain_content().unwrap();
    assert!(img.dict.get(b"Filter").ok().and_then(|f| f.as_name().ok()) != Some(b"CCITTFaxDecode"));
    assert_eq!(plain, [0b1110_0111, 0b1110_0111]);
    let again = Engine::default().process(r.output.as_ref().unwrap(), "b.pdf");
    assert_eq!(again.status, Status::Clean, "{:#?}", again.findings);
}
