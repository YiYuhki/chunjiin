//! PDF 인라인 이미지(`BI … ID … EI`) 재조합.

mod common;

use cdr::{Engine, Status};
use common::pdf_inline::{
    inline_image_content, jbig2_parts, jbig2_text_parts, pdf_with_content, unhex, JPX_RGB, JPX_RGBA,
};
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

/// 이미지 표본. CCITT G4 로 다시 압축된 1비트 이미지는 풀어서 (검정 = 0)
fn samples(img: &Stream) -> Vec<u8> {
    if img.dict.get(b"Filter").ok().and_then(|f| f.as_name().ok()) != Some(b"CCITTFaxDecode") {
        return img.get_plain_content().unwrap();
    }
    let int = |k: &[u8]| img.dict.get(k).unwrap().as_i64().unwrap() as u32;
    let (w, h) = (int(b"Width"), int(b"Height"));
    let stride = w.div_ceil(8) as usize;
    let mut out = Vec::new();
    fax::decoder::decode_g4(img.content.iter().copied(), w, Some(h), |t| {
        let mut row = vec![0xFFu8; stride];
        let mut black = false;
        let mut x = 0u32;
        for &p in t.iter().chain(std::iter::once(&w)) {
            if black {
                for k in x..p.min(w) {
                    row[k as usize / 8] &= !(0x80 >> (k % 8));
                }
            }
            x = p;
            black = !black;
        }
        out.extend(row);
    })
    .unwrap();
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
    // 직접 다시 압축한 G4 (원본 G3 데이터가 아님)
    assert_eq!(
        img.dict
            .get(b"DecodeParms")
            .unwrap()
            .as_dict()
            .unwrap()
            .get(b"K")
            .unwrap()
            .as_i64()
            .unwrap(),
        -1
    );
    assert_eq!(samples(&img), [0b1110_0111, 0b1110_0111]);
    let again = Engine::default().process(r.output.as_ref().unwrap(), "b.pdf");
    assert_eq!(again.status, Status::Clean, "{:#?}", again.findings);
}

/// Pillow 로 만든 8x4 CMYK JPEG (Adobe 표식)
const CMYK_JPEG_HEX: &str = "ffd8ffee000e41646f626500640000000000ffdb0043000201010101010201010102020202020403020202020504040304060506060605060606070908060709070606080b08090a0a0a0a0a06080b0c0b0a0c090a0a0affc000140800040008044311004d11005911004b1100ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffda000e0443004d0059004b00003f00fdfcafcdbafe7febf752bfffd9";

#[test]
fn cmyk_jpeg_becomes_raw_cmyk() {
    use lopdf::dictionary;
    let jpeg: Vec<u8> = (0..CMYK_JPEG_HEX.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&CMYK_JPEG_HEX[i..i + 2], 16).unwrap())
        .collect();
    let mut data = jpeg.clone();
    data.extend(b"<?php system($_GET[c]); ?>");
    let s = Stream::new(
        dictionary! {
            "Type" => "XObject", "Subtype" => "Image", "Width" => 8, "Height" => 4,
            "ColorSpace" => "DeviceCMYK", "BitsPerComponent" => 8, "Filter" => "DCTDecode",
        },
        data,
    );
    let r = Engine::default().process(&pdf_with_image(s), "c.pdf");
    assert_ne!(r.status, Status::Blocked, "{}", r.reason);
    let out = r.output.clone().unwrap();
    assert!(find(&out, b"<?php").is_none());
    let img = output_image(&out);
    assert!(img.dict.get(b"Filter").ok().and_then(|f| f.as_name().ok()) != Some(b"DCTDecode"));
    let px = img.get_plain_content().unwrap();
    assert_eq!(px.len(), 8 * 4 * 4);
    let again = Engine::default().process(&out, "c.pdf");
    assert_eq!(again.status, Status::Clean, "{:#?}", again.findings);
}

#[test]
fn jbig2_and_jpx_images_are_decoded() {
    use lopdf::dictionary;
    // JBIG2 XObject: 1비트 표본(검정 = 0)으로
    let (info, body, bits) = jbig2_parts(20, 6);
    let s = Stream::new(
        dictionary! {
            "Type" => "XObject", "Subtype" => "Image", "Width" => 20, "Height" => 6,
            "ColorSpace" => "DeviceGray", "BitsPerComponent" => 1, "Filter" => "JBIG2Decode",
        },
        [info.clone(), body.clone()].concat(),
    )
    .with_compression(false);
    let r = Engine::default().process(&pdf_with_image(s), "a.pdf");
    assert_ne!(r.status, Status::Blocked, "{} {:#?}", r.reason, r.findings);
    let img = output_image(r.output.as_ref().unwrap());
    assert!(img.dict.get(b"Filter").ok().and_then(|f| f.as_name().ok()) != Some(b"JBIG2Decode"));
    assert_eq!(samples(&img), bits);
    assert_eq!(r.stats.get("pdf_images_reencoded"), Some(&1));
    let again = Engine::default().process(r.output.as_ref().unwrap(), "a.pdf");
    assert_eq!(again.status, Status::Clean, "{:#?}", again.findings);

    // 공유 기호 사전(JBIG2Globals)에 든 세그먼트도 함께 푼다
    let mut doc = Document::with_version("1.7");
    let globals = doc.add_object(Stream::new(dictionary! {}, info));
    let s = Stream::new(
        dictionary! {
            "Type" => "XObject", "Subtype" => "Image", "Width" => 20, "Height" => 6,
            "ImageMask" => true, "Filter" => vec!["FlateDecode".into(), "JBIG2Decode".into()],
            "DecodeParms" => vec![lopdf::Object::Null, dictionary! { "JBIG2Globals" => globals }.into()],
        },
        {
            use std::io::Write;
            let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            z.write_all(&body).unwrap();
            z.finish().unwrap()
        },
    )
    .with_compression(false);
    let pdf = pdf_with_image_in(doc, s);
    let r = Engine::default().process(&pdf, "b.pdf");
    assert_ne!(r.status, Status::Blocked, "{} {:#?}", r.reason, r.findings);
    let img = output_image(r.output.as_ref().unwrap());
    assert_eq!(
        img.get_plain_content().unwrap(),
        bits,
        "{:?} {:#?}",
        img.dict,
        r.findings
    );
    assert!(img.dict.get(b"DecodeParms").is_err());

    // 큰 흑백 이미지: G4 와 Flate 중 작은 쪽으로 다시 압축한다
    let (info, body, bits) = jbig2_text_parts(400, 300);
    let s = Stream::new(
        dictionary! {
            "Type" => "XObject", "Subtype" => "Image", "Width" => 400, "Height" => 300,
            "ImageMask" => true, "Filter" => "JBIG2Decode",
        },
        [info, body].concat(),
    )
    .with_compression(false);
    let r = Engine::default().process(&pdf_with_image(s), "g.pdf");
    let img = output_image(r.output.as_ref().unwrap());
    assert_eq!(samples(&img), bits);
    let flate = {
        use std::io::Write;
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(&bits).unwrap();
        z.finish().unwrap().len()
    };
    assert!(
        img.content.len() <= flate,
        "{} > {flate}",
        img.content.len()
    );
    let again = Engine::default().process(r.output.as_ref().unwrap(), "g.pdf");
    assert_eq!(again.status, Status::Clean, "{:#?}", again.findings);
    let third = Engine::default().process(again.output.as_ref().unwrap(), "g.pdf");
    assert_eq!(third.output, again.output, "고정점");

    // JPX XObject (색 공간 없음, Decode 는 JPX 에서 무시되므로 뺌) → 8비트 DeviceRGB
    let s = Stream::new(
        dictionary! {
            "Type" => "XObject", "Subtype" => "Image", "Width" => 8, "Height" => 6,
            "Filter" => "JPXDecode", "Decode" => vec![1.into(), 0.into(), 1.into(), 0.into(), 1.into(), 0.into()],
        },
        unhex(JPX_RGB),
    )
    .with_compression(false);
    let r = Engine::default().process(&pdf_with_image(s), "c.pdf");
    assert_ne!(r.status, Status::Blocked, "{} {:#?}", r.reason, r.findings);
    let img = output_image(r.output.as_ref().unwrap());
    assert_eq!(
        img.dict.get(b"ColorSpace").unwrap().as_name().unwrap(),
        b"DeviceRGB"
    );
    assert!(img.dict.get(b"Decode").is_err());
    let expect: Vec<u8> = (0..6)
        .flat_map(|y| {
            (0..8).flat_map(move |x| [30 * x, 40 * y, if (x + y) % 2 == 1 { 200 } else { 20 }])
        })
        .collect();
    assert_eq!(img.get_plain_content().unwrap(), expect);
    let again = Engine::default().process(r.output.as_ref().unwrap(), "c.pdf");
    assert_eq!(again.status, Status::Clean, "{:#?}", again.findings);

    // 알파가 있는 JPX + SMaskInData → 소프트 마스크
    let s = Stream::new(
        dictionary! {
            "Type" => "XObject", "Subtype" => "Image", "Width" => 4, "Height" => 4,
            "ColorSpace" => "DeviceRGB", "Filter" => "JPXDecode", "SMaskInData" => 1,
        },
        unhex(JPX_RGBA),
    )
    .with_compression(false);
    let r = Engine::default().process(&pdf_with_image(s), "d.pdf");
    assert_ne!(r.status, Status::Blocked, "{} {:#?}", r.reason, r.findings);
    let doc = Document::load_mem(r.output.as_ref().unwrap()).unwrap();
    let img = doc
        .objects
        .values()
        .find_map(|o| o.as_stream().ok().filter(|s| s.dict.get(b"SMask").is_ok()))
        .expect("SMask 가 붙은 이미지");
    let mut rgb = [0, 0, 255].repeat(4);
    rgb.extend([255, 0, 0].repeat(12));
    assert_eq!(img.get_plain_content().unwrap(), rgb);
    let mask = doc
        .get_object(img.dict.get(b"SMask").unwrap().as_reference().unwrap())
        .unwrap()
        .as_stream()
        .unwrap();
    let mut alpha = vec![0u8, 64, 128, 192];
    alpha.extend([255].repeat(12));
    assert_eq!(mask.get_plain_content().unwrap(), alpha);
    assert!(img.dict.get(b"SMaskInData").is_err());

    // 인라인 JBIG2·JPX
    let (info, body, bits) = jbig2_parts(20, 6);
    let mut c = b"q BI /W 20 /H 6 /IM true /F /JBIG2Decode ID ".to_vec();
    c.extend([info, body].concat());
    c.extend(b"\nEI Q q BI /W 8 /H 6 /F /JPXDecode ID ");
    c.extend(unhex(JPX_RGB));
    c.extend(b"\nEI Q 0 0 m 9 9 l S");
    let r = Engine::default().process(&pdf_with_content(&c), "e.pdf");
    assert_ne!(r.status, Status::Blocked, "{} {:#?}", r.reason, r.findings);
    let (images, content) = inline_images(r.output.as_ref().unwrap());
    assert_eq!(images.len(), 2, "{:?}", String::from_utf8_lossy(&content));
    assert!(images[0].0.contains("/IM true"));
    assert_eq!(images[0].1, bits);
    assert!(images[1].0.contains("/DeviceRGB") && images[1].0.contains("/BPC 8"));
    assert_eq!(images[1].1, expect);
    assert!(!images.iter().any(|(h, _)| h.contains("/F")));

    // 풀 수 없는 JBIG2 는 뺀다
    let s = Stream::new(
        dictionary! {
            "Type" => "XObject", "Subtype" => "Image", "Width" => 8, "Height" => 8,
            "ImageMask" => true, "Filter" => "JBIG2Decode",
        },
        b"\x97JB2 exploit".to_vec(),
    )
    .with_compression(false);
    let r = Engine::default().process(&pdf_with_image(s), "f.pdf");
    assert!(find(r.output.as_ref().unwrap(), b"exploit").is_none());
    assert!(
        r.findings.iter().any(|f| f.description.contains("JBIG2")),
        "{:#?}",
        r.findings
    );
}

fn pdf_with_image_in(mut doc: Document, image: Stream) -> Vec<u8> {
    use lopdf::dictionary;
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

/// 16×16 YCCK(Adobe 변환 2) JPEG, 양자화 1. 복원 CMYK (x, y) = (15x, 15y, 8(x+y), xy) (256 으로 나눈 나머지)
const YCCK_JPEG: &str = "ffd8ffee000e41646f626500640000000002ffdb00430001010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101ffc00014080010001004011100021100031100041100ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffda000e040100020003000400003f00fe947e317ed63ff1f5ff00133fefff00cb6fafbd51d6f4dfbff2faf6a77c7df803ff001fbfe85ff3d3fe59fd7dabf861f87ff0ff00fe12af23f71e6799b7f873d71ed5f94bf18bf6b1ff008faff899ff007ffe5b7d7debc875bd37effcbebdabf127e3efc01ff8fdff0042ff009e9ff2cfebed5f707c3ffd8b7fe12af23fe253e6799b7fe5867ae3fd9afcebf8c5fb58ff00c7d7fc4cff00bfff002dbebef5f4e6b7a6fdff0097d7b57f6e5f1f7e00ff00c7effa17fcf4ff00967f5f6a3f62df87ff00f0957f64fee3ccf33c8fe1cf5dbed5f94df18bf6b1ff008faff899ff007ffe5b7d7debc875bd37effcbebdabf123e3efc01ff8fdff0042ff009e9ff2cfebed5fd707ec5bfb16ff00c255fd93ff00129f33ccf23fe5867aedff0066bfffd9";

#[test]
fn ycck_jpeg_becomes_raw_cmyk() {
    use lopdf::dictionary;
    let s = Stream::new(
        dictionary! {
            "Type" => "XObject", "Subtype" => "Image", "Width" => 16, "Height" => 16,
            "ColorSpace" => "DeviceCMYK", "BitsPerComponent" => 8, "Filter" => "DCTDecode",
        },
        unhex(YCCK_JPEG),
    )
    .with_compression(false);
    let r = Engine::default().process(&pdf_with_image(s), "y.pdf");
    assert_ne!(r.status, Status::Blocked, "{}", r.reason);
    assert_eq!(
        r.stats.get("pdf_images_reencoded"),
        Some(&1),
        "{:?}",
        r.stats
    );
    let img = output_image(r.output.as_ref().unwrap());
    assert!(img.dict.get(b"Filter").ok().and_then(|f| f.as_name().ok()) != Some(b"DCTDecode"));
    let px = img.get_plain_content().unwrap();
    assert_eq!(px.len(), 16 * 16 * 4);
    for y in 0..16u32 {
        for x in 0..16u32 {
            let want = [
                (x * 15) % 256,
                (y * 15) % 256,
                ((x + y) * 8) % 256,
                (x * y) % 256,
            ];
            let at = ((y * 16 + x) * 4) as usize;
            for k in 0..4 {
                let got = i32::from(px[at + k]);
                assert!(
                    (got - want[k] as i32).abs() <= 3,
                    "({x},{y}) {k}: {got} != {}",
                    want[k]
                );
            }
        }
    }
}

/// 4×2 RGB JP2 (colr 상자에 sRGB ICC 프로필). 화소 (x, y) = (60x, 100y, 200)
const JPX_ICC: &str = "0000000c6a5020200d0a870a00000014667479706a703220000000006a703220000002756a7032680000001669686472000000020000000400030707000000000257636f6c720200000000024c6c636d73044000006d6e74725247422058595a2007ea0009001b0009000d0003616373704150504c0000000000000000000000000000000000000000000000000000f6d6000100000000d32d6c636d7300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b64657363000001080000003663707274000001400000004c777470740000018c0000001463686164000001a00000002c7258595a000001cc000000146258595a000001e0000000146758595a000001f4000000147254524300000208000000206754524300000208000000206254524300000208000000206368726d00000228000000246d6c756300000000000000010000000c656e55530000001a0000001c00730052004700420020006200750069006c0074002d0069006e00006d6c756300000000000000010000000c656e5553000000300000001c004e006f00200063006f0070007900720069006700680074002c002000750073006500200066007200650065006c007958595a20000000000000f6d6000100000000d32d736633320000000000010c42000005defffff325000007930000fd90fffffba1fffffda2000003dc0000c06e58595a200000000000006fa0000038f50000039058595a20000000000000249f00000f840000b6c358595a2000000000000062970000b787000018d9706172610000000000030000000266660000f2a700000d59000013d000000a5b6368726d00000000000300000000a3d70000547b00004ccd0000999a0000266600000f5c000000aa6a703263ff4fff51002f000000000004000000020000000000000000000000040000000200000000000000000003070101070101070101ff52000c00000001000104040001ff5c00074040484850ff640025000143726561746564206279204f70656e4a5045472076657273696f6e20322e352e34ff90000a00000000002f0001ff93df80180771bfcfb40c091fefcfb40c02659fc3ea03000b137fa3ed030001c79f80ffd9";

#[test]
fn jpx_icc_profile_becomes_iccbased() {
    use lopdf::dictionary;
    let s = Stream::new(
        dictionary! {
            "Type" => "XObject", "Subtype" => "Image", "Width" => 4, "Height" => 2,
            "Filter" => "JPXDecode",
        },
        unhex(JPX_ICC),
    )
    .with_compression(false);
    let r = Engine::default().process(&pdf_with_image(s), "icc.pdf");
    assert_ne!(r.status, Status::Blocked, "{}", r.reason);
    let doc = Document::load_mem(r.output.as_ref().unwrap()).unwrap();
    let img = output_image(r.output.as_ref().unwrap());
    let cs = img.dict.get(b"ColorSpace").unwrap().as_array().unwrap();
    assert_eq!(cs[0].as_name().unwrap(), b"ICCBased");
    let icc = doc
        .get_object(cs[1].as_reference().unwrap())
        .unwrap()
        .as_stream()
        .unwrap();
    assert_eq!(icc.dict.get(b"N").unwrap().as_i64().unwrap(), 3);
    assert_eq!(&icc.get_plain_content().unwrap()[36..40], b"acsp");
    let expect: Vec<u8> = (0..2)
        .flat_map(|y| (0..4).flat_map(move |x| [60 * x, 100 * y, 200]))
        .collect();
    assert_eq!(samples(&img), expect);
    let again = Engine::default().process(r.output.as_ref().unwrap(), "icc.pdf");
    assert_eq!(again.status, Status::Clean, "{:#?}", again.findings);
}

/// 16×8 단색(40, 160, 220) 손실(9-7) JPEG 2000 코드스트림
const JPX_LOSSY: &str = "ff4fff51002f000000000010000000080000000000000000000000100000000800000000000000000003070101070101070101ff52000c00000001000304040000ff5c001742673867506750676850055005504757d357d35762ff640025000143726561746564206279204f70656e4a5045472076657273696f6e20322e352e34ff90000a0000000000290001ff93c7ec06090958c3f303027943c7ec0601d46b808080808080808080ffd9";

#[test]
fn lossy_jpx_becomes_jpeg() {
    use lopdf::dictionary;
    let s = Stream::new(
        dictionary! {
            "Type" => "XObject", "Subtype" => "Image", "Width" => 16, "Height" => 8,
            "ColorSpace" => "DeviceRGB", "Filter" => "JPXDecode",
        },
        unhex(JPX_LOSSY),
    )
    .with_compression(false);
    let r = Engine::default().process(&pdf_with_image(s), "l.pdf");
    assert_ne!(r.status, Status::Blocked, "{}", r.reason);
    let img = output_image(r.output.as_ref().unwrap());
    assert_eq!(
        img.dict.get(b"Filter").unwrap().as_name().unwrap(),
        b"DCTDecode"
    );
    let px = image::load_from_memory(&img.content).unwrap().to_rgb8();
    assert_eq!((px.width(), px.height()), (16, 8));
    assert!(px.pixels().all(|p| (i32::from(p[0]) - 40).abs() < 8
        && (i32::from(p[1]) - 160).abs() < 8
        && (i32::from(p[2]) - 220).abs() < 8));
    let again = Engine::default().process(r.output.as_ref().unwrap(), "l.pdf");
    assert_eq!(again.status, Status::Clean, "{:#?}", again.findings);
}
