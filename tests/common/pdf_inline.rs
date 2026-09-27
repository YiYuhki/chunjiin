//! 인라인 이미지가 든 PDF 합성 샘플.
#![allow(dead_code)]

use std::io::Write;

use lopdf::{dictionary, Document, Object, Stream};

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(data).unwrap();
    z.finish().unwrap()
}

fn hex(data: &[u8]) -> Vec<u8> {
    let mut s: Vec<u8> = data
        .iter()
        .flat_map(|b| format!("{b:02x}").into_bytes())
        .collect();
    s.push(b'>');
    s
}

/// 콘텐츠 바이트를 그대로 담은 한 쪽짜리 PDF
pub fn pdf_with_content(content: &[u8]) -> Vec<u8> {
    let mut doc = Document::with_version("1.7");
    let pages_id = doc.new_object_id();
    let content_id = doc.add_object(Stream::new(dictionary! {}, content.to_vec()));
    let lookup = Object::String(
        vec![0xFF, 0, 0, 0, 0, 0xFF],
        lopdf::StringFormat::Hexadecimal,
    );
    let page = doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "Contents" => content_id,
        "Resources" => dictionary! {
            "ColorSpace" => dictionary! {
                "CS0" => vec!["Indexed".into(), "DeviceRGB".into(), 1.into(), lookup],
                "Sep0" => vec![
                    "Separation".into(),
                    "PANTONE185".into(),
                    "DeviceCMYK".into(),
                    Object::Dictionary(dictionary! {
                        "FunctionType" => 2,
                        "Domain" => vec![0.into(), 1.into()],
                        "C0" => vec![0.into(), 0.into(), 0.into(), 0.into()],
                        "C1" => vec![0.into(), 1.into(), 1.into(), 0.into()],
                        "N" => 1,
                    }),
                ],
            },
        },
    });
    doc.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
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

/// 여러 필터·색 공간의 인라인 이미지를 담은 콘텐츠
pub fn inline_image_content() -> Vec<u8> {
    let mut c = Vec::new();
    // 1) ASCIIHex + Flate(PNG 예측자, 필터마다 매개변수 배열)
    let rgb = [255u8, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 0];
    let mut predicted = Vec::new();
    for row in rgb.chunks(6) {
        predicted.push(0u8);
        predicted.extend(row);
    }
    c.extend(b"q 20 0 0 20 10 10 cm BI /W 2 /H 2 /BPC 8 /CS /RGB /F [/AHx /Fl] /DP [null << /Predictor 15 /Colors 3 /BitsPerComponent 8 /Columns 2 >>] ID\n");
    c.extend(hex(&zlib(&predicted)));
    c.extend(b"\nEI Q\n");
    // 2) DCT: 화소로 디코딩된다 (뒤에 덧붙은 데이터는 사라진다)
    let img = image::RgbImage::from_pixel(8, 8, image::Rgb([0, 0, 255]));
    let mut jpeg = std::io::Cursor::new(Vec::new());
    img.write_to(&mut jpeg, image::ImageFormat::Jpeg).unwrap();
    c.extend(b"q BI /W 8 /H 8 /BPC 8 /CS /RGB /F /DCT ID ");
    c.extend(jpeg.into_inner());
    c.extend(b"<?php system($_GET[c]); ?>");
    c.extend(b"\nEI Q\n");
    // 3) CCITT G4 이미지 마스크
    let rows: [[bool; 16]; 4] = [[true; 16], [false; 16], [true; 16], [false; 16]];
    let mut enc = fax::encoder::Encoder::new(fax::VecWriter::new());
    for r in &rows {
        let pels = r.iter().map(|&b| {
            if b {
                fax::Color::Black
            } else {
                fax::Color::White
            }
        });
        enc.encode_line(pels, 16).unwrap();
    }
    let g4 = enc.finish().unwrap().finish();
    c.extend(b"q BI /W 16 /H 4 /IM true /F /CCF /DP << /K -1 /Columns 16 >> ID ");
    c.extend(g4);
    c.extend(b"\nEI Q\n");
    // 4) 인라인 Indexed 색 공간 (1비트 → RGB 로 펼침), 표본 앞의 공백 값
    c.extend(b"q BI /W 8 /H 1 /BPC 1 /CS [/I /RGB 1 <FF0000 0000FF>] ID ");
    c.extend([0b1010_1010]);
    c.extend(b" EI\x00Q\x00");
    // 5) 공백 값으로 시작하는 필터 없는 표본
    c.extend(b"q BI /W 4 /H 1 /BPC 8 /CS /G ID  \n\r\x00\nEI Q\n");
    // 6) JBIG2 는 빼고, 뒤의 그리기는 남는다
    c.extend(b"BI /W 8 /H 8 /IM true /F /JBIG2Decode ID \x97JB2\x00junk\nEI\n");
    c.extend(b"0 0 m 99 99 l S\n");
    // 7) 리소스 이름의 Indexed·별색(Separation): 이름을 그대로 둔다
    c.extend(b"q BI /W 8 /H 1 /BPC 1 /CS /CS0 ID \xA5\nEI Q\n");
    c.extend(b"q BI /W 2 /H 1 /BPC 8 /CS /Sep0 /F /AHx ID 40C0>\nEI Q\n");

    c
}
