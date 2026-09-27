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

/// 8×6 RGB 무손실 JPEG 2000 코드스트림 (Pillow/OpenJPEG). 화소 (x, y) = (30x, 40y, x+y 홀수면 200 아니면 20)
pub const JPX_RGB: &str = "ff4fff51002f000000000008000000060000000000000000000000080000000600000000000000000003070101070101070101ff52000c00000001000204040001ff5c000a4040484850484850ff640025000143726561746564206279204f70656e4a5045472076657273696f6e20322e352e34ff90000a0000000000510001ff93df8020095c3d87df802006915b39c3e708088f9d3fc7da08000d02ff7fa03e10c008ff7f80c1f384001beda77fa1f502000cbf281e93f30b08e7380aac0063c645241fffd9";
/// 4×4 RGBA JP2: 첫 줄은 파랑(알파 0·64·128·192), 나머지는 불투명 빨강
pub const JPX_RGBA: &str = "0000000c6a5020200d0a870a00000014667479706a703220000000006a7032200000004f6a703268000000166968647200000004000000040004070700000000000f636f6c720100000000001000000022636465660004000000000001000100000002000200000003000300010000000000d96a703263ff4fff510032000000000004000000040000000000000000000000040000000400000000000000000004070101070101070101070101ff52000c00000001000204040001ff5c000a4040484850484850ff640025000143726561746564206279204f70656e4a5045472076657273696f6e20322e352e34ff90000a0000000000580001ff93c7d40201df800807c7d40208cfb4080471a7e004017f80a7e004097bc3ea029f80143ed020031f02d709dfa7e00603ff7f80a3ed02000674c3ea039f801c1f50180da237052d770e737fffd9";

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// JBIG2 세그먼트 (번호, 종류, 데이터). 페이지 연결 1바이트, 참조 없음
pub fn jbig2_segment(n: u32, t: u8, data: &[u8]) -> Vec<u8> {
    let mut v = n.to_be_bytes().to_vec();
    v.push(t);
    v.push(0);
    v.push(1);
    v.extend((data.len() as u32).to_be_bytes());
    v.extend(data);
    v
}

/// 무늬 (x+2y)%5==0 이 검정인 w×h 그림을 JBIG2(MMR 일반 영역)로: (페이지 정보, 영역+끝, 기대 1비트 표본)
pub fn jbig2_parts(w: u32, h: u32) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    jbig2_parts_with(w, h, |x, y| (x + 2 * y).is_multiple_of(5))
}

/// 문서 스캔 같은 무늬(줄마다 흩어진 글자 모양)의 JBIG2
pub fn jbig2_text_parts(w: u32, h: u32) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    jbig2_parts_with(w, h, |x, y| {
        let (cx, cy) = (x / 9, y / 14);
        let seed = cx.wrapping_mul(2_654_435_761) ^ cy.wrapping_mul(40_503);
        let (gx, gy) = (x % 9, y % 14);
        // 획(세로·가로 막대)으로 된 글자 모양이 칸마다 있거나 없다
        let stroke = match seed % 4 {
            0 => gx < 2,
            1 => !(2..=7).contains(&gy),
            2 => gx < 2 || gy < 2,
            _ => gx > 4 || gy > 7,
        };
        cy % 2 == 0 && gy < 10 && gx < 7 && seed % 5 != 0 && stroke
    })
}

pub fn jbig2_parts_with(
    w: u32,
    h: u32,
    black: impl Fn(u32, u32) -> bool,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut info = Vec::new();
    for v in [w, h, 0, 0] {
        info.extend(v.to_be_bytes());
    }
    info.push(0);
    info.extend(0u16.to_be_bytes());
    let mut enc = fax::encoder::Encoder::new(fax::VecWriter::new());
    for y in 0..h {
        let row = (0..w).map(|x| {
            if black(x, y) {
                fax::Color::Black
            } else {
                fax::Color::White
            }
        });
        enc.encode_line(row, w).unwrap();
    }
    let mmr = enc.finish().unwrap().finish();
    let mut region = Vec::new();
    for v in [w, h, 0, 0] {
        region.extend(v.to_be_bytes());
    }
    region.push(0); // 합성: OR
    region.push(1); // MMR
    region.extend(mmr);
    let body = [jbig2_segment(1, 38, &region), jbig2_segment(2, 49, &[])].concat();
    let stride = (w as usize).div_ceil(8);
    let mut bits = vec![0xFFu8; stride * h as usize];
    for y in 0..h {
        for x in 0..w {
            if black(x, y) {
                bits[y as usize * stride + x as usize / 8] &= !(0x80 >> (x % 8));
            }
        }
    }
    (jbig2_segment(0, 48, &info), body, bits)
}

/// JBIG2·JPX 인라인 이미지를 담은 콘텐츠
pub fn codec_inline_content() -> Vec<u8> {
    let (info, body, _) = jbig2_parts(20, 6);
    let mut c = b"q BI /W 20 /H 6 /IM true /F /JBIG2Decode ID ".to_vec();
    c.extend([info, body].concat());
    c.extend(b"\nEI Q q BI /W 8 /H 6 /F /JPXDecode ID ");
    c.extend(unhex(JPX_RGB));
    c.extend(b"\nEI Q 0 0 m 9 9 l S");
    c
}
