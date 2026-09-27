//! Outlook 메시지(.msg) 합성 샘플.
#![allow(dead_code)]

use super::legacy::{cfb, utf16};
use super::png_with_payload;

/// 고정 길이 속성 (id, 형식, 값)
fn props_stream(header: usize, fixed: &[(u16, u16, u64)]) -> Vec<u8> {
    let mut out = vec![0u8; header];
    for &(id, ty, v) in fixed {
        out.extend(((u32::from(id) << 16) | u32::from(ty)).to_le_bytes());
        out.extend(6u32.to_le_bytes());
        out.extend(v.to_le_bytes());
    }
    out
}

fn string_prop(base: &str, id: u16, s: &str) -> (String, Vec<u8>) {
    (format!("{base}__substg1.0_{id:04X}001F"), utf16(s))
}

fn binary_prop(base: &str, id: u16, d: &[u8]) -> (String, Vec<u8>) {
    (format!("{base}__substg1.0_{id:04X}0102"), d.to_vec())
}

/// 악성 요소를 고루 담은 메시지
pub fn malicious_msg() -> Vec<u8> {
    let mut e: Vec<(String, Vec<u8>)> = Vec::new();
    // 2024-01-02 03:04:05 UTC
    let filetime = (1_704_164_645u64 + 11_644_473_600) * 10_000_000;
    e.push((
        "__properties_version1.0".into(),
        props_stream(32, &[(0x0039, 0x0040, filetime)]),
    ));
    e.push(string_prop(
        "",
        0x0037,
        "분기 보고서\r\nBcc: victim@evil.example",
    ));
    e.push(string_prop("", 0x0C1A, "김철수"));
    e.push(string_prop("", 0x5D01, "kim@example.com"));
    e.push(string_prop("", 0x1000, "본문입니다.\u{202E}fdp.exe"));
    let html = r#"<html><head><meta http-equiv="refresh" content="0;url=https://evil.example/"></head><body onload="steal()"><p>본문입니다.</p><script>alert(1)</script><img src="https://evil.example/track.gif"><img src="cid:logo@x"><a href="javascript:alert(2)">링크</a></body></html>"#;
    e.push(binary_prop("", 0x1013, html.as_bytes()));
    // 수신자: SMTP 주소, 이름만(Exchange 내부), 숨은 참조
    let r0 = "__recip_version1.0_#00000000/";
    e.push((
        format!("{r0}__properties_version1.0"),
        props_stream(8, &[(0x0C15, 0x0003, 1)]),
    ));
    e.push(string_prop(r0, 0x3001, "Lee, Younghee"));
    e.push(string_prop(r0, 0x39FE, "lee@example.com"));
    let r1 = "__recip_version1.0_#00000001/";
    e.push((
        format!("{r1}__properties_version1.0"),
        props_stream(8, &[(0x0C15, 0x0003, 2)]),
    ));
    e.push(string_prop(r1, 0x3001, "박영수"));
    e.push(string_prop(r1, 0x3003, "/O=EXCHANGE/OU=ADMIN/CN=PARK"));
    let r2 = "__recip_version1.0_#00000002/";
    e.push((
        format!("{r2}__properties_version1.0"),
        props_stream(8, &[(0x0C15, 0x0003, 3)]),
    ));
    e.push(string_prop(r2, 0x39FE, "hidden@example.com"));
    // 첨부 0: 본문에 쓰인 그림 (뒤에 덧붙은 데이터)
    let a0 = "__attach_version1.0_#00000000/";
    e.push((
        format!("{a0}__properties_version1.0"),
        props_stream(8, &[(0x3705, 0x0003, 1)]),
    ));
    e.push(string_prop(a0, 0x3707, "logo.png"));
    e.push(string_prop(a0, 0x3712, "logo@x"));
    e.push(binary_prop(a0, 0x3701, &png_with_payload()));
    // 첨부 1: 실행 파일
    let a1 = "__attach_version1.0_#00000001/";
    e.push((
        format!("{a1}__properties_version1.0"),
        props_stream(8, &[(0x3705, 0x0003, 1)]),
    ));
    e.push(string_prop(a1, 0x3707, "invoice.exe"));
    e.push(binary_prop(a1, 0x3701, b"MZ\x90\x00\x03\x00\x00\x00"));
    // 첨부 2: 공유 폴더를 가리키는 참조 첨부
    let a2 = "__attach_version1.0_#00000002/";
    e.push((
        format!("{a2}__properties_version1.0"),
        props_stream(8, &[(0x3705, 0x0003, 2)]),
    ));
    e.push(string_prop(a2, 0x3707, "payload.lnk"));
    e.push(string_prop(
        a2,
        0x370D,
        "\\\\evil.example\\share\\payload.lnk",
    ));
    // 첨부 3: OLE 개체
    let a3 = "__attach_version1.0_#00000003/";
    e.push((
        format!("{a3}__properties_version1.0"),
        props_stream(8, &[(0x3705, 0x0003, 6)]),
    ));
    e.push(string_prop(a3, 0x3707, "Package.bin"));
    e.push((
        format!("{a3}__substg1.0_3701000D/\u{1}Ole10Native"),
        b"\x00\x00calc.exe".to_vec(),
    ));
    // 첨부 4: 내장 메시지 (그 안에 또 스크립트)
    let a4 = "__attach_version1.0_#00000004/";
    e.push((
        format!("{a4}__properties_version1.0"),
        props_stream(8, &[(0x3705, 0x0003, 5)]),
    ));
    let inner = format!("{a4}__substg1.0_3701000D/");
    e.push((
        format!("{inner}__properties_version1.0"),
        props_stream(24, &[]),
    ));
    e.push(string_prop(&inner, 0x0037, "전달된 메일"));
    e.push(string_prop(&inner, 0x0C1A, "Park"));
    e.push(string_prop(&inner, 0x5D01, "park@example.com"));
    e.push(binary_prop(
        &inner,
        0x1013,
        r#"<p>안쪽</p><iframe src="https://evil.example/"></iframe><script>x()</script>"#
            .as_bytes(),
    ));
    let refs: Vec<(&str, &[u8])> = e.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect();
    cfb(&refs)
}

/// RTF 에 감싼 HTML 본문만 있는 메시지 (Outlook 이 흔히 저장하는 형태). 압축하지 않은(MELA) 형식
pub fn rtf_html_msg() -> Vec<u8> {
    let rtf = br"{\rtf1\ansi\ansicpg949\fromhtml1 \deff0{\fonttbl{\f0\fswiss Arial;}}{\*\htmltag19 <html>}{\*\htmltag34 <body>}\htmlrtf {\htmlrtf0 \'c7\'d1\'b1\'db \'ba\'bb\'b9\'ae{\*\htmltag84 <script>alert(1)</script>}\htmlrtf\par\htmlrtf0}{\*\htmltag42 </body></html>}}";
    let mut comp = Vec::new();
    comp.extend(((rtf.len() + 12) as u32).to_le_bytes());
    comp.extend((rtf.len() as u32).to_le_bytes());
    comp.extend(b"MELA");
    comp.extend(0u32.to_le_bytes());
    comp.extend(rtf);
    let e: Vec<(String, Vec<u8>)> = vec![
        ("__properties_version1.0".into(), props_stream(32, &[])),
        string_prop("", 0x0037, "RTF 본문"),
        binary_prop("", 0x1009, &comp),
    ];
    let refs: Vec<(&str, &[u8])> = e.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect();
    cfb(&refs)
}

/// 압축 RTF 폭탄: 2바이트 참조마다 17바이트로 풀리는 LZFu 스트림
pub fn rtf_bomb_msg(compressed_len: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(compressed_len);
    let mut wpos = 207usize;
    while body.len() < compressed_len {
        body.push(0xFF);
        for _ in 0..8 {
            let offset = (wpos + 100) % 4096;
            body.extend((((offset << 4) | 0xF) as u16).to_be_bytes());
            wpos = (wpos + 17) % 4096;
        }
    }
    let mut comp = Vec::new();
    comp.extend(((body.len() + 12) as u32).to_le_bytes());
    comp.extend(u32::MAX.to_le_bytes());
    comp.extend(b"LZFu");
    comp.extend(0u32.to_le_bytes());
    comp.extend(body);
    let e: Vec<(String, Vec<u8>)> = vec![
        ("__properties_version1.0".into(), props_stream(32, &[])),
        string_prop("", 0x0037, "bomb"),
        binary_prop("", 0x1009, &comp),
    ];
    let refs: Vec<(&str, &[u8])> = e.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect();
    cfb(&refs)
}
