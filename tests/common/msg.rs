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

/// 일정 항목: 시작·종료·장소가 명명 속성에 들어 있다
pub fn appointment_msg() -> Vec<u8> {
    let appt = [
        0x02, 0x20, 0x06, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46,
    ];
    let mut entries = Vec::new();
    for (i, lid) in [0x820Du32, 0x820E, 0x8208].into_iter().enumerate() {
        entries.extend(lid.to_le_bytes());
        entries.extend(6u16.to_le_bytes()); // GUID 색인 3, 번호 이름
        entries.extend((i as u16).to_le_bytes());
    }
    let start = (1_704_164_645u64 + 11_644_473_600) * 10_000_000;
    let e: Vec<(String, Vec<u8>)> = vec![
        (
            "__properties_version1.0".into(),
            props_stream(
                32,
                &[
                    (0x8000, 0x0040, start),
                    (0x8001, 0x0040, start + 36_000_000_000),
                ],
            ),
        ),
        (
            "__nameid_version1.0/__substg1.0_00020102".into(),
            appt.to_vec(),
        ),
        ("__nameid_version1.0/__substg1.0_00030102".into(), entries),
        string_prop("", 0x001A, "IPM.Appointment"),
        string_prop("", 0x0037, "분기 회의"),
        string_prop("", 0x1000, "안건: 예산"),
        string_prop("", 0x8002, "3층 회의실\r\nBEGIN:VALARM\r\nACTION:PROCEDURE"),
    ];
    let refs: Vec<(&str, &[u8])> = e.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect();
    cfb(&refs)
}

/// 반복 회의 (미국 동부 시간대, 월·수 6회, 한 회차 삭제·한 회차 변경, 참석자·알림)
pub fn recurring_meeting_msg() -> Vec<u8> {
    let appt = [
        0x02, 0x20, 0x06, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46,
    ];
    let common = [
        0x08, 0x20, 0x06, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46,
    ];
    let mut guids = appt.to_vec();
    guids.extend(common);
    // (번호, GUID 색인) → 속성 ID 0x8000 + 순서
    let named: [(u32, u16); 10] = [
        (0x820D, 3),
        (0x820E, 3),
        (0x8208, 3),
        (0x8216, 3),
        (0x8233, 3),
        (0x8234, 3),
        (0x8215, 3),
        (0x8205, 3),
        (0x8503, 4),
        (0x8501, 4),
    ];
    let mut entries = Vec::new();
    for (i, (lid, g)) in named.iter().enumerate() {
        entries.extend(lid.to_le_bytes());
        entries.extend((g << 1).to_le_bytes());
        entries.extend((i as u16).to_le_bytes());
    }
    // 2024-03-04 (1601-01-01 부터의 분)
    let (d0304, d0306, d0311, d0320) = (
        222_566_400u32,
        222_569_280u32,
        222_576_480u32,
        222_589_440u32,
    );
    let mut rec = Vec::new();
    let w16 = |v: &mut Vec<u8>, x: u16| v.extend(x.to_le_bytes());
    let w32 = |v: &mut Vec<u8>, x: u32| v.extend(x.to_le_bytes());
    w16(&mut rec, 0x3004);
    w16(&mut rec, 0x3004);
    w16(&mut rec, 0x200B); // 매주
    w16(&mut rec, 1);
    w16(&mut rec, 0);
    w32(&mut rec, 0);
    w32(&mut rec, 1); // 간격
    w32(&mut rec, 0);
    w32(&mut rec, 0b0000_1010); // 월·수
    w32(&mut rec, 0x2022); // 횟수로 끝
    w32(&mut rec, 6);
    w32(&mut rec, 0); // 한 주의 시작: 일요일
    w32(&mut rec, 2);
    w32(&mut rec, d0306);
    w32(&mut rec, d0311);
    w32(&mut rec, 1);
    w32(&mut rec, d0311);
    w32(&mut rec, d0304);
    w32(&mut rec, d0320);
    w32(&mut rec, 0x3006);
    w32(&mut rec, 0x3009);
    w32(&mut rec, 600); // 10:00
    w32(&mut rec, 660); // 11:00
    w16(&mut rec, 1);
    // 3/11 회차를 14:00~15:00 으로 옮기고 제목을 바꿈
    let ansi = b"Weekly (moved)";
    w32(&mut rec, d0311 + 840);
    w32(&mut rec, d0311 + 900);
    w32(&mut rec, d0311 + 600);
    w16(&mut rec, 0x0001 | 0x0004 | 0x0008); // 제목, 알림 시간, 알림 켬
    w16(&mut rec, ansi.len() as u16 + 1);
    w16(&mut rec, ansi.len() as u16);
    rec.extend(ansi);
    w32(&mut rec, 30); // 30분 전
    w32(&mut rec, 1);
    w32(&mut rec, 0); // ReservedBlock1
    w32(&mut rec, 4); // ChangeHighlight
    w32(&mut rec, 0);
    w32(&mut rec, 0); // ReservedBlockEE1
    w32(&mut rec, d0311 + 840);
    w32(&mut rec, d0311 + 900);
    w32(&mut rec, d0311 + 600);
    let wide: Vec<u16> = "주간 회의(변경)".encode_utf16().collect();
    w16(&mut rec, wide.len() as u16);
    for u in wide {
        w16(&mut rec, u);
    }
    w32(&mut rec, 0); // ReservedBlockEE2
    w32(&mut rec, 0); // ReservedBlock2
                      // 미국 동부: 편차 300분, 일광 절약 -60분 (3월 둘째 일요일 ~ 11월 첫째 일요일 2시)
    let mut tz = Vec::new();
    w32(&mut tz, 300);
    w32(&mut tz, 0);
    w32(&mut tz, (-60i32) as u32);
    w16(&mut tz, 0);
    for v in [0u16, 11, 0, 1, 2, 0, 0, 0] {
        w16(&mut tz, v);
    }
    w16(&mut tz, 0);
    for v in [0u16, 3, 0, 2, 2, 0, 0, 0] {
        w16(&mut tz, v);
    }
    // 첫 회차 2024-03-04 10:00 EST = 15:00 UTC
    let start = (1_709_564_400u64 + 11_644_473_600) * 10_000_000;
    let mut e: Vec<(String, Vec<u8>)> = vec![
        (
            "__properties_version1.0".into(),
            props_stream(
                32,
                &[
                    (0x8000, 0x0040, start),
                    (0x8001, 0x0040, start + 36_000_000_000),
                    (0x8006, 0x000B, 0),
                    (0x8007, 0x0003, 2),
                    (0x8008, 0x000B, 1),
                    (0x8009, 0x0003, 15),
                ],
            ),
        ),
        ("__nameid_version1.0/__substg1.0_00020102".into(), guids),
        ("__nameid_version1.0/__substg1.0_00030102".into(), entries),
        string_prop("", 0x001A, "IPM.Appointment"),
        string_prop("", 0x0037, "주간 회의"),
        string_prop("", 0x0C1A, "김철수"),
        string_prop("", 0x5D01, "kim@example.com"),
        string_prop("", 0x1000, "진행 상황 공유"),
        string_prop("", 0x8002, "3층 회의실"),
        binary_prop("", 0x8003, &rec),
        binary_prop("", 0x8004, &tz),
        string_prop("", 0x8005, "(UTC-05:00) Eastern Time (US & Canada)"),
    ];
    // 수신자: 필수(수락), 선택(거절), 자원, 주최자 자신
    for (i, (name, addr, kind, status, flags)) in [
        ("이영희", "lee@example.com", 1u64, 3u64, 0u64),
        ("Park, Minsu", "park@example.com", 2, 4, 0),
        ("회의실A", "room-a@example.com", 3, 0, 0),
        ("김철수", "kim@example.com", 1, 1, 3),
    ]
    .into_iter()
    .enumerate()
    {
        let rb = format!("__recip_version1.0_#{i:08X}/");
        e.push((
            format!("{rb}__properties_version1.0"),
            props_stream(
                8,
                &[
                    (0x0C15, 0x0003, kind),
                    (0x5FFF, 0x0003, status),
                    (0x5FFD, 0x0003, flags),
                ],
            ),
        ));
        e.push(string_prop(&rb, 0x3001, name));
        e.push(string_prop(&rb, 0x39FE, addr));
    }
    let refs: Vec<(&str, &[u8])> = e.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect();
    cfb(&refs)
}

/// 사진이 있는 연락처
pub fn contact_msg() -> Vec<u8> {
    let e: Vec<(String, Vec<u8>)> = vec![
        ("__properties_version1.0".into(), props_stream(32, &[])),
        string_prop("", 0x001A, "IPM.Contact"),
        string_prop("", 0x0037, "김철수"),
        string_prop("", 0x3001, "김철수"),
        string_prop("", 0x3A16, "예시, 주식회사"),
        string_prop("", 0x3A1C, "010-0000-0000"),
        (
            "__attach_version1.0_#00000000/__properties_version1.0".into(),
            props_stream(8, &[(0x3705, 0x0003, 1), (0x7FFF, 0x000B, 1)]),
        ),
        string_prop(
            "__attach_version1.0_#00000000/",
            0x3707,
            "ContactPicture.png",
        ),
        binary_prop(
            "__attach_version1.0_#00000000/",
            0x3701,
            &png_with_payload(),
        ),
    ];
    let refs: Vec<(&str, &[u8])> = e.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect();
    cfb(&refs)
}

/// 반복 작업 (매주 화요일, 5회)
pub fn recurring_task_msg() -> Vec<u8> {
    let task = [
        0x03, 0x20, 0x06, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46,
    ];
    let mut entries = Vec::new();
    for (i, lid) in [0x8104u32, 0x8105, 0x8126, 0x8116].into_iter().enumerate() {
        entries.extend(lid.to_le_bytes());
        entries.extend(6u16.to_le_bytes());
        entries.extend((i as u16).to_le_bytes());
    }
    // 2024-03-05 (화)
    let d0305 = 222_567_840u32;
    let mut rec = Vec::new();
    for v in [0x3004u16, 0x3004, 0x200B, 1, 0] {
        rec.extend(v.to_le_bytes());
    }
    for v in [
        0u32,
        1,
        0,
        0b0000_0100,
        0x2022,
        5,
        1,
        0,
        0,
        d0305,
        d0305 + 4 * 7 * 1440,
    ] {
        rec.extend(v.to_le_bytes());
    }
    let day = |d: u32| u64::from(d) * 60 * 10_000_000; // 1601 기준 분 → FILETIME
    let e: Vec<(String, Vec<u8>)> = vec![
        (
            "__properties_version1.0".into(),
            props_stream(
                32,
                &[
                    (0x8000, 0x0040, day(d0305)),
                    (0x8001, 0x0040, day(d0305 + 1440)),
                    (0x8002, 0x000B, 1),
                ],
            ),
        ),
        (
            "__nameid_version1.0/__substg1.0_00020102".into(),
            task.to_vec(),
        ),
        ("__nameid_version1.0/__substg1.0_00030102".into(), entries),
        string_prop("", 0x001A, "IPM.Task"),
        string_prop("", 0x0037, "주간 보고서 작성"),
        binary_prop("", 0x8003, &rec),
    ];
    let refs: Vec<(&str, &[u8])> = e.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect();
    cfb(&refs)
}
