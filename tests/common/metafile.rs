//! 메타파일(EMF/WMF) 테스트 표본. 공격용 레코드는 모두 여기서 만든다.
#![allow(dead_code)]

/// 공격 레코드에 심는 표식
pub const PAYLOAD: &[u8] = b"HIDDEN-METAFILE-PAYLOAD";

fn emf_rec(t: u32, body: &[u8]) -> Vec<u8> {
    let size = (body.len() + 8).div_ceil(4) * 4;
    let mut v = t.to_le_bytes().to_vec();
    v.extend((size as u32).to_le_bytes());
    v.extend(body);
    v.resize(size, 0);
    v
}

fn le32(vals: &[i32]) -> Vec<u8> {
    vals.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// 2×2 24비트 DIB (BITMAPINFOHEADER + 화소)
fn dib_2x2() -> (Vec<u8>, Vec<u8>) {
    let mut info = le32(&[40, 2, 2]);
    info.extend(1u16.to_le_bytes());
    info.extend(24u16.to_le_bytes());
    info.extend(le32(&[0, 16, 0, 0, 0, 0]));
    let bits = vec![
        0, 0, 255, 0, 255, 0, 0, 0, // 빨강, 초록 + 채움
        255, 0, 0, 255, 255, 255, 0, 0,
    ];
    (info, bits)
}

/// 정상 그리기 + 주석(페이로드)·이스케이프·범위 밖 개체 선택·비트맵(뒤에 덧붙은 페이로드)을 담은 EMF
pub fn malicious_emf() -> Vec<u8> {
    let mut recs = Vec::new();
    // 브러시 생성(1번) → 선택 → 사각형
    recs.push(emf_rec(39, &le32(&[1, 0, 0x0000FF, 0])));
    recs.push(emf_rec(37, &le32(&[1])));
    recs.push(emf_rec(43, &le32(&[10, 10, 90, 90])));
    // 주석 레코드의 페이로드
    let mut c = (PAYLOAD.len() as u32).to_le_bytes().to_vec();
    c.extend(PAYLOAD);
    recs.push(emf_rec(70, &c));
    // 이스케이프(EXTESCAPE)
    let mut e = le32(&[0x1001, PAYLOAD.len() as i32]);
    e.extend(PAYLOAD);
    recs.push(emf_rec(106, &e));
    // 개체 표 밖의 번호를 선택 (GDI 취약점 유형)
    recs.push(emf_rec(37, &le32(&[0x7FFF_0000])));
    // StretchDIBits: 화소 뒤에 페이로드를 덧붙이고 cbBits 를 부풀림
    let (info, mut bits) = dib_2x2();
    bits.extend(PAYLOAD);
    let fixed = 72usize;
    let mut body = le32(&[0, 0, 10, 10, 20, 20, 0, 0, 2, 2]);
    let at_info = 8 + fixed;
    let at_bits = at_info + info.len();
    body.extend(le32(&[
        at_info as i32,
        info.len() as i32,
        at_bits as i32,
        bits.len() as i32,
        0,
        0x00CC_0020,
        4,
        4,
    ]));
    assert_eq!(body.len(), fixed);
    body.extend(&info);
    body.extend(&bits);
    recs.push(emf_rec(81, &body));
    // 글자 (ExtTextOutW)
    let text: Vec<u8> = "안녕".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut t = le32(&[0, 0, 100, 20, 1]);
    t.extend(1f32.to_le_bytes());
    t.extend(1f32.to_le_bytes());
    t.extend(le32(&[5, 5, 2, 76, 0, 0, 0, 0, 0, 0]));
    t.extend(&text);
    recs.push(emf_rec(84, &t));

    let body: Vec<u8> = recs.concat();
    let eof = emf_rec(14, &le32(&[0, 16, 20]));
    let mut desc: Vec<u8> = "EvilApp\0\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    desc.extend(PAYLOAD);
    while !desc.len().is_multiple_of(4) {
        desc.push(0);
    }
    let hsize = 108 + desc.len();
    let total = hsize + body.len() + eof.len();
    let mut h = le32(&[1, hsize as i32, 0, 0, 100, 100, 0, 0, 2646, 2646]);
    h.extend(0x464D_4520u32.to_le_bytes());
    h.extend(0x0001_0000u32.to_le_bytes());
    h.extend((total as u32).to_le_bytes());
    h.extend(((recs.len() + 2) as u32).to_le_bytes());
    h.extend(2u16.to_le_bytes());
    h.extend(0u16.to_le_bytes());
    h.extend(le32(&[
        (desc.len() / 2) as i32,
        108,
        0,
        1024,
        768,
        320,
        240,
        0,
        0,
        0,
    ]));
    h.extend(le32(&[320_000, 240_000]));
    assert_eq!(h.len(), 108);
    [h, desc, body, eof].concat()
}

fn wmf_rec(f: u16, params: &[u8]) -> Vec<u8> {
    let mut p = params.to_vec();
    if p.len() % 2 == 1 {
        p.push(0);
    }
    let mut v = ((3 + p.len() / 2) as u32).to_le_bytes().to_vec();
    v.extend(f.to_le_bytes());
    v.extend(p);
    v
}

fn le16(vals: &[i16]) -> Vec<u8> {
    vals.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// 정상 그리기 + 이스케이프(SETABORTPROC 유형)·존재하지 않는 개체 선택을 담은 WMF (배치 머리글 없음)
pub fn malicious_wmf_raw() -> Vec<u8> {
    let mut recs = Vec::new();
    recs.push(wmf_rec(0x02FC, &le16(&[0, 0xFF, 0, 0]))); // 브러시 → 0번
    recs.push(wmf_rec(0x012D, &le16(&[0])));
    recs.push(wmf_rec(0x041B, &le16(&[90, 90, 10, 10]))); // Rectangle
    let mut esc = le16(&[9, PAYLOAD.len() as i16]); // SETABORTPROC
    esc.extend(PAYLOAD);
    recs.push(wmf_rec(0x0626, &esc));
    recs.push(wmf_rec(0x012D, &le16(&[40]))); // 없는 개체
    let mut text = le16(&[5]);
    text.extend(b"hello\0");
    text.extend(le16(&[20, 20]));
    recs.push(wmf_rec(0x0521, &text));
    recs.push(wmf_rec(0x0000, &[]));
    let body = recs.concat();
    let words = 9 + body.len() / 2;
    let max = recs.iter().map(|r| r.len() / 2).max().unwrap();
    let mut h = le16(&[1, 9, 0x0300]);
    h.extend((words as u32).to_le_bytes());
    h.extend(1u16.to_le_bytes());
    h.extend((max as u32).to_le_bytes());
    h.extend(0u16.to_le_bytes());
    [h, body].concat()
}

/// 배치 머리글(Aldus Placeable) 이 붙은 WMF
pub fn malicious_wmf() -> Vec<u8> {
    let mut h = 0x9AC6_CDD7u32.to_le_bytes().to_vec();
    h.extend(le16(&[0, 0, 0, 100, 100, 1440]));
    h.extend([0; 4]);
    let sum = h
        .as_chunks::<2>()
        .0
        .iter()
        .fold(0u16, |s, w| s ^ u16::from_le_bytes(*w));
    h.extend(sum.to_le_bytes());
    [h, malicious_wmf_raw()].concat()
}

/// EMF 레코드 종류 목록 (머리글 뒤부터)
pub fn emf_types(d: &[u8]) -> Vec<u32> {
    let mut out = Vec::new();
    let mut p = u32::from_le_bytes(d[4..8].try_into().unwrap()) as usize;
    while p + 8 <= d.len() {
        let t = u32::from_le_bytes(d[p..p + 4].try_into().unwrap());
        let s = u32::from_le_bytes(d[p + 4..p + 8].try_into().unwrap()) as usize;
        out.push(t);
        if s < 8 || t == 14 {
            break;
        }
        p += s;
    }
    out
}

/// WMF 레코드 함수 목록
pub fn wmf_functions(d: &[u8]) -> Vec<u16> {
    let base = if d.starts_with(&0x9AC6_CDD7u32.to_le_bytes()) {
        22
    } else {
        0
    };
    let mut out = Vec::new();
    let mut p = base + 18;
    while p + 6 <= d.len() {
        let s = u32::from_le_bytes(d[p..p + 4].try_into().unwrap()) as usize;
        let f = u16::from_le_bytes(d[p + 4..p + 6].try_into().unwrap());
        out.push(f);
        if s < 3 || f == 0 {
            break;
        }
        p += s * 2;
    }
    out
}

/// OfficeArt 메타파일 그림 레코드 본문 (식별자 16 + OfficeArtMetafileHeader + zlib 압축 데이터)
pub fn officeart_metafile_body(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(data).unwrap();
    let packed = z.finish().unwrap();
    let mut b = vec![0xAB; 16];
    b.extend((data.len() as u32).to_le_bytes());
    b.extend(le32(&[0, 0, 100, 100, 1000, 1000]));
    b.extend((packed.len() as u32).to_le_bytes());
    b.extend([0, 0xFE]);
    b.extend(packed);
    b
}

/// OfficeArt 메타파일 그림 레코드 본문에서 메타파일을 꺼낸다
pub fn officeart_metafile_data(body: &[u8]) -> Vec<u8> {
    let cb = u32::from_le_bytes(body[16 + 28..16 + 32].try_into().unwrap()) as usize;
    let mut out = Vec::new();
    std::io::Read::read_to_end(
        &mut flate2::read::ZlibDecoder::new(&body[16 + 34..16 + 34 + cb]),
        &mut out,
    )
    .unwrap();
    out
}
