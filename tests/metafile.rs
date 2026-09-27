mod common;

use cdr::{CdrResult, Engine, Status};
use common::legacy::*;
use common::metafile::*;
use common::{make_zip, unzip};

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn severities(r: &CdrResult, cat: &str) -> Vec<String> {
    r.findings
        .iter()
        .filter(|f| f.category == cat)
        .map(|f| format!("{:?}", f.severity))
        .collect()
}

/// EMF 레코드를 종류로 찾는다
fn emf_record(d: &[u8], t: u32) -> &[u8] {
    let mut p = u32::from_le_bytes(d[4..8].try_into().unwrap()) as usize;
    loop {
        let rt = u32::from_le_bytes(d[p..p + 4].try_into().unwrap());
        let s = u32::from_le_bytes(d[p + 4..p + 8].try_into().unwrap()) as usize;
        if rt == t {
            return &d[p..p + s];
        }
        p += s;
    }
}

#[test]
fn emf_is_rebuilt_from_allowed_records() {
    let src = malicious_emf();
    let r = Engine::default().process(&src, "a.emf");
    assert_eq!(
        r.status,
        Status::Sanitized,
        "{} {:#?}",
        r.reason,
        r.findings
    );
    let out = r.output.as_ref().unwrap();
    // 주석·이스케이프·범위 밖 개체 선택이 빠지고 그리기 레코드만 남는다
    assert_eq!(emf_types(out), [39, 37, 43, 81, 84, 14]);
    assert!(!contains(out, PAYLOAD));
    let desc: Vec<u8> = "EvilApp"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert!(!contains(out, &desc), "머리글 설명 문자열 제거");
    // 머리글: 크기·레코드 수 재계산, 설명 없음
    let u32at = |d: &[u8], at: usize| u32::from_le_bytes(d[at..at + 4].try_into().unwrap());
    assert_eq!(u32at(out, 4), 108);
    assert_eq!(u32at(out, 48) as usize, out.len());
    assert_eq!(u32at(out, 52), 7);
    assert_eq!(u32at(out, 64), 0);
    // 비트맵: 선언된 화소 크기만 (덧붙은 데이터 없음)
    let blt = emf_record(out, 81);
    assert_eq!(u32at(blt, 8 + 52), 16);
    assert_eq!(u32at(blt, 8 + 44), 40);
    // 글자는 그대로
    let text: Vec<u8> = "안녕".encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert!(contains(emf_record(out, 84), &text));
    assert_eq!(severities(&r, "metafile"), ["Medium", "Low"]);

    let again = Engine::default().process(out, "a.emf");
    assert_eq!(again.status, Status::Clean, "{:#?}", again.findings);
    assert_eq!(
        again.output.as_deref(),
        Some(out.as_slice()),
        "재조합 결과는 고정점"
    );
}

#[test]
fn wmf_escape_and_dangling_objects_are_removed() {
    let r = Engine::default().process(&malicious_wmf(), "a.wmf");
    assert_eq!(
        r.status,
        Status::Sanitized,
        "{} {:#?}",
        r.reason,
        r.findings
    );
    let out = r.output.as_ref().unwrap();
    assert!(!contains(out, PAYLOAD));
    assert_eq!(wmf_functions(out), [0x02FC, 0x012D, 0x041B, 0x0521, 0x0000]);
    // 배치 머리글 검사합이 맞다
    let sum = out[..20]
        .as_chunks::<2>()
        .0
        .iter()
        .fold(0u16, |s, w| s ^ u16::from_le_bytes(*w));
    assert_eq!(u16::from_le_bytes([out[20], out[21]]), sum);
    // 전체 크기(워드)가 실제 길이와 같다
    let words = u32::from_le_bytes(out[22 + 6..22 + 10].try_into().unwrap()) as usize;
    assert_eq!(words * 2, out.len() - 22);

    let again = Engine::default().process(out, "a.wmf");
    assert_eq!(again.status, Status::Clean, "{:#?}", again.findings);
}

#[test]
fn broken_metafiles_are_blocked() {
    let mut emf = malicious_emf();
    emf[4..8].copy_from_slice(&7u32.to_le_bytes()); // 머리글 크기
    assert_eq!(
        Engine::default().process(&emf, "a.emf").status,
        Status::Blocked
    );
    // 개수가 레코드 크기를 넘는 다각형(버퍼 과다 읽기 유형)은 버린다
    let mut emf = malicious_emf();
    let hsize = u32::from_le_bytes(emf[4..8].try_into().unwrap()) as usize;
    let mut poly = 3u32.to_le_bytes().to_vec(); // EMR_POLYGON
    poly.extend(36u32.to_le_bytes());
    poly.extend([0; 16]);
    poly.extend(0x4000_0000u32.to_le_bytes());
    poly.extend([0; 8]);
    emf.splice(hsize..hsize, poly);
    let r = Engine::default().process(&emf, "a.emf");
    assert_eq!(r.status, Status::Sanitized);
    assert!(!emf_types(r.output.as_ref().unwrap()).contains(&3));
}

#[test]
fn docx_emf_image_is_rebuilt_and_typed() {
    const CT: &str = "http://schemas.openxmlformats.org/package/2006/content-types";
    const PR: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
    const REL: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
    let ct = format!(
        r#"<Types xmlns="{CT}"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="emf" ContentType="image/x-emf"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#
    );
    let rels = format!(
        r#"<Relationships xmlns="{PR}"><Relationship Id="rId1" Type="{REL}/officeDocument" Target="word/document.xml"/></Relationships>"#
    );
    let doc_rels = format!(
        r#"<Relationships xmlns="{PR}"><Relationship Id="rId5" Type="{REL}/image" Target="media/image1.emf"/></Relationships>"#
    );
    let doc = format!(
        r#"<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="{REL}" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><w:body><w:p><w:r><w:drawing><a:blip r:embed="rId5"/></w:drawing></w:r></w:p></w:body></w:document>"#
    );
    let emf = malicious_emf();
    let src = make_zip(&[
        ("[Content_Types].xml", ct.as_bytes()),
        ("_rels/.rels", rels.as_bytes()),
        ("word/document.xml", doc.as_bytes()),
        ("word/_rels/document.xml.rels", doc_rels.as_bytes()),
        ("word/media/image1.emf", &emf),
    ]);
    let r = Engine::default().process(&src, "a.docx");
    assert_eq!(
        r.status,
        Status::Sanitized,
        "{} {:#?}",
        r.reason,
        r.findings
    );
    let files = unzip(r.output.as_ref().unwrap());
    let (_, img) = files
        .iter()
        .find(|(n, _)| n == "word/media/image1.emf")
        .expect("메타파일 파트 유지");
    assert_eq!(emf_types(img), [39, 37, 43, 81, 84, 14]);
    assert!(!contains(img, PAYLOAD));
    let (_, types) = files
        .iter()
        .find(|(n, _)| n == "[Content_Types].xml")
        .unwrap();
    assert!(contains(types, b"image/x-emf"));
    let (_, d) = files
        .iter()
        .find(|(n, _)| n == "word/document.xml")
        .unwrap();
    assert!(contains(d, b"rId5"), "그림 참조 유지");

    let again = Engine::default().process(r.output.as_ref().unwrap(), "a.docx");
    assert_eq!(again.status, Status::Clean, "{:#?}", again.findings);
}

#[test]
fn rtf_wmf_picture_is_rebuilt() {
    let wmf = malicious_wmf_raw();
    let hex: String = wmf.iter().map(|b| format!("{b:02x}")).collect();
    let src = format!(r"{{\rtf1\ansi {{\pict\wmetafile8\picw100\pich100 {hex}}}text}}");
    let r = Engine::default().process(src.as_bytes(), "a.rtf");
    assert_eq!(
        r.status,
        Status::Sanitized,
        "{} {:#?}",
        r.reason,
        r.findings
    );
    let out = String::from_utf8(r.output.clone().unwrap()).unwrap();
    assert!(out.contains(r"\wmetafile8") && out.contains("text"));
    let payload_hex: String = PAYLOAD.iter().map(|b| format!("{b:02x}")).collect();
    assert!(!out.contains(&payload_hex));
    // 16진수를 다시 읽으면 재조합된 WMF
    let start = out.find(r"\pich100").unwrap() + r"\pich100".len();
    let digits: Vec<u8> = out[start..]
        .bytes()
        .take_while(|&c| c != b'}')
        .filter(u8::is_ascii_hexdigit)
        .collect();
    let bytes: Vec<u8> = digits
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect();
    assert_eq!(
        wmf_functions(&bytes),
        [0x02FC, 0x012D, 0x041B, 0x0521, 0x0000]
    );

    let again = Engine::default().process(out.as_bytes(), "a.rtf");
    assert_eq!(again.status, Status::Clean, "{:#?}", again.findings);
}

#[test]
fn doc_metafile_is_rebuilt_in_place() {
    // Data 스트림 안의 EMF 그림 (앞뒤에 다른 데이터)
    let blip = ppt_rec(0, 0x3D4, 0xF01A, &officeart_metafile_body(&malicious_emf()));
    let mut data = b"PICF-HEADER-PLACEHOLDER".to_vec();
    data.extend(&blip);
    data.extend(b"TAIL");
    let mut streams = read_cfb(&malicious_doc(1 << 9));
    streams.push(("Data".into(), data.clone()));
    let refs: Vec<(&str, &[u8])> = streams
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    let r = Engine::default().process(&cfb(&refs), "a.doc");
    assert_ne!(r.status, Status::Blocked, "{}", r.reason);
    let out = read_cfb(r.output.as_ref().unwrap());
    let new_data = stream(&out, "Data").unwrap();
    assert_eq!(new_data.len(), data.len(), "길이(오프셋) 보존");
    assert!(new_data.starts_with(b"PICF-HEADER-PLACEHOLDER") && new_data.ends_with(b"TAIL"));
    assert_eq!(new_data[23..31], blip[..8], "레코드 헤더 유지");
    let emf = officeart_metafile_data(&new_data[23 + 8..]);
    assert_eq!(emf_types(&emf), [39, 37, 43, 81, 84, 14]);
    assert!(!contains(&emf, PAYLOAD));
}

#[test]
fn wmf_object_flood_is_linear() {
    // 개체 표를 채운 뒤에도 생성 레코드를 계속 넣는 파일: 레코드마다 표 전체를 훑으면 수십억 번 연산
    let n = 300_000usize;
    let rec: Vec<u8> = [
        7u32.to_le_bytes().as_slice(),
        &0x02FCu16.to_le_bytes(),
        &[0; 8],
    ]
    .concat();
    let mut src = Vec::with_capacity(18 + n * rec.len() + 6);
    for w in [1u16, 9, 0x0300] {
        src.extend(w.to_le_bytes());
    }
    src.extend(((9 + n * 7 + 3) as u32).to_le_bytes());
    src.extend(0u16.to_le_bytes());
    src.extend(7u32.to_le_bytes());
    src.extend(0u16.to_le_bytes());
    for _ in 0..n {
        src.extend(&rec);
    }
    src.extend(3u32.to_le_bytes());
    src.extend(0u16.to_le_bytes());
    let started = std::time::Instant::now();
    let r = Engine::default().process(&src, "a.wmf");
    assert_eq!(r.status, Status::Sanitized, "{}", r.reason);
    assert!(started.elapsed().as_secs() < 20, "{:?}", started.elapsed());
    assert_eq!(wmf_functions(r.output.as_ref().unwrap()).len(), 65535 + 1);
}

#[test]
fn emf_plus_records_are_validated_and_kept() {
    let r = Engine::default().process(&dual_emf(0), "a.emf");
    assert_ne!(r.status, Status::Blocked, "{} {:#?}", r.reason, r.findings);
    let out = r.output.clone().unwrap();
    assert!(contains(&out, b"EMF+"), "EMF+ 유지");
    assert!(!contains(&out, PAYLOAD), "EMF+ 주석은 옮기지 않음");
    // 머리글·브러시·FillRects
    assert_eq!(r.stats.get("emf_plus_records"), Some(&3), "{:?}", r.stats);
    let again = Engine::default().process(&out, "a.emf");
    assert_eq!(again.status, Status::Clean, "{:#?}", again.findings);
    assert_eq!(again.output.as_deref(), Some(out.as_slice()), "고정점");

    // 없는 브러시를 가리키면 EMF+ 를 모두 빼고 GDI 로만 그린다
    let r = Engine::default().process(&dual_emf(9), "b.emf");
    assert_ne!(r.status, Status::Blocked, "{}", r.reason);
    let out = r.output.clone().unwrap();
    assert!(!contains(&out, b"EMF+"));
    assert!(!emf_record(&out, 43).is_empty(), "GDI 사각형은 유지");
    assert!(!severities(&r, "metafile").is_empty(), "{:#?}", r.findings);
}
