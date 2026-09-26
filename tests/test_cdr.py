from __future__ import annotations

import io
import zipfile

import pikepdf
import pytest
from PIL import Image

from cdr import CDREngine, Policy, Status
from cdr.detect import FileType, detect

import samples


@pytest.fixture
def engine() -> CDREngine:
    return CDREngine()


def categories(result) -> set[str]:
    return {f.category for f in result.findings}


def unzip(data: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return {n: zf.read(n) for n in zf.namelist()}


# ------------------------------------------------------------------ 형식 판별
def test_detect_by_magic_not_extension():
    assert detect(samples.clean_pdf(), "report.docx") == FileType.PDF
    assert detect(samples.malicious_docm(), "x.pdf") == FileType.DOCX
    assert detect(samples.malicious_xlsm()) == FileType.XLSX
    assert detect(samples.malicious_pptx()) == FileType.PPTX
    assert detect(samples.png_bytes()) == FileType.PNG
    assert detect(samples.malicious_rtf()) == FileType.RTF


def test_extension_mismatch_reported(engine):
    r = engine.process(samples.clean_pdf(), "invoice.docx")
    assert "type-mismatch" in categories(r)
    assert r.output_filename == "invoice.pdf"


# ------------------------------------------------------------------ OOXML
def test_docm_disarm(engine):
    r = engine.process(samples.malicious_docm(), "보고서.docm")
    assert r.status == Status.SANITIZED, r.reason
    assert r.output_filename == "보고서.docx"
    cats = categories(r)
    for expected in ("macro", "embedded-object", "template-injection", "dangerous-link", "dde",
                     "external-resource", "macro-enabled-format", "hidden-data", "metadata"):
        assert expected in cats, expected

    parts = unzip(r.output)
    names = set(parts)
    assert list(parts)[0] == "[Content_Types].xml"
    assert not any("vba" in n.lower() for n in names)
    assert not any("embeddings" in n for n in names)
    assert "docProps/custom.xml" not in names

    ct = parts["[Content_Types].xml"].decode()
    assert "macroEnabled" not in ct and "vbaProject" not in ct and "oleObject" not in ct

    doc = parts["word/document.xml"].decode()
    assert "DDEAUTO" not in doc and "INCLUDEPICTURE" not in doc
    assert "PAGE" in doc                    # 안전한 필드는 유지
    assert "안전한 본문" in doc and "악성 링크" in doc  # 텍스트는 보존(링크만 해제)
    assert "OLEObject" not in doc
    assert 'r:link="rId7"' not in doc and 'r:embed="rId6"' in doc

    rels = parts["word/_rels/document.xml.rels"].decode()
    assert "https://example.com/" in rels
    assert "file://" not in rels and "vbaProject" not in rels and "10.0.0.1" not in rels

    settings_rels = parts["word/_rels/settings.xml.rels"].decode()
    assert "evil.example" not in settings_rels
    assert "attachedTemplate" not in parts["word/settings.xml"].decode()

    core = parts["docProps/core.xml"].decode()
    assert "홍길동" not in core and "attacker" not in core

    # 내장 이미지도 재인코딩되어 덧붙은 데이터와 메타데이터 제거
    img = parts["word/media/image1.png"]
    assert img.endswith(b"IEND\xaeB`\x82")
    assert b"attacker" not in img


def test_docx_output_is_idempotent(engine):
    first = engine.process(samples.malicious_docm(), "a.docm")
    second = engine.process(first.output, first.output_filename)
    assert second.status == Status.CLEAN, [f.to_dict() for f in second.findings]


def test_remove_hyperlinks_policy():
    r = CDREngine(Policy(remove_hyperlinks=True)).process(samples.malicious_docm(), "a.docm")
    rels = unzip(r.output)["word/_rels/document.xml.rels"].decode()
    assert "example.com" not in rels
    assert "hyperlink" in categories(r)


def test_xxe_blocked(engine):
    r = engine.process(samples.xxe_docx(), "xxe.docx")
    assert r.status == Status.BLOCKED
    assert "DOCTYPE" in r.reason


def test_xlsm_disarm(engine):
    r = engine.process(samples.malicious_xlsm(), "매출.xlsm")
    assert r.status == Status.SANITIZED, r.reason
    assert r.output_filename == "매출.xlsx"
    assert {"xlm-macro", "external-link", "auto-exec", "dde"} <= categories(r)
    parts = unzip(r.output)
    assert not any(n.startswith(("xl/macrosheets", "xl/externalLinks")) for n in parts)
    wb = parts["xl/workbook.xml"].decode()
    assert "Auto_Open" not in wb and "externalReferences" not in wb and 'name="Data"' in wb
    assert "Macro1" not in wb
    sheet = parts["xl/worksheets/sheet1.xml"].decode()
    assert "SUM(1,2)" in sheet
    assert "cmd|" not in sheet and "WEBSERVICE" not in sheet
    assert "<v>0</v>" in sheet  # 캐시 값은 유지


def test_pptx_disarm(engine):
    r = engine.process(samples.malicious_pptx(), "deck.ppsx")
    assert r.status == Status.SANITIZED, r.reason
    parts = unzip(r.output)
    slide = parts["ppt/slides/slide1.xml"].decode()
    assert "ppaction://program" not in slide and "ppaction://macro" not in slide
    assert "hlinkshowjump" in slide
    assert "calc.exe" not in parts["ppt/slides/_rels/slide1.xml.rels"].decode()
    assert "presentationml.presentation.main" in parts["[Content_Types].xml"].decode()


# ------------------------------------------------------------------ PDF
def test_pdf_disarm(engine):
    src = samples.malicious_pdf()
    r = engine.process(src, "문서.pdf")
    assert r.status == Status.SANITIZED, r.reason
    cats = categories(r)
    for expected in ("javascript", "launch", "auto-exec", "embedded-file", "dangerous-link", "xfa",
                     "hidden-data", "metadata"):
        assert expected in cats, expected

    out = r.output
    assert b"HIDDEN-PAYLOAD" not in out
    with pikepdf.open(io.BytesIO(out)) as pdf:
        root = pdf.Root
        assert "/OpenAction" not in root and "/AA" not in root
        assert "/JavaScript" not in root.Names and "/EmbeddedFiles" not in root.Names
        assert "/XFA" not in root.AcroForm
        assert "/Metadata" not in root
        page = pdf.pages[0].obj
        assert "/AA" not in page
        annots = list(page.Annots)
        assert len(annots) == 3  # FileAttachment 제거
        uris = []
        for a in annots:
            if "/A" in a:
                assert str(a.A.S) == "/URI"
                uris.append(str(a.A.URI))
        # Launch 는 제거되고 /Next 의 정상 URI 가 승계됨, file: URI 는 제거
        assert sorted(uris) == ["https://example.com/", "https://ok.example/"]
        for obj in pdf.objects:
            if isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream)):
                assert "/JS" not in obj
                assert obj.get("/S") != pikepdf.Name.JavaScript
    assert b"evil executable" not in out


def test_clean_pdf_is_clean(engine):
    r = engine.process(samples.clean_pdf(), "ok.pdf")
    assert r.status == Status.CLEAN
    assert r.output.startswith(b"%PDF-")


def test_encrypted_pdf_blocked(engine):
    pdf = pikepdf.new()
    pdf.add_blank_page()
    buf = io.BytesIO()
    pdf.save(buf, encryption=pikepdf.Encryption(user="secret", owner="owner"))
    r = engine.process(buf.getvalue(), "locked.pdf")
    assert r.status == Status.BLOCKED
    assert "암호" in r.reason


# ------------------------------------------------------------------ RTF
def test_rtf_disarm(engine):
    r = engine.process(samples.malicious_rtf(), "letter.rtf")
    assert r.status == Status.SANITIZED, r.reason
    out = r.output
    assert b"\\object" not in out and b"objdata" not in out and b"Equation" not in out
    assert b"template" not in out
    assert b"DDEAUTO" not in out
    assert b"PAGE" in out and b"Hello" in out and b"\\{world\\}" in out
    assert b"MZ-appended" not in out
    assert out.count(b"{") - out.count(b"\\{") == out.count(b"}") - out.count(b"\\}")
    assert {"template-injection", "embedded-object", "dde", "hidden-data"} <= categories(r)


def test_rtf_unbalanced_blocked(engine):
    r = engine.process(rb"{\rtf1 {\b bold", "bad.rtf")
    assert r.status == Status.BLOCKED


# ------------------------------------------------------------------ 이미지
def test_png_metadata_and_trailer_removed(engine):
    src = samples.png_bytes(with_meta=True, trailing=b"<?php system($_GET[c]); ?>" * 3)
    r = engine.process(src, "a.png")
    assert r.status == Status.SANITIZED
    assert b"php" not in r.output and b"attacker" not in r.output
    img = Image.open(io.BytesIO(r.output))
    assert img.size == (8, 8) and img.getpixel((0, 0)) == (200, 30, 30)


def test_jpeg_exif_removed(engine):
    r = engine.process(samples.jpeg_bytes(with_exif=True), "photo.jpg")
    assert r.output is not None
    assert b"EvilCam" not in r.output and b"payload-here" not in r.output


def test_image_bomb_blocked():
    img = Image.new("1", (20000, 20000))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    r = CDREngine(Policy(max_image_pixels=10_000_000)).process(buf.getvalue(), "bomb.png")
    assert r.status == Status.BLOCKED


# ------------------------------------------------------------------ 텍스트/CSV
def test_csv_injection(engine):
    src = "이름,금액,메모\n홍길동,-100,=HYPERLINK(\"http://evil\")\n김철수,+3.5,@SUM(A1)\n".encode()
    r = engine.process(src, "list.csv")
    assert r.status == Status.SANITIZED
    text = r.output.decode()
    assert "'=HYPERLINK" in text and "'@SUM" in text
    assert ",-100," in text and ",+3.5," in text


def test_text_bidi(engine):
    r = engine.process("invoice‮gpj.exe".encode(), "readme.txt")
    assert "‮" not in r.output.decode()
    assert "bidi-override" in categories(r)


# ------------------------------------------------------------------ 컨테이너/정책
def test_zip_archive_recursive(engine):
    archive = samples.make_zip({
        "docs/a.docm": samples.malicious_docm(),
        "docs/b.pdf": samples.malicious_pdf(),
        "tool.exe": b"MZ\x90\x00" + b"\x00" * 100,
        "legacy.doc": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 600,
    })
    r = engine.process(archive, "inbox.zip")
    assert r.status == Status.SANITIZED
    names = set(unzip(r.output))
    assert names == {"docs/a.docx", "docs/b.pdf"}


def test_zip_path_traversal_blocked(engine):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<x/>")
        zf.writestr("../../evil.sh", "rm -rf /")
    r = engine.process(buf.getvalue(), "t.docx")
    assert r.status == Status.BLOCKED
    assert "경로" in r.reason


def test_zip_bomb_blocked():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", b"\x00" * (20 * 1024 * 1024))
    r = CDREngine(Policy(max_zip_ratio=100)).process(buf.getvalue(), "bomb.docx")
    assert r.status == Status.BLOCKED


def test_legacy_and_executable_blocked(engine):
    assert engine.process(b"MZ\x90\x00" + b"\x00" * 64, "setup.pdf").status == Status.BLOCKED
    r = engine.process(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 600, "old.doc")
    assert r.status == Status.BLOCKED


def test_size_limit():
    r = CDREngine(Policy(max_file_size=10)).process(b"x" * 11, "a.txt")
    assert r.status == Status.BLOCKED


def test_hwpx_disarm(engine):
    src = samples.make_zip({
        "mimetype": "application/hwp+zip",
        "Contents/content.hpf": (
            '<?xml version="1.0"?><opf:package xmlns:opf="http://www.idpf.org/2007/opf/">'
            '<opf:manifest><opf:item id="s" href="Scripts/DefaultJScript" media-type="application/x-javascript"/>'
            '<opf:item id="o" href="BinData/ole1.ole" media-type="application/ole"/>'
            '<opf:item id="i" href="BinData/image1.png" media-type="image/png"/></opf:manifest>'
            '<opf:spine><opf:itemref idref="o"/></opf:spine></opf:package>'
        ),
        "Contents/section0.xml": '<?xml version="1.0"?><hs:sec xmlns:hs="urn:hs">본문</hs:sec>',
        "Scripts/DefaultJScript": "function OnDocument_New(){ new ActiveXObject('WScript.Shell').Run('calc'); }",
        "BinData/ole1.ole": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1payload",
        "BinData/image1.png": samples.png_bytes(with_meta=True),
    })
    r = engine.process(src, "공문.hwpx")
    assert r.status == Status.SANITIZED, r.reason
    with zipfile.ZipFile(io.BytesIO(r.output)) as zf:
        infos = zf.infolist()
        assert infos[0].filename == "mimetype" and infos[0].compress_type == zipfile.ZIP_STORED
        names = zf.namelist()
        manifest = zf.read("Contents/content.hpf").decode()
    assert "Scripts/DefaultJScript" not in names and "BinData/ole1.ole" not in names
    assert "BinData/image1.png" in names
    assert "Scripts/" not in manifest and "ole1" not in manifest and 'idref="o"' not in manifest
    assert {"macro", "embedded-object"} <= categories(r)
