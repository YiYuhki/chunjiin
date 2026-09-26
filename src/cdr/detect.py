"""매직 바이트/내부 구조 기반 파일 형식 판별.

확장자는 신뢰하지 않는다. 확장자와 실제 형식이 다르면 별도로 탐지 항목을 남긴다.
"""

from __future__ import annotations

import io
import zipfile
from enum import Enum

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06")


class FileType(str, Enum):
    PDF = "pdf"
    DOCX = "docx"
    XLSX = "xlsx"
    PPTX = "pptx"
    HWPX = "hwpx"
    RTF = "rtf"
    PNG = "png"
    JPEG = "jpeg"
    GIF = "gif"
    BMP = "bmp"
    TIFF = "tiff"
    OLE = "ole"        # 레거시 doc/xls/ppt/hwp, 암호화된 OOXML
    ZIP = "zip"        # 일반 압축 파일
    CSV = "csv"
    TEXT = "text"
    UNKNOWN = "unknown"


# 형식별로 "정상" 으로 간주하는 확장자
EXTENSIONS: dict[FileType, set[str]] = {
    FileType.PDF: {"pdf"},
    FileType.DOCX: {"docx", "docm", "dotx", "dotm"},
    FileType.XLSX: {"xlsx", "xlsm", "xltx", "xltm", "xlam"},
    FileType.PPTX: {"pptx", "pptm", "potx", "potm", "ppsx", "ppsm", "ppam"},
    FileType.HWPX: {"hwpx"},
    FileType.RTF: {"rtf", "doc"},
    FileType.PNG: {"png"},
    FileType.JPEG: {"jpg", "jpeg", "jpe", "jfif"},
    FileType.GIF: {"gif"},
    FileType.BMP: {"bmp", "dib"},
    FileType.TIFF: {"tif", "tiff"},
    FileType.OLE: {"doc", "dot", "xls", "xlt", "ppt", "pot", "pps", "hwp", "msg"},
    FileType.ZIP: {"zip"},
    FileType.CSV: {"csv", "tsv"},
    FileType.TEXT: {"txt", "log", "md"},
}

# 재구성 결과물의 표준 확장자 (매크로 사용 형식 → 일반 형식)
OUTPUT_EXTENSION: dict[FileType, str] = {
    FileType.PDF: "pdf",
    FileType.DOCX: "docx",
    FileType.XLSX: "xlsx",
    FileType.PPTX: "pptx",
    FileType.HWPX: "hwpx",
    FileType.RTF: "rtf",
    FileType.PNG: "png",
    FileType.JPEG: "jpg",
    FileType.GIF: "gif",
    FileType.BMP: "bmp",
    FileType.TIFF: "tiff",
    FileType.CSV: "csv",
    FileType.TEXT: "txt",
}


def _detect_zip(data: bytes) -> FileType:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist())
            if "mimetype" in names:
                try:
                    mt = zf.read("mimetype")[:64]
                except Exception:
                    mt = b""
                if mt.strip().startswith(b"application/hwp+zip"):
                    return FileType.HWPX
            if "[Content_Types].xml" in names:
                if any(n.startswith("word/") for n in names):
                    return FileType.DOCX
                if any(n.startswith("xl/") for n in names):
                    return FileType.XLSX
                if any(n.startswith("ppt/") for n in names):
                    return FileType.PPTX
            return FileType.ZIP
    except (zipfile.BadZipFile, ValueError, NotImplementedError, OSError):
        return FileType.UNKNOWN


def _looks_like_text(data: bytes) -> bool:
    sample = data[:8192]
    if b"\x00" in sample:
        return False
    for enc in ("utf-8", "cp949"):
        try:
            sample.decode(enc)
            return True
        except UnicodeDecodeError:
            # 샘플 경계에서 멀티바이트 문자가 잘렸을 수 있음
            try:
                sample[:-3].decode(enc)
                return True
            except UnicodeDecodeError:
                continue
    return False


def detect(data: bytes, filename: str = "") -> FileType:
    head = data[:16]
    if data[:1024].find(b"%PDF-") != -1:
        return FileType.PDF
    if head.startswith(b"{\\rtf"):
        return FileType.RTF
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return FileType.PNG
    if head.startswith(b"\xff\xd8\xff"):
        return FileType.JPEG
    if head.startswith((b"GIF87a", b"GIF89a")):
        return FileType.GIF
    if head.startswith(b"BM") and len(data) > 26:
        return FileType.BMP
    if head.startswith((b"II*\x00", b"MM\x00*")):
        return FileType.TIFF
    if head.startswith(OLE_MAGIC):
        return FileType.OLE
    if head.startswith(ZIP_MAGIC):
        return _detect_zip(data)
    if _looks_like_text(data):
        ext = extension_of(filename)
        if ext in EXTENSIONS[FileType.CSV]:
            return FileType.CSV
        return FileType.TEXT
    return FileType.UNKNOWN


def extension_of(filename: str) -> str:
    if "." not in filename:
        return ""
    return filename.rsplit(".", 1)[-1].lower()


def extension_matches(ftype: FileType, filename: str) -> bool:
    ext = extension_of(filename)
    if not ext:
        return True
    return ext in EXTENSIONS.get(ftype, set())
