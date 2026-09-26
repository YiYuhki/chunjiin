"""HWPX(한컴오피스 OWPML) CDR.

제거 대상
- 문서 스크립트(Scripts/*: JScript 매크로)
- OLE 개체로 삽입된 BinData 항목
- 매니페스트(content.hpf) 의 제거 항목 참조
"""

from __future__ import annotations

import posixpath

from ..detect import OLE_MAGIC, FileType, detect
from ..errors import BlockedError
from ..policy import Policy
from ..report import FindingCollector, Severity
from ._zip import ZipEntry, parse_xml, read_zip, serialize_xml, write_zip
from .image import sanitize_image

EXECUTABLE_EXT = {"exe", "dll", "js", "jse", "vbs", "vbe", "wsf", "hta", "bat", "cmd", "ps1", "scr", "lnk", "jar"}


def sanitize_hwpx(data: bytes, policy: Policy, fc: FindingCollector) -> bytes:
    entries = read_zip(data, policy, fc)
    names = {e.name for e in entries}
    if "mimetype" not in names:
        raise BlockedError("mimetype 없음 - 올바른 HWPX 가 아님", "structure")

    drop: set[str] = set()
    for e in entries:
        low = e.name.lower()
        ext = low.rsplit(".", 1)[-1] if "." in low else ""
        if low.startswith("scripts/"):
            fc.add("macro", Severity.CRITICAL, "문서 스크립트(JScript 매크로) 제거", e.name)
            drop.add(e.name)
        elif low.startswith("bindata/") and (e.data.startswith(OLE_MAGIC) or ext == "ole"):
            fc.add("embedded-object", Severity.HIGH, "OLE 개체 제거", e.name)
            drop.add(e.name)
        elif ext in EXECUTABLE_EXT or e.data[:2] == b"MZ":
            fc.add("executable", Severity.CRITICAL, "실행 파일 형태의 내장 파일 제거", e.name)
            drop.add(e.name)

    out: list[ZipEntry] = []
    for e in entries:
        if e.name in drop:
            continue
        low = e.name.lower()
        content = e.data
        if low.endswith((".xml", ".hpf", ".rdf")):
            tree = parse_xml(content, e.name)
            if low.endswith("content.hpf"):
                _clean_manifest(tree.getroot(), e.name, drop)
            content = serialize_xml(tree)
        elif policy.sanitize_embedded_images and low.startswith("bindata/"):
            itype = detect(content)
            if itype in (FileType.PNG, FileType.JPEG, FileType.GIF, FileType.BMP):
                sub = FindingCollector()
                content = sanitize_image(content, itype, policy, sub)
                for f in sub.findings:
                    fc.add(f.category, f.severity, f.description, e.name)
        out.append(ZipEntry(e.name, content))

    # mimetype 은 반드시 첫 번째, 무압축으로 저장해야 한다 (OCF 규격)
    return write_zip(out, first=("mimetype",), stored=("mimetype",))


def _clean_manifest(root, name: str, drop: set[str]) -> None:
    base = posixpath.dirname(name)
    dropped_ids: set[str] = set()
    for item in list(root.iter()):
        if not isinstance(item.tag, str):
            continue
        href = item.get("href")
        if not href:
            continue
        candidates = {href, posixpath.normpath(posixpath.join(base, href))}
        if candidates & drop:
            if item.get("id"):
                dropped_ids.add(item.get("id"))
            item.getparent().remove(item)
    if dropped_ids:
        for ref in list(root.iter()):
            if isinstance(ref.tag, str) and ref.get("idref") in dropped_ids:
                ref.getparent().remove(ref)
