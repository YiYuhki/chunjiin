"""압축 컨테이너(OOXML/HWPX) 공통 유틸리티: 안전한 읽기와 재구성 쓰기."""

from __future__ import annotations

import io
import posixpath
import zipfile
from dataclasses import dataclass

from lxml import etree

from ..errors import BlockedError
from ..policy import Policy
from ..report import FindingCollector, Severity


@dataclass
class ZipEntry:
    name: str
    data: bytes


def read_zip(data: bytes, policy: Policy, fc: FindingCollector) -> list[ZipEntry]:
    """Zip bomb, 경로 조작, 암호화 엔트리를 검사한 뒤 엔트리를 모두 읽는다."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        raise BlockedError(f"손상된 압축 컨테이너: {e}", "structure") from e

    with zf:
        infos = zf.infolist()
        if len(infos) > policy.max_zip_entries:
            raise BlockedError(f"압축 엔트리 수 초과 ({len(infos)})", "zip-bomb")

        total = sum(i.file_size for i in infos)
        if total > policy.max_zip_uncompressed:
            raise BlockedError(f"압축 해제 크기 초과 ({total} bytes)", "zip-bomb")

        seen: set[str] = set()
        entries: list[ZipEntry] = []
        for info in infos:
            name = info.filename
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:
                raise BlockedError(f"암호화된 엔트리: {name}", "encrypted")
            norm = posixpath.normpath(name.replace("\\", "/"))
            if name.startswith(("/", "\\")) or norm.startswith("..") or ":" in name.split("/")[0]:
                raise BlockedError(f"경로 조작 엔트리: {name}", "path-traversal")
            if norm.lower() in seen:
                fc.add("structure", Severity.MEDIUM, "중복된 엔트리 이름 제거", name)
                continue
            seen.add(norm.lower())
            if info.compress_size > 0 and info.file_size / info.compress_size > policy.max_zip_ratio \
                    and info.file_size > 1024 * 1024:
                raise BlockedError(f"비정상 압축률 엔트리: {name}", "zip-bomb")
            try:
                content = _read_limited(zf, info, policy.max_zip_uncompressed)
            except (zipfile.BadZipFile, OSError, EOFError, NotImplementedError) as e:
                raise BlockedError(f"엔트리 읽기 실패: {name} ({e})", "structure") from e
            entries.append(ZipEntry(name, content))
        return entries


def _read_limited(zf: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    # 헤더의 file_size 를 위조한 경우에 대비해 실제 해제량으로도 제한한다.
    buf = io.BytesIO()
    with zf.open(info) as fp:
        while True:
            chunk = fp.read(1024 * 1024)
            if not chunk:
                break
            buf.write(chunk)
            if buf.tell() > max(info.file_size, 0) + 1024 or buf.tell() > limit:
                raise BlockedError(f"선언 크기와 실제 크기 불일치: {info.filename}", "zip-bomb")
    return buf.getvalue()


def write_zip(entries: list[ZipEntry], first: tuple[str, ...] = (), stored: tuple[str, ...] = ()) -> bytes:
    """엔트리를 새 압축 파일로 재구성한다. `first` 엔트리를 맨 앞에 배치한다."""
    order = {n: i for i, n in enumerate(first)}
    entries = sorted(entries, key=lambda e: (order.get(e.name, len(order)),))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for e in entries:
            info = zipfile.ZipInfo(e.name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED if e.name in stored else zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, e.data)
    return out.getvalue()


_PARSER = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    load_dtd=False,
    dtd_validation=False,
    huge_tree=False,
    remove_comments=True,
    remove_pis=False,
)


def parse_xml(data: bytes, name: str) -> etree._ElementTree:
    """XXE/Billion laughs 가 불가능한 파서로 XML 을 읽는다. DOCTYPE 은 허용하지 않는다."""
    try:
        tree = etree.parse(io.BytesIO(data), _PARSER)
    except etree.XMLSyntaxError as e:
        raise BlockedError(f"XML 파싱 실패: {name} ({e})", "structure") from e
    if tree.docinfo.doctype or tree.docinfo.internalDTD is not None:
        raise BlockedError(f"DOCTYPE 선언 포함 (XXE 의심): {name}", "xxe")
    return tree


def serialize_xml(tree: etree._ElementTree) -> bytes:
    return etree.tostring(tree, xml_declaration=True, encoding="UTF-8", standalone=True)
