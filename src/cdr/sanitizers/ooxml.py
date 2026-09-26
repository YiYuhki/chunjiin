"""OOXML(docx/xlsx/pptx 및 매크로 사용 변형) CDR.

패키지를 해체하여 허용된 파트만 골라 XML 을 재직렬화한 뒤 새 패키지로 재구성한다.

제거 대상
- VBA 매크로(vbaProject.bin), Excel 4.0(XLM) 매크로 시트, 자동 실행 이름(Auto_Open)
- ActiveX 컨트롤, OLE 개체/패키지 임베딩, altChunk
- 원격 템플릿 인젝션(attachedTemplate), 외부 프레임/하위 문서/외부 이미지 등 외부 관계
- 허용되지 않은 스킴의 하이퍼링크(file:, javascript:, UNC 경로 등)
- Word DDE/DDEAUTO/INCLUDEPICTURE 등 위험 필드, Excel DDE/CALL/REGISTER 수식
- PowerPoint 프로그램/매크로 실행 액션
- 외부 데이터 연결(connections, queryTables), 외부 통합 문서 링크
- 리본 사용자 지정(customUI), 사용자 정의 문서 속성
"""

from __future__ import annotations

import posixpath
import re
from urllib.parse import urlsplit

from lxml import etree

from ..detect import FileType, detect
from ..errors import BlockedError
from ..policy import Policy
from ..report import FindingCollector, Severity
from ._zip import ZipEntry, parse_xml, read_zip, serialize_xml, write_zip
from .image import sanitize_image

CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
PR_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
S_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
CP_NS = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
DC_NS = "http://purl.org/dc/elements/1.1/"

CONTENT_TYPES = "[Content_Types].xml"

# 매크로/템플릿/쇼 형식의 메인 파트 → 일반 문서 형식
MAIN_TYPE_MAP = {
    "application/vnd.ms-word.document.macroEnabled.main+xml":
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
    "application/vnd.ms-word.template.macroEnabledTemplate.main+xml":
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml":
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
    "application/vnd.ms-excel.sheet.macroEnabled.main+xml":
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
    "application/vnd.ms-excel.template.macroEnabled.main+xml":
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
    "application/vnd.ms-excel.addin.macroEnabled.main+xml":
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml":
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
    "application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml":
        "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
    "application/vnd.ms-powerpoint.slideshow.macroEnabled.main+xml":
        "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
    "application/vnd.ms-powerpoint.template.macroEnabled.main+xml":
        "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
    "application/vnd.ms-powerpoint.addin.macroEnabled.main+xml":
        "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml":
        "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.template.main+xml":
        "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
}

# (경로 패턴, 분류, 심각도, 설명)
DROP_PATH_RULES: list[tuple[re.Pattern[str], str, Severity, str]] = [
    (re.compile(r"(^|/)vbaproject(signature(agile|v3)?)?\.bin$"), "macro", Severity.CRITICAL, "VBA 매크로 프로젝트"),
    (re.compile(r"(^|/)vbadata\.xml$"), "macro", Severity.CRITICAL, "VBA 매크로 데이터"),
    (re.compile(r"(^|/)attachedtoolbars\.bin$"), "macro", Severity.HIGH, "매크로 도구 모음"),
    (re.compile(r"^xl/macrosheets/"), "xlm-macro", Severity.CRITICAL, "Excel 4.0(XLM) 매크로 시트"),
    (re.compile(r"^xl/dialogsheets/"), "xlm-macro", Severity.HIGH, "Excel 대화상자 시트"),
    (re.compile(r"(^|/)activex/"), "activex", Severity.HIGH, "ActiveX 컨트롤"),
    (re.compile(r"(^|/)embeddings/"), "embedded-object", Severity.HIGH, "OLE 개체/임베디드 파일"),
    (re.compile(r"^customui/"), "customui", Severity.MEDIUM, "리본 사용자 지정(매크로 콜백)"),
    (re.compile(r"^xl/externallinks/"), "external-link", Severity.HIGH, "외부 통합 문서 링크(DDE 가능)"),
    (re.compile(r"^xl/connections\.xml$"), "data-connection", Severity.MEDIUM, "외부 데이터 연결"),
    (re.compile(r"^xl/querytables/"), "data-connection", Severity.MEDIUM, "외부 데이터 쿼리 테이블"),
]

# 관계 유형 이름(끝부분) → 대상 파트 제거
DROP_REL_TYPES: dict[str, tuple[str, Severity, str]] = {
    "vbaProject": ("macro", Severity.CRITICAL, "VBA 매크로 프로젝트"),
    "oleObject": ("embedded-object", Severity.HIGH, "OLE 개체"),
    "package": ("embedded-object", Severity.HIGH, "임베디드 패키지"),
    "control": ("activex", Severity.HIGH, "ActiveX 컨트롤"),
    "activeXControlBinary": ("activex", Severity.HIGH, "ActiveX 바이너리"),
    "aFChunk": ("alt-chunk", Severity.MEDIUM, "altChunk(외부 형식 삽입 콘텐츠)"),
    "externalLink": ("external-link", Severity.HIGH, "외부 통합 문서 링크"),
    "extensibility": ("customui", Severity.MEDIUM, "리본 사용자 지정"),
    "ui/extensibility": ("customui", Severity.MEDIUM, "리본 사용자 지정"),
    "xlMacrosheet": ("xlm-macro", Severity.CRITICAL, "Excel 4.0 매크로 시트"),
    "xlIntlMacrosheet": ("xlm-macro", Severity.CRITICAL, "Excel 4.0 매크로 시트"),
    "wordVbaData": ("macro", Severity.CRITICAL, "VBA 매크로 데이터"),
    "connections": ("data-connection", Severity.MEDIUM, "외부 데이터 연결"),
    "queryTable": ("data-connection", Severity.MEDIUM, "외부 데이터 쿼리 테이블"),
}

DROP_CONTENT_TYPE_KEYWORDS = ("vbaproject", "vbadata", "oleobject", "activex", "macrosheet", "externallink")

EXTERNAL_REL_RISK: dict[str, tuple[str, Severity, str]] = {
    "attachedTemplate": ("template-injection", Severity.CRITICAL, "원격 템플릿 인젝션"),
    "oleObject": ("external-object", Severity.HIGH, "외부 OLE 개체 링크"),
    "frame": ("external-frame", Severity.HIGH, "외부 프레임 로드"),
    "subDocument": ("external-document", Severity.HIGH, "외부 하위 문서"),
    "externalLinkPath": ("external-link", Severity.HIGH, "외부 통합 문서 경로"),
    "image": ("external-resource", Severity.MEDIUM, "외부 이미지(추적/NTLM 해시 유출 가능)"),
}

WORD_FIELD_RE = re.compile(
    r"\b(DDE|DDEAUTO|INCLUDETEXT|INCLUDEPICTURE|INCLUDE|IMPORT|LINK|MACROBUTTON)\b", re.IGNORECASE
)
WORD_QUOTE_OBFUSCATION_RE = re.compile(r"\bQUOTE(\s+\d{2,3}){3,}", re.IGNORECASE)
EXCEL_FORMULA_FUNC_RE = re.compile(
    r"\b(CALL|REGISTER|REGISTER\.ID|EXEC|WEBSERVICE|FILTERXML|RTD)\s*\(", re.IGNORECASE
)
AUTO_NAME_RE = re.compile(r"^(_xlnm\.)?auto_(open|close|activate|deactivate)", re.IGNORECASE)
PPT_DANGEROUS_ACTION = ("ppaction://program", "ppaction://macro", "ppaction://ole")

# 자식이 모두 사라지면 함께 제거할 컨테이너 요소
EMPTY_CONTAINERS = {
    "externalReferences", "hyperlinks", "oleObjects", "controls", "AlternateContent",
    "Choice", "Fallback", "control", "oleObject", "definedNames",
}


def _local(tag: object) -> str:
    return etree.QName(tag).localname if isinstance(tag, str) else ""


def _rels_path_for(part: str) -> str:
    d, n = posixpath.split(part)
    return posixpath.join(d, "_rels", n + ".rels")


def _source_of_rels(rels: str) -> str:
    d, n = posixpath.split(rels)
    base = posixpath.dirname(d)
    return posixpath.join(base, n[: -len(".rels")]) if n != ".rels" else ""


def _resolve(source_part: str, target: str) -> str:
    target = target.replace("\\", "/")
    if target.startswith("/"):
        return posixpath.normpath(target.lstrip("/"))
    base = posixpath.dirname(source_part)
    return posixpath.normpath(posixpath.join(base, target))


def _rel_type_name(rel_type: str) -> str:
    # ".../relationships/vbaProject" → "vbaProject", ".../relationships/ui/extensibility" → "ui/extensibility"
    marker = "/relationships/"
    idx = rel_type.rfind(marker)
    return rel_type[idx + len(marker):] if idx != -1 else rel_type.rsplit("/", 1)[-1]


def _remove(el: etree._Element) -> None:
    parent = el.getparent()
    if parent is None:
        return
    _drop_keep_tail(el)
    while parent is not None and _local(parent.tag) in EMPTY_CONTAINERS and len(parent) == 0:
        gp = parent.getparent()
        if gp is None:
            break
        _drop_keep_tail(parent)
        parent = gp


def _drop_keep_tail(el: etree._Element) -> None:
    parent = el.getparent()
    if el.tail:
        prev = el.getprevious()
        if prev is not None:
            prev.tail = (prev.tail or "") + el.tail
        else:
            parent.text = (parent.text or "") + el.tail
    parent.remove(el)


def _attached(el: etree._Element, root: etree._Element) -> bool:
    for anc in el.iterancestors():
        if anc is root:
            return True
    return False


def _unwrap(el: etree._Element) -> None:
    parent = el.getparent()
    if parent is None:
        return
    idx = parent.index(el)
    for child in reversed(list(el)):
        parent.insert(idx, child)
    el.tail = None
    parent.remove(el)


class _Package:
    def __init__(self, entries: list[ZipEntry]) -> None:
        self.parts: dict[str, bytes] = {e.name: e.data for e in entries}
        self.lower: dict[str, str] = {n.lower(): n for n in self.parts}

    def exists(self, name: str) -> str | None:
        return self.lower.get(name.lower())


def sanitize_ooxml(data: bytes, ftype: FileType, policy: Policy, fc: FindingCollector) -> bytes:
    pkg = _Package(read_zip(data, policy, fc))
    if CONTENT_TYPES not in pkg.parts:
        raise BlockedError("[Content_Types].xml 없음 - 올바른 OOXML 패키지가 아님", "structure")

    ct_tree = parse_xml(pkg.parts[CONTENT_TYPES], CONTENT_TYPES)
    ct_root = ct_tree.getroot()
    overrides = {
        o.get("PartName", "").lstrip("/").lower(): o
        for o in ct_root.findall(f"{{{CT_NS}}}Override")
    }

    # 1) 제거할 파트 결정 ---------------------------------------------------
    drop: dict[str, tuple[str, Severity, str]] = {}
    for name in pkg.parts:
        low = name.lower()
        for pattern, cat, sev, desc in DROP_PATH_RULES:
            if pattern.search(low):
                drop[name] = (cat, sev, desc)
                break
        else:
            ov = overrides.get(low)
            ctype = (ov.get("ContentType", "") if ov is not None else "").lower()
            if any(k in ctype for k in DROP_CONTENT_TYPE_KEYWORDS):
                drop[name] = ("active-content", Severity.HIGH, f"위험 콘텐츠 형식({ctype})")

    if policy.strip_metadata and pkg.exists("docProps/custom.xml"):
        drop[pkg.exists("docProps/custom.xml")] = ("metadata", Severity.INFO, "사용자 정의 문서 속성")

    rels_trees: dict[str, etree._ElementTree] = {}
    for name in list(pkg.parts):
        if name.endswith(".rels"):
            rels_trees[name] = parse_xml(pkg.parts[name], name)

    # 관계 유형 기반 추가 제거 (반복: 제거된 파트의 하위 파트도 제거)
    changed = True
    while changed:
        changed = False
        for rels_name, tree in rels_trees.items():
            src = _source_of_rels(rels_name)
            src_dropped = src and pkg.exists(src) in drop
            for rel in tree.getroot().findall(f"{{{PR_NS}}}Relationship"):
                if rel.get("TargetMode") == "External":
                    continue
                target = pkg.exists(_resolve(src, rel.get("Target", "")))
                if not target or target in drop:
                    continue
                tname = _rel_type_name(rel.get("Type", ""))
                if tname in DROP_REL_TYPES:
                    drop[target] = DROP_REL_TYPES[tname]
                    changed = True
                elif src_dropped and not target.lower().startswith(("word/media/", "xl/media/", "ppt/media/")):
                    drop[target] = ("dependent-part", Severity.INFO, f"제거된 파트({src})의 하위 파트")
                    changed = True

    for name, (cat, sev, desc) in sorted(drop.items()):
        fc.add(cat, sev, f"{desc} 제거", name)

    # 제거된 파트의 .rels 도 제거
    for name in list(pkg.parts):
        if name.endswith(".rels"):
            src = _source_of_rels(name)
            if src and pkg.exists(src) in drop:
                drop.setdefault(name, ("dependent-part", Severity.INFO, "제거된 파트의 관계 파일"))

    # 2) 관계 정리 --------------------------------------------------------
    removed_ids: dict[str, set[str]] = {}
    for rels_name, tree in rels_trees.items():
        if rels_name in drop:
            continue
        src = _source_of_rels(rels_name)
        for rel in list(tree.getroot().findall(f"{{{PR_NS}}}Relationship")):
            rid = rel.get("Id", "")
            target = rel.get("Target", "")
            tname = _rel_type_name(rel.get("Type", ""))
            remove = False
            if rel.get("TargetMode") == "External":
                remove = _judge_external(tname, target, policy, fc, rels_name)
            else:
                resolved = pkg.exists(_resolve(src, target))
                if resolved and resolved in drop:
                    remove = True
            if remove:
                tree.getroot().remove(rel)
                removed_ids.setdefault(src, set()).add(rid)
        pkg.parts[rels_name] = serialize_xml(tree)

    # 3) 콘텐츠 형식 정리 ---------------------------------------------------
    for low, ov in overrides.items():
        real = pkg.exists(low)
        if real is None or real in drop:
            ct_root.remove(ov)
            continue
        ctype = ov.get("ContentType", "")
        if ctype in MAIN_TYPE_MAP:
            ov.set("ContentType", MAIN_TYPE_MAP[ctype])
            fc.add("macro-enabled-format", Severity.MEDIUM,
                   "매크로 사용/템플릿 형식을 일반 문서 형식으로 변환", real)
    remaining_bins = any(n.lower().endswith(".bin") for n in pkg.parts if n not in drop)
    for d in ct_root.findall(f"{{{CT_NS}}}Default"):
        if "vbaproject" in d.get("ContentType", "").lower() and not remaining_bins:
            ct_root.remove(d)
    pkg.parts[CONTENT_TYPES] = serialize_xml(ct_tree)

    # 4) 각 XML 파트 무해화 및 재직렬화 ----------------------------------------
    out: list[ZipEntry] = []
    for name, content in pkg.parts.items():
        if name in drop:
            continue
        low = name.lower()
        if name == CONTENT_TYPES or low.endswith(".rels"):
            out.append(ZipEntry(name, content))
            continue
        if low.endswith((".xml", ".vml")) or content.lstrip()[:5] == b"<?xml":
            tree = parse_xml(content, name)
            _sanitize_part(tree.getroot(), name, removed_ids.get(name, set()), policy, fc)
            out.append(ZipEntry(name, serialize_xml(tree)))
            continue
        if policy.sanitize_embedded_images:
            itype = detect(content)
            if itype in (FileType.PNG, FileType.JPEG, FileType.GIF, FileType.BMP):
                sub = FindingCollector()
                content = sanitize_image(content, itype, policy, sub)
                for f in sub.findings:
                    fc.add(f.category, f.severity, f.description, name)
        out.append(ZipEntry(name, content))

    return write_zip(out, first=(CONTENT_TYPES,))


def _judge_external(tname: str, target: str, policy: Policy, fc: FindingCollector, where: str) -> bool:
    """외부 관계를 제거해야 하면 True."""
    if tname == "hyperlink":
        scheme = urlsplit(target.strip()).scheme.lower()
        if scheme not in policy.allowed_uri_schemes:
            fc.add("dangerous-link", Severity.HIGH, f"허용되지 않은 링크 제거: {target[:200]}", where)
            return True
        if policy.remove_hyperlinks:
            fc.add("hyperlink", Severity.LOW, f"하이퍼링크 제거(정책): {target[:200]}", where)
            return True
        return False
    cat, sev, desc = EXTERNAL_REL_RISK.get(
        tname, ("external-resource", Severity.MEDIUM, f"외부 참조({tname})")
    )
    fc.add(cat, sev, f"{desc} 제거: {target[:200]}", where)
    return True


def _sanitize_part(root: etree._Element, name: str, removed: set[str], policy: Policy,
                   fc: FindingCollector) -> None:
    low = name.lower()

    # 제거된 관계를 참조하는 요소 정리
    if removed:
        targets: list[tuple[etree._Element, str]] = []
        for el in root.iter():
            if not isinstance(el.tag, str):
                continue
            for k, v in el.attrib.items():
                if k.startswith(f"{{{R_NS}}}") and v in removed:
                    targets.append((el, k))
                    break
        for el, attr in targets:
            if el is root or not _attached(el, root):
                continue  # 이미 상위 요소와 함께 제거됨
            local = _local(el.tag)
            if local == "hyperlink":
                _unwrap(el)
            elif local == "blip":
                del el.attrib[attr]
            elif local == "oleObj":
                frame = next((a for a in el.iterancestors() if _local(a.tag) == "graphicFrame"), None)
                _remove(frame if frame is not None else el)
            else:
                _remove(el)

    if low.startswith("word/"):
        _sanitize_word_fields(root, name, fc)
    elif low.startswith("xl/worksheets/"):
        _sanitize_excel_formulas(root, name, fc)
    elif low == "xl/workbook.xml":
        _sanitize_excel_workbook(root, name, fc)
    elif low.startswith("xl/tables/"):
        _sanitize_excel_table(root)
    elif low.startswith("ppt/"):
        _sanitize_ppt_actions(root, name, fc)
    elif low == "docprops/core.xml" and policy.strip_metadata:
        for tag in (f"{{{DC_NS}}}creator", f"{{{CP_NS}}}lastModifiedBy"):
            for el in root.iter(tag):
                if el.text:
                    fc.add("metadata", Severity.INFO, f"작성자 정보 제거({_local(tag)})", name)
                    el.text = ""


def _sanitize_word_fields(root: etree._Element, name: str, fc: FindingCollector) -> None:
    W = f"{{{W_NS}}}"
    stack: list[list[etree._Element]] = []
    for el in root.iter():
        tag = el.tag
        if tag == W + "fldChar":
            kind = el.get(W + "fldCharType")
            if kind == "begin":
                stack.append([])
            elif kind == "end" and stack:
                instrs = stack.pop()
                code = "".join(i.text or "" for i in instrs)
                if _dangerous_field(code):
                    fc.add("dde", Severity.HIGH, f"위험 필드 코드 무력화: {code.strip()[:120]}", name)
                    for i in instrs:
                        i.text = ""
        elif tag in (W + "instrText", W + "delInstrText"):
            for level in stack:
                level.append(el)

    for fld in list(root.iter(W + "fldSimple")):
        code = fld.get(W + "instr", "")
        if _dangerous_field(code):
            fc.add("dde", Severity.HIGH, f"위험 필드 코드 무력화: {code.strip()[:120]}", name)
            _unwrap(fld)


def _dangerous_field(code: str) -> bool:
    return bool(WORD_FIELD_RE.search(code) or WORD_QUOTE_OBFUSCATION_RE.search(code))


def _strip_string_literals(formula: str) -> str:
    return re.sub(r'"[^"]*"', '""', formula)


def _sanitize_excel_formulas(root: etree._Element, name: str, fc: FindingCollector) -> None:
    for f in list(root.iter(f"{{{S_NS}}}f")):
        formula = _strip_string_literals(f.text or "")
        # 시트 이름 인용('Sheet 1'!A1) 안의 파이프는 무시할 수 없으므로 DDE 형태(앱|'토픽'!)만 본다
        if re.search(r"[A-Za-z0-9_.\-]+\s*\|\s*'?[^']*'?\s*!", formula) or EXCEL_FORMULA_FUNC_RE.search(formula):
            fc.add("dde", Severity.HIGH, f"위험 수식 제거(캐시 값 유지): ={(f.text or '')[:120]}", name)
            _remove(f)


def _sanitize_excel_workbook(root: etree._Element, name: str, fc: FindingCollector) -> None:
    for dn in list(root.iter(f"{{{S_NS}}}definedName")):
        if AUTO_NAME_RE.match(dn.get("name", "")):
            fc.add("auto-exec", Severity.HIGH, f"자동 실행 이름 제거: {dn.get('name')}", name)
            _remove(dn)


def _sanitize_excel_table(root: etree._Element) -> None:
    if root.get("tableType") == "queryTable":
        del root.attrib["tableType"]
        root.attrib.pop("connectionId", None)
    for col in root.iter(f"{{{S_NS}}}tableColumn"):
        col.attrib.pop("queryTableFieldId", None)


def _sanitize_ppt_actions(root: etree._Element, name: str, fc: FindingCollector) -> None:
    for el in list(root.iter()):
        if not isinstance(el.tag, str):
            continue
        action = (el.get("action") or "").lower()
        if action.startswith(PPT_DANGEROUS_ACTION):
            fc.add("auto-exec", Severity.HIGH, f"프로그램/매크로 실행 액션 제거: {action[:120]}", name)
            _remove(el)
