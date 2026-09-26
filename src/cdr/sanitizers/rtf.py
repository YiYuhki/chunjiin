"""RTF CDR.

RTF 를 토큰 단위로 파싱하여 위험한 대상(destination) 그룹을 통째로 제거한다.

제거 대상
- OLE 개체(\\object, \\objdata, \\objclass) - CVE-2017-11882, CVE-2017-0199 등 악용 경로
- \\*\\datastore, \\*\\oleclsid
- 원격 템플릿(\\*\\template)
- DDE/INCLUDEPICTURE 등 위험 필드 코드(\\*\\fldinst)
- 최상위 그룹 종료 후 덧붙은 데이터
"""

from __future__ import annotations

import re

from ..errors import BlockedError
from ..policy import Policy
from ..report import FindingCollector, Severity
from .ooxml import WORD_FIELD_RE, WORD_QUOTE_OBFUSCATION_RE

CTRL_RE = re.compile(rb"\\([a-zA-Z]{1,32})(-?\d{1,10})? ?")
GROUP_HEAD_RE = re.compile(rb"\{[\r\n ]*(\\\*[\r\n ]*)?\\([a-zA-Z]{1,32})")
MAX_DEPTH = 1000

DROP_GROUPS: dict[bytes, tuple[str, Severity, str]] = {
    b"object": ("embedded-object", Severity.HIGH, "OLE 개체"),
    b"objdata": ("embedded-object", Severity.HIGH, "OLE 개체 데이터"),
    b"objclass": ("embedded-object", Severity.HIGH, "OLE 개체 클래스"),
    b"datastore": ("embedded-object", Severity.HIGH, "데이터 저장소(datastore)"),
    b"oleclsid": ("embedded-object", Severity.MEDIUM, "OLE 클래스 ID"),
    b"template": ("template-injection", Severity.CRITICAL, "원격/첨부 템플릿"),
    b"objalias": ("embedded-object", Severity.MEDIUM, "OLE 개체 별칭"),
    b"objsect": ("embedded-object", Severity.MEDIUM, "OLE 개체 섹션"),
}
STRIP_WORDS = {b"objupdate", b"objautlink", b"objlink"}


def _group_end(data: bytes, start: int) -> int:
    depth = 0
    i, n = start, len(data)
    while i < n:
        c = data[i]
        if c == 0x5C:  # '\\'
            m = CTRL_RE.match(data, i)
            if m:
                i = m.end()
                if m.group(1) == b"bin":
                    i += max(0, int(m.group(2) or 0))
                continue
            i += 2
            continue
        if c == 0x7B:
            depth += 1
        elif c == 0x7D:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def _plain_text(group: bytes) -> str:
    text = CTRL_RE.sub(b" ", group)
    text = re.sub(rb"\\[^a-zA-Z]", b" ", text).replace(b"{", b" ").replace(b"}", b" ")
    return text.decode("latin-1")


def sanitize_rtf(data: bytes, policy: Policy, fc: FindingCollector) -> bytes:
    if not data.startswith(b"{\\rtf"):
        raise BlockedError("올바른 RTF 헤더가 아님", "structure")

    out = bytearray()
    i, n, depth = 0, len(data), 0
    while i < n:
        c = data[i]
        if c == 0x7B:  # '{'
            m = GROUP_HEAD_RE.match(data, i)
            if m:
                word = m.group(2)
                if word in DROP_GROUPS:
                    end = _group_end(data, i)
                    if end == -1:
                        raise BlockedError("닫히지 않은 RTF 그룹", "structure")
                    cat, sev, desc = DROP_GROUPS[word]
                    fc.add(cat, sev, f"{desc} 그룹 제거 ({end - i} bytes)", f"offset {i}")
                    i = end
                    continue
                if word == b"fldinst":
                    end = _group_end(data, i)
                    if end == -1:
                        raise BlockedError("닫히지 않은 RTF 그룹", "structure")
                    code = _plain_text(data[i:end])
                    if WORD_FIELD_RE.search(code) or WORD_QUOTE_OBFUSCATION_RE.search(code):
                        fc.add("dde", Severity.HIGH, f"위험 필드 코드 제거: {' '.join(code.split())[:120]}",
                               f"offset {i}")
                        i = end
                        continue
            depth += 1
            if depth > MAX_DEPTH:
                raise BlockedError("RTF 그룹 중첩 깊이 초과", "structure")
            out.append(c)
            i += 1
            continue
        if c == 0x7D:  # '}'
            depth -= 1
            if depth < 0:
                raise BlockedError("RTF 괄호 불균형", "structure")
            out.append(c)
            i += 1
            if depth == 0:
                rest = data[i:]
                if rest.strip(b"\r\n\t \x00"):
                    fc.add("hidden-data", Severity.HIGH,
                           f"문서 종료 후 덧붙은 데이터 {len(rest)} bytes 제거", f"offset {i}")
                break
            continue
        if c == 0x5C:  # '\\'
            m = CTRL_RE.match(data, i)
            if m:
                word = m.group(1)
                end = m.end()
                if word == b"bin":
                    end += max(0, int(m.group(2) or 0))
                if word in STRIP_WORDS:
                    fc.add("embedded-object", Severity.MEDIUM, f"개체 자동 갱신 지시어 제거(\\{word.decode()})",
                           f"offset {i}")
                else:
                    out += data[i:end]
                i = end
                continue
            out += data[i:i + 2]
            i += 2
            continue
        out.append(c)
        i += 1

    if depth != 0:
        raise BlockedError("RTF 괄호 불균형(문서가 닫히지 않음)", "structure")
    return bytes(out)
