"""텍스트/CSV CDR.

- 알려진 인코딩으로 디코딩 가능한지 검증 후 UTF-8 로 재작성
- 제어 문자 제거, 양방향(BiDi) 오버라이드 문자(RLO 등) 제거
- CSV 수식 인젝션(=, +, -, @, 탭, CR 로 시작하는 셀) 무력화
"""

from __future__ import annotations

import csv
import io
import re

from ..errors import BlockedError
from ..policy import Policy
from ..report import FindingCollector, Severity

CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
BIDI_RE = re.compile(r"[‪-‮⁦-⁩]")
FORMULA_PREFIX = ("=", "+", "-", "@", "\t", "\r")
NUMERIC_RE = re.compile(r"^[+-]?(\d+([.,]\d*)?|[.,]\d+)([eE][+-]?\d+)?$")


def _decode(data: bytes) -> str:
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    for enc in ("utf-8", "cp949"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    raise BlockedError("텍스트 인코딩 판별 실패", "structure")


def _clean_text(text: str, fc: FindingCollector) -> str:
    n_ctrl = len(CONTROL_RE.findall(text))
    if n_ctrl:
        fc.add("control-char", Severity.LOW, f"제어 문자 {n_ctrl}개 제거")
        text = CONTROL_RE.sub("", text)
    n_bidi = len(BIDI_RE.findall(text))
    if n_bidi:
        fc.add("bidi-override", Severity.MEDIUM, f"양방향 제어 문자 {n_bidi}개 제거(텍스트 위장 방지)")
        text = BIDI_RE.sub("", text)
    return text


def sanitize_text(data: bytes, policy: Policy, fc: FindingCollector) -> bytes:
    return _clean_text(_decode(data), fc).encode("utf-8")


def sanitize_csv(data: bytes, policy: Policy, fc: FindingCollector, delimiter: str = ",") -> bytes:
    text = _clean_text(_decode(data), fc)
    if not policy.neutralize_csv_formulas:
        return text.encode("utf-8")

    try:
        rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delimiter))
    except csv.Error as e:
        raise BlockedError(f"CSV 파싱 실패: {e}", "structure") from e

    count = 0
    for r, row in enumerate(rows):
        for c, cell in enumerate(row):
            if cell.startswith(FORMULA_PREFIX) and not NUMERIC_RE.match(cell):
                row[c] = "'" + cell
                count += 1
                if count <= 20:
                    fc.add("csv-injection", Severity.HIGH, f"수식 인젝션 무력화: {cell[:80]}", f"row {r + 1}, col {c + 1}")
    if count > 20:
        fc.add("csv-injection", Severity.HIGH, f"이외 수식 인젝션 {count - 20}건 무력화")

    buf = io.StringIO(newline="")
    csv.writer(buf, delimiter=delimiter, lineterminator="\r\n").writerows(rows)
    return buf.getvalue().encode("utf-8")
