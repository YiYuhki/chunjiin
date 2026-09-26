"""레거시 OLE 복합 문서(doc/xls/ppt/hwp) 분석.

바이너리 레거시 형식은 안전한 재구성이 어려우므로 기본 정책은 차단이다.
차단 사유를 명확히 알리기 위해 매크로/스크립트/암호화 여부를 분석한다.
"""

from __future__ import annotations

import io

import olefile

from ..policy import Policy
from ..report import FindingCollector, Severity


def analyze_ole(data: bytes, policy: Policy, fc: FindingCollector) -> str:
    """분석 결과를 기록하고 차단 사유 문자열을 반환한다."""
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception as e:
        fc.add("structure", Severity.HIGH, f"손상된 OLE 컨테이너: {e}", removed=False)
        return "손상된 OLE 복합 문서"

    with ole:
        streams = ["/".join(s) for s in ole.listdir(streams=True, storages=True)]
        lower = [s.lower() for s in streams]

        kind = "레거시 Office/HWP 바이너리 문서"
        if any(s == "encryptedpackage" for s in lower):
            fc.add("encryption", Severity.HIGH, "암호화된 Office 문서 - 내용 검사 불가", removed=False)
            return "암호화된 문서는 검사할 수 없어 차단합니다"
        if "fileheader" in lower and any(s.startswith("bodytext") for s in lower):
            kind = "HWP 5.x 바이너리 문서"
        elif "worddocument" in lower:
            kind = "Word 97-2003 문서"
        elif "workbook" in lower or "book" in lower:
            kind = "Excel 97-2003 통합 문서"
        elif "powerpoint document" in lower:
            kind = "PowerPoint 97-2003 프레젠테이션"

        if any(s.startswith(("macros", "_vba_project_cur")) or "/vba/" in f"/{s}/" for s in lower):
            fc.add("macro", Severity.CRITICAL, "VBA 매크로 포함", removed=False)
        if any(s.startswith("scripts/") for s in lower):
            fc.add("macro", Severity.CRITICAL, "HWP 문서 스크립트 포함", removed=False)
        if any(s.startswith("objectpool") or "\x01ole10native" in s for s in lower):
            fc.add("embedded-object", Severity.HIGH, "OLE 임베디드 개체 포함", removed=False)
        if "\x05summaryinformation" in lower:
            fc.add("metadata", Severity.INFO, "문서 요약 정보 포함", removed=False)

    return f"{kind}는 안전한 재구성이 불가하여 차단합니다 (OOXML/HWPX/PDF 로 변환 후 재시도)"
