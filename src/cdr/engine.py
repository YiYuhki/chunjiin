"""CDR 엔진: 형식 판별 → 형식별 무해화/재구성 → 재검증 → 결과 보고."""

from __future__ import annotations

import logging
import posixpath

from .detect import OUTPUT_EXTENSION, FileType, detect, extension_matches, extension_of
from .errors import BlockedError
from .policy import Policy
from .report import CDRResult, FindingCollector, Severity, Status, sha256
from .sanitizers._zip import ZipEntry, read_zip, write_zip
from .sanitizers.hwpx import sanitize_hwpx
from .sanitizers.image import sanitize_image
from .sanitizers.ole import analyze_ole
from .sanitizers.ooxml import sanitize_ooxml
from .sanitizers.pdf import sanitize_pdf
from .sanitizers.rtf import sanitize_rtf
from .sanitizers.text import sanitize_csv, sanitize_text

log = logging.getLogger("cdr")

MAX_ARCHIVE_DEPTH = 3
IMAGE_TYPES = (FileType.PNG, FileType.JPEG, FileType.GIF, FileType.BMP, FileType.TIFF)
OOXML_TYPES = (FileType.DOCX, FileType.XLSX, FileType.PPTX)


class CDREngine:
    def __init__(self, policy: Policy | None = None) -> None:
        self.policy = policy or Policy()

    # ------------------------------------------------------------------
    def process(self, data: bytes, filename: str = "unnamed", _depth: int = 0) -> CDRResult:
        result = CDRResult(
            filename=filename,
            detected_type=FileType.UNKNOWN.value,
            status=Status.BLOCKED,
            input_sha256=sha256(data),
            input_size=len(data),
        )
        fc = FindingCollector()

        if len(data) > self.policy.max_file_size:
            return self._blocked(result, fc, f"파일 크기 제한 초과 ({len(data)} bytes)", "size")
        if not data:
            return self._blocked(result, fc, "빈 파일", "structure")

        ftype = detect(data, filename)
        result.detected_type = ftype.value

        if not extension_matches(ftype, filename):
            fc.add("type-mismatch", Severity.MEDIUM,
                   f"확장자(.{extension_of(filename)})와 실제 형식({ftype.value}) 불일치 - 확장자 교정",
                   filename)

        try:
            output = self._sanitize(data, ftype, filename, fc, _depth)
        except BlockedError as e:
            return self._blocked(result, fc, e.reason, e.category)
        except Exception as e:  # 예기치 못한 오류는 차단(fail-closed)
            log.exception("CDR 처리 중 예외: %s", filename)
            return self._blocked(result, fc, f"처리 중 오류: {type(e).__name__}: {e}", "internal")

        if self.policy.verify_output and ftype != FileType.ZIP:
            residual = self._verify(output, ftype, filename, _depth)
            if residual:
                return self._blocked(result, fc, f"재검증 실패 - 잔여 위협: {residual}", "verify")

        result.findings = fc.findings
        result.output = output
        result.output_sha256 = sha256(output)
        result.output_size = len(output)
        result.output_filename = self._output_name(filename, ftype)
        significant = [f for f in fc.findings if f.severity.rank >= Severity.LOW.rank]
        result.status = Status.SANITIZED if significant else Status.CLEAN
        return result

    # ------------------------------------------------------------------
    def _sanitize(self, data: bytes, ftype: FileType, filename: str, fc: FindingCollector, depth: int) -> bytes:
        p = self.policy
        if ftype == FileType.PDF:
            return sanitize_pdf(data, p, fc)
        if ftype in OOXML_TYPES:
            return sanitize_ooxml(data, ftype, p, fc)
        if ftype == FileType.HWPX:
            return sanitize_hwpx(data, p, fc)
        if ftype == FileType.RTF:
            return sanitize_rtf(data, p, fc)
        if ftype in IMAGE_TYPES:
            return sanitize_image(data, ftype, p, fc)
        if ftype == FileType.CSV:
            delim = "\t" if extension_of(filename) == "tsv" else ","
            return sanitize_csv(data, p, fc, delimiter=delim)
        if ftype == FileType.TEXT:
            return sanitize_text(data, p, fc)
        if ftype == FileType.ZIP:
            return self._sanitize_archive(data, fc, depth)
        if ftype == FileType.OLE:
            raise BlockedError(analyze_ole(data, p, fc), "legacy-format")
        if data[:2] == b"MZ" or data[:4] == b"\x7fELF":
            raise BlockedError("실행 파일은 허용되지 않습니다", "executable")
        raise BlockedError("지원하지 않는 파일 형식", "unsupported")

    def _sanitize_archive(self, data: bytes, fc: FindingCollector, depth: int) -> bytes:
        if depth >= MAX_ARCHIVE_DEPTH:
            raise BlockedError("압축 파일 중첩 깊이 초과", "zip-bomb")
        out: list[ZipEntry] = []
        used: set[str] = set()
        for entry in read_zip(data, self.policy, fc):
            sub = self.process(entry.data, posixpath.basename(entry.name), _depth=depth + 1)
            if sub.status == Status.BLOCKED:
                fc.add("archive-entry", Severity.HIGH, f"압축 내 파일 차단·제거: {sub.reason}", entry.name)
                continue
            for f in sub.findings:
                fc.add(f.category, f.severity, f.description, f"{entry.name}:{f.location}")
            name = posixpath.join(posixpath.dirname(entry.name), sub.output_filename)
            if name.lower() in used:
                continue
            used.add(name.lower())
            out.append(ZipEntry(name, sub.output))
        return write_zip(out)

    def _verify(self, output: bytes, ftype: FileType, filename: str, depth: int) -> str:
        """재구성 결과를 다시 무해화기에 통과시켜 MEDIUM 이상 탐지가 남아 있는지 확인한다."""
        out_type = detect(output, self._output_name(filename, ftype))
        if out_type != ftype:
            return f"재구성 결과 형식 불일치({out_type.value})"
        fc = FindingCollector()
        try:
            self._sanitize(output, ftype, self._output_name(filename, ftype), fc, depth)
        except BlockedError as e:
            return e.reason
        residual = [f for f in fc.findings if f.severity.rank >= Severity.MEDIUM.rank]
        return "; ".join(f"{f.category}: {f.description}" for f in residual[:5])

    @staticmethod
    def _output_name(filename: str, ftype: FileType) -> str:
        base = posixpath.basename(filename.replace("\\", "/")) or "unnamed"
        stem = base.rsplit(".", 1)[0] if "." in base else base
        ext = OUTPUT_EXTENSION.get(ftype)
        if ftype == FileType.ZIP:
            ext = "zip"
        return f"{stem}.{ext}" if ext else stem

    @staticmethod
    def _blocked(result: CDRResult, fc: FindingCollector, reason: str, category: str) -> CDRResult:
        fc.add(category, Severity.HIGH, reason, removed=False)
        result.status = Status.BLOCKED
        result.reason = reason
        result.findings = fc.findings
        result.output = None
        return result
