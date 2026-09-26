"""CDR 처리 결과와 탐지 항목(Finding) 모델."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)


class Status(str, Enum):
    CLEAN = "clean"          # 위협 요소 없음, 재구성된 파일 제공
    SANITIZED = "sanitized"  # 위협 요소 제거 후 재구성된 파일 제공
    BLOCKED = "blocked"      # 무해화 불가 → 파일 차단


@dataclass
class Finding:
    category: str
    severity: Severity
    description: str
    location: str = ""
    removed: bool = True

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class CDRResult:
    filename: str
    detected_type: str
    status: Status
    findings: list[Finding] = field(default_factory=list)
    output: bytes | None = None
    output_filename: str | None = None
    input_sha256: str = ""
    output_sha256: str = ""
    input_size: int = 0
    output_size: int = 0
    reason: str = ""

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "detected_type": self.detected_type,
            "status": self.status.value,
            "reason": self.reason,
            "output_filename": self.output_filename,
            "input_sha256": self.input_sha256,
            "output_sha256": self.output_sha256,
            "input_size": self.input_size,
            "output_size": self.output_size,
            "max_severity": self.max_severity.value if self.max_severity else None,
            "findings": [f.to_dict() for f in self.findings],
        }


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FindingCollector:
    """새니타이저가 탐지 항목을 누적하는 헬퍼."""

    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def add(
        self,
        category: str,
        severity: Severity,
        description: str,
        location: str = "",
        removed: bool = True,
    ) -> None:
        self.findings.append(Finding(category, severity, description, location, removed))

    def __len__(self) -> int:
        return len(self.findings)
