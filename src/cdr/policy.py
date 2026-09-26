"""CDR 정책 설정."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Policy:
    # 입력 제한
    max_file_size: int = 100 * 1024 * 1024

    # 압축 컨테이너(OOXML/HWPX) 제한 - Zip bomb 방어
    max_zip_entries: int = 10_000
    max_zip_uncompressed: int = 1024 * 1024 * 1024
    max_zip_ratio: float = 200.0

    # 이미지 제한 - 디컴프레션 폭탄 방어
    max_image_pixels: int = 150_000_000

    # 링크 정책
    remove_hyperlinks: bool = False
    allowed_uri_schemes: frozenset[str] = field(
        default_factory=lambda: frozenset({"http", "https", "mailto"})
    )

    # 메타데이터(작성자, 사용자 정의 속성, EXIF 등) 제거
    strip_metadata: bool = True

    # OOXML/HWPX 내부 이미지도 재인코딩
    sanitize_embedded_images: bool = True

    # CSV 수식 인젝션 방어
    neutralize_csv_formulas: bool = True

    # 재구성 결과를 다시 검사하여 잔여 위협이 있으면 차단
    verify_output: bool = True
