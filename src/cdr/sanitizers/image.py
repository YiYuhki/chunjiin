"""이미지 CDR: 픽셀 데이터만 추출하여 새 이미지로 재인코딩한다.

- EXIF/XMP/주석 등 메타데이터 제거
- 파일 끝에 덧붙은 데이터(폴리글롯, 은닉 페이로드) 제거
- 디컴프레션 폭탄 차단
"""

from __future__ import annotations

import io
import warnings

from PIL import Image, ImageOps, ImageSequence

from ..detect import FileType
from ..errors import BlockedError
from ..policy import Policy
from ..report import FindingCollector, Severity

_PIL_FORMAT = {
    FileType.PNG: "PNG",
    FileType.JPEG: "JPEG",
    FileType.GIF: "GIF",
    FileType.BMP: "BMP",
    FileType.TIFF: "TIFF",
}


def _trailing_bytes(data: bytes, ftype: FileType) -> int:
    if ftype == FileType.PNG:
        idx = data.rfind(b"IEND")
        if idx != -1:
            return max(0, len(data) - (idx + 8))
    elif ftype == FileType.JPEG:
        idx = data.rfind(b"\xff\xd9")
        if idx != -1:
            return max(0, len(data) - (idx + 2))
    elif ftype == FileType.GIF:
        if not data.endswith(b"\x3b"):
            idx = data.rfind(b"\x00\x3b")
            if idx != -1:
                return len(data) - (idx + 2)
    return 0


def sanitize_image(data: bytes, ftype: FileType, policy: Policy, fc: FindingCollector) -> bytes:
    fmt = _PIL_FORMAT.get(ftype)
    if fmt is None:
        raise BlockedError(f"지원하지 않는 이미지 형식: {ftype.value}", "unsupported")

    trailing = _trailing_bytes(data, ftype)
    if trailing > 16:
        fc.add("hidden-data", Severity.HIGH, f"이미지 끝에 덧붙은 데이터 {trailing} bytes 제거", "trailer")

    Image.MAX_IMAGE_PIXELS = policy.max_image_pixels
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as probe:
                probe.verify()
            img = Image.open(io.BytesIO(data))
            img.load()
    except (Image.DecompressionBombError, Image.DecompressionBombWarning) as e:
        raise BlockedError(f"디컴프레션 폭탄 의심: {e}", "image-bomb") from e
    except Exception as e:  # Pillow 는 다양한 예외를 던진다
        raise BlockedError(f"이미지 디코딩 실패: {e}", "structure") from e

    benign = {"transparency", "duration", "loop", "background", "dpi", "gamma", "aspect"}
    meta_keys = [k for k in img.info if k not in benign and not str(k).startswith("jfif")]
    if meta_keys and policy.strip_metadata:
        fc.add("metadata", Severity.INFO, "이미지 메타데이터 제거: " + ", ".join(sorted(map(str, meta_keys))[:10]))
    if ftype == FileType.JPEG and img.getexif():
        fc.add("metadata", Severity.INFO, "EXIF 제거 (회전 정보는 픽셀에 적용)")

    out = io.BytesIO()
    try:
        if ftype == FileType.GIF and getattr(img, "n_frames", 1) > 1:
            frames = [f.copy() for f in ImageSequence.Iterator(img)]
            for f in frames:
                f.info = {k: v for k, v in f.info.items() if k in ("duration", "transparency")}
            frames[0].save(
                out, format="GIF", save_all=True, append_images=frames[1:],
                loop=img.info.get("loop", 0), duration=img.info.get("duration", 100),
            )
        else:
            if ftype == FileType.JPEG:
                img = ImageOps.exif_transpose(img)
            clean = _rebuild(img)
            params: dict = {}
            if ftype == FileType.JPEG:
                if clean.mode not in ("RGB", "L", "CMYK"):
                    clean = clean.convert("RGB")
                params = {"quality": 95, "subsampling": 0}
            if "transparency" in img.info and ftype in (FileType.PNG, FileType.GIF):
                params["transparency"] = img.info["transparency"]
            if not policy.strip_metadata and "dpi" in img.info:
                params["dpi"] = img.info["dpi"]
            clean.save(out, format=fmt, **params)
    except Exception as e:
        raise BlockedError(f"이미지 재인코딩 실패: {e}", "reconstruct") from e
    finally:
        img.close()
    return out.getvalue()


def _rebuild(img: Image.Image) -> Image.Image:
    """원본 객체의 info/부가 정보를 가져오지 않도록 픽셀만으로 새 이미지를 만든다."""
    clean = Image.frombytes(img.mode, img.size, img.tobytes())
    if img.mode == "P":
        palette = img.getpalette()
        if palette:
            clean.putpalette(palette)
    return clean
