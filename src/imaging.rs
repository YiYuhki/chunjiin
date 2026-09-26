//! 이미지 재조합: 픽셀만 디코딩하여 새 이미지로 인코딩한다.
//! 메타데이터(EXIF/XMP/텍스트 청크), 덧붙은 데이터, 폴리글롯 페이로드가 모두 사라진다.

use std::io::Cursor;

use image::{DynamicImage, ImageFormat, ImageReader, Limits};

use crate::error::{blocked, Result};
use crate::policy::Policy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageKind {
    Png,
    Jpeg,
    Gif,
    Bmp,
}

impl ImageKind {
    pub fn sniff(data: &[u8]) -> Option<ImageKind> {
        if data.starts_with(b"\x89PNG\r\n\x1a\n") {
            Some(ImageKind::Png)
        } else if data.starts_with(b"\xff\xd8\xff") {
            Some(ImageKind::Jpeg)
        } else if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
            Some(ImageKind::Gif)
        } else if data.starts_with(b"BM") && data.len() > 26 {
            Some(ImageKind::Bmp)
        } else {
            None
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            ImageKind::Png => "png",
            ImageKind::Jpeg => "jpeg",
            ImageKind::Gif => "gif",
            ImageKind::Bmp => "bmp",
        }
    }

    pub fn mime(self) -> &'static str {
        match self {
            ImageKind::Png => "image/png",
            ImageKind::Jpeg => "image/jpeg",
            ImageKind::Gif => "image/gif",
            ImageKind::Bmp => "image/bmp",
        }
    }

    fn format(self) -> ImageFormat {
        match self {
            ImageKind::Png => ImageFormat::Png,
            ImageKind::Jpeg => ImageFormat::Jpeg,
            ImageKind::Gif => ImageFormat::Gif,
            ImageKind::Bmp => ImageFormat::Bmp,
        }
    }
}

pub fn decode(data: &[u8], kind: ImageKind, policy: &Policy) -> Result<DynamicImage> {
    let mut reader = ImageReader::with_format(Cursor::new(data), kind.format());
    let mut limits = Limits::default();
    limits.max_alloc = Some(policy.max_image_pixels.saturating_mul(4));
    reader.limits(limits);
    let (w, h) = match reader.into_dimensions() {
        Ok(d) => d,
        Err(e) => return blocked("image", format!("이미지 헤더 해석 실패: {e}")),
    };
    if (w as u64) * (h as u64) > policy.max_image_pixels {
        return blocked("image-bomb", format!("이미지 크기 초과 ({w}x{h})"));
    }
    let mut reader = ImageReader::with_format(Cursor::new(data), kind.format());
    let mut limits = Limits::default();
    limits.max_alloc = Some(policy.max_image_pixels.saturating_mul(8));
    reader.limits(limits);
    match reader.decode() {
        Ok(img) => Ok(img),
        Err(e) => blocked("image", format!("이미지 디코딩 실패: {e}")),
    }
}

/// 이미지를 같은 형식으로 재인코딩한다. BMP 는 PNG 로 변환한다.
pub fn reencode(data: &[u8], kind: ImageKind, policy: &Policy) -> Result<(Vec<u8>, ImageKind)> {
    if policy.media_passthrough {
        check_header(data, kind, policy)?;
        return Ok((data.to_vec(), kind));
    }
    let img = decode(data, kind, policy)?;
    let (img, target) = match kind {
        ImageKind::Jpeg => (DynamicImage::ImageRgb8(img.to_rgb8()), ImageKind::Jpeg),
        ImageKind::Gif => (img, ImageKind::Gif),
        ImageKind::Bmp | ImageKind::Png => (img, ImageKind::Png),
    };
    let mut out = Cursor::new(Vec::new());
    let r = match target {
        ImageKind::Jpeg => {
            let enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 92);
            img.write_with_encoder(enc)
        }
        _ => img.write_to(&mut out, target.format()),
    };
    if let Err(e) = r {
        return blocked("reconstruct", format!("이미지 재인코딩 실패: {e}"));
    }
    Ok((out.into_inner(), target))
}

/// 이미지를 원래 형식 그대로(BMP 포함) 재인코딩한다. 형식 정보가 문서 안에 따로
/// 기록되는 레거시 문서(HWP 등)에서 사용한다.
pub fn reencode_same(data: &[u8], kind: ImageKind, policy: &Policy) -> Result<Vec<u8>> {
    if policy.media_passthrough {
        check_header(data, kind, policy)?;
        return Ok(data.to_vec());
    }
    if kind != ImageKind::Bmp {
        let (bytes, out) = reencode(data, kind, policy)?;
        if out == kind {
            return Ok(bytes);
        }
    }
    let img = decode(data, kind, policy)?;
    let mut out = Cursor::new(Vec::new());
    match img.write_to(&mut out, kind.format()) {
        Ok(()) => Ok(out.into_inner()),
        Err(e) => blocked("reconstruct", format!("이미지 재인코딩 실패: {e}")),
    }
}

/// 헤더만 읽어 크기 제한을 검사한다 (재검증 단계용)
fn check_header(data: &[u8], kind: ImageKind, policy: &Policy) -> Result<()> {
    match ImageReader::with_format(Cursor::new(data), kind.format()).into_dimensions() {
        Ok((w, h)) if (w as u64) * (h as u64) <= policy.max_image_pixels => Ok(()),
        Ok((w, h)) => blocked("image-bomb", format!("이미지 크기 초과 ({w}x{h})")),
        Err(e) => blocked("image", format!("이미지 헤더 해석 실패: {e}")),
    }
}
