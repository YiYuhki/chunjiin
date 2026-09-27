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
    if kind == ImageKind::Gif {
        if let Some(out) = reencode_animated_gif(data, policy)? {
            return Ok((out, ImageKind::Gif));
        }
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

/// 애니메이션 GIF 의 최대 프레임 수
const MAX_GIF_FRAMES: usize = 1000;

/// 애니메이션 GIF 를 프레임마다 화소로 풀어(합성된 전체 화면) 새 GIF 로 쓴다. 프레임 지연은
/// 유지하고 반복은 무한으로 쓴다. 프레임이 하나뿐이면 None (정지 그림으로 처리).
/// 프레임을 하나씩 풀고 바로 쓰므로 메모리는 한 프레임 크기만 쓴다. 프레임 수와 전체 화소
/// (그림 하나 한도의 1/4)를 넘는 뒷부분은 옮기지 않는다
fn reencode_animated_gif(data: &[u8], policy: &Policy) -> Result<Option<Vec<u8>>> {
    use image::codecs::gif::{GifDecoder, GifEncoder, Repeat};
    use image::{AnimationDecoder, ImageDecoder};
    let Ok(mut dec) = GifDecoder::new(Cursor::new(data)) else {
        return blocked("image", "GIF 헤더 해석 실패");
    };
    let (w, h) = dec.dimensions();
    let px = u64::from(w) * u64::from(h);
    if px == 0 || px > policy.max_image_pixels {
        return blocked("image-bomb", format!("이미지 크기 초과 ({w}x{h})"));
    }
    let mut limits = Limits::default();
    limits.max_alloc = Some(policy.max_image_pixels.saturating_mul(8));
    if dec.set_limits(limits).is_err() {
        return blocked("image-bomb", "GIF 메모리 한도 초과");
    }
    let budget = (policy.max_image_pixels / 4).max(px);
    let mut frames = dec.into_frames();
    let Some(first) = frames.next() else {
        return blocked("image", "GIF 프레임 없음");
    };
    let Ok(first) = first else {
        return blocked("image", "GIF 디코딩 실패");
    };
    let Some(second) = frames.next() else {
        return Ok(None);
    };
    let mut out = Vec::new();
    {
        let mut enc = GifEncoder::new_with_speed(&mut out, 10);
        if enc.set_repeat(Repeat::Infinite).is_err() {
            return blocked("reconstruct", "GIF 재인코딩 실패");
        }
        let mut used = 0u64;
        for (i, f) in std::iter::once(Ok(first))
            .chain(std::iter::once(second))
            .chain(frames)
            .enumerate()
        {
            used = used.saturating_add(px);
            if i >= MAX_GIF_FRAMES || used > budget {
                break;
            }
            // 깨진 뒤쪽 프레임은 거기까지만 옮긴다
            let Ok(f) = f else {
                if i == 0 {
                    return blocked("image", "GIF 디코딩 실패");
                }
                break;
            };
            if enc.encode_frame(f).is_err() {
                return blocked("reconstruct", "GIF 재인코딩 실패");
            }
        }
    }
    Ok(Some(out))
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

/// CMYK JPEG 을 원시 CMYK 표본으로 푼다 (색 변환 없이 JPEG 에 저장된 값 그대로).
/// 반환: (표본, 폭, 높이, Adobe APP14 표식 여부). YCCK 등 다른 입력 형식이면 None
pub fn decode_cmyk_jpeg(data: &[u8], policy: &Policy) -> Option<(Vec<u8>, usize, usize, bool)> {
    use zune_core::colorspace::ColorSpace;
    use zune_core::options::DecoderOptions;
    let max = policy.max_image_pixels.min(1 << 28) as usize;
    let opts = DecoderOptions::default()
        .jpeg_set_out_colorspace(ColorSpace::CMYK)
        .set_max_width(max.min(1 << 16))
        .set_max_height(max.min(1 << 16));
    let mut d = zune_jpeg::JpegDecoder::new_with_options(Cursor::new(data), opts);
    d.decode_headers().ok()?;
    match d.input_colorspace()? {
        ColorSpace::CMYK => {}
        // YCCK(Adobe 변환 2): 성분을 그대로 받아 libjpeg 와 같이 CMYK 로 바꾼다
        ColorSpace::YCCK => {
            let mut d = zune_jpeg::JpegDecoder::new_with_options(
                Cursor::new(data),
                opts.jpeg_set_out_colorspace(ColorSpace::YCCK),
            );
            d.decode_headers().ok()?;
            let (w, h) = d.dimensions()?;
            if (w as u64).checked_mul(h as u64)? > policy.max_image_pixels {
                return None;
            }
            let mut px = d.decode().ok()?;
            if px.len() != w.checked_mul(h)?.checked_mul(4)? {
                return None;
            }
            for p in px.as_chunks_mut::<4>().0 {
                let (y, cb, cr) = (
                    f32::from(p[0]),
                    f32::from(p[1]) - 128.0,
                    f32::from(p[2]) - 128.0,
                );
                let c = |v: f32| 255 - v.round().clamp(0.0, 255.0) as u8;
                p[0] = c(y + 1.402 * cr);
                p[1] = c(y - 0.344_136 * cb - 0.714_136 * cr);
                p[2] = c(y + 1.772 * cb);
            }
            return Some((px, w, h, true));
        }
        _ => return None,
    }
    let (w, h) = d.dimensions()?;
    if (w as u64).checked_mul(h as u64)? > policy.max_image_pixels {
        return None;
    }
    let px = d.decode().ok()?;
    if px.len() != w.checked_mul(h)?.checked_mul(4)? {
        return None;
    }
    let adobe = data
        .windows(9)
        .any(|x| x[0] == 0xFF && x[1] == 0xEE && &x[4..9] == b"Adobe");
    Some((px, w, h, adobe))
}
