//! 메타파일 안 비트맵(DIB) 정규화.
//!
//! 헤더 변형(CORE/INFO/V4/V5)은 40바이트 BITMAPINFOHEADER 로 바꾸고, 색상표는 선언된 개수만,
//! 화소는 너비·높이·비트 수로 계산한 크기만큼만 옮긴다. RLE·JPEG·PNG 압축은 풀어서 무압축으로 쓴다.

use super::rd;
use crate::error::Result;
use crate::imaging::{self, ImageKind};
use crate::legacy::blip::PixelBudget;
use crate::policy::Policy;

const BI_RGB: u32 = 0;
const BI_RLE8: u32 = 1;
const BI_RLE4: u32 = 2;
const BI_BITFIELDS: u32 = 3;
const BI_JPEG: u32 = 4;
const BI_PNG: u32 = 5;

/// 색상표 형식 (EMF/WMF 의 ColorUsage)
pub const DIB_RGB_COLORS: u32 = 0;
pub const DIB_PAL_COLORS: u32 = 1;

pub struct Dib {
    /// BITMAPINFOHEADER(40) + 마스크(BI_BITFIELDS) + 색상표
    pub info: Vec<u8>,
    pub bits: Vec<u8>,
}

struct Header {
    size: usize,
    width: i32,
    height: i32,
    bpp: u16,
    compression: u32,
    size_image: u32,
    x_ppm: i32,
    y_ppm: i32,
    colors_used: u32,
}

fn header(info: &[u8]) -> Option<Header> {
    let size = rd::u32(info, 0)? as usize;
    let h = if size == 12 {
        Header {
            size,
            width: rd::u16(info, 4)? as i32,
            height: rd::u16(info, 6)? as i32,
            bpp: rd::u16(info, 10)?,
            compression: BI_RGB,
            size_image: 0,
            x_ppm: 0,
            y_ppm: 0,
            colors_used: 0,
        }
    } else if [40, 52, 56, 64, 108, 124].contains(&size) {
        Header {
            size,
            width: rd::i32(info, 4)?,
            height: rd::i32(info, 8)?,
            bpp: rd::u16(info, 14)?,
            compression: rd::u32(info, 16)?,
            size_image: rd::u32(info, 20)?,
            x_ppm: rd::i32(info, 24)?,
            y_ppm: rd::i32(info, 28)?,
            colors_used: rd::u32(info, 32)?,
        }
    } else {
        return None;
    };
    let planes = rd::u16(info, if size == 12 { 8 } else { 12 })?;
    (planes == 1).then_some(h)
}

/// 화소 부분만 따로 있는 DIB(EMF: 헤더·화소 위치가 따로 지정됨)를 정규화한다.
/// `rows` 는 화소가 일부 줄만 담긴 경우(SetDIBitsToDevice)의 줄 수.
/// 구조가 맞지 않으면 None, 화소 예산을 넘으면 차단 오류.
pub fn canonical(
    info: &[u8],
    bits: &[u8],
    usage: u32,
    rows: Option<u32>,
    policy: &Policy,
    budget: &mut PixelBudget,
) -> Result<Option<Dib>> {
    let Some(h) = header(info) else {
        return Ok(None);
    };
    if h.width <= 0 || h.height == 0 || h.height == i32::MIN {
        return Ok(None);
    }
    let (w, ah) = (h.width as u64, h.height.unsigned_abs() as u64);
    let px = w.saturating_mul(ah);
    if px > policy.max_image_pixels {
        return Ok(None);
    }
    budget.charge_pixels(px)?;

    match h.compression {
        BI_JPEG | BI_PNG => return Ok(decode_embedded(&h, bits, policy)),
        BI_RGB if [1, 4, 8, 16, 24, 32].contains(&h.bpp) => {}
        BI_BITFIELDS if [16, 32].contains(&h.bpp) && h.size != 12 => {}
        BI_RLE8 if h.bpp == 8 && h.height > 0 => {}
        BI_RLE4 if h.bpp == 4 && h.height > 0 => {}
        _ => return Ok(None),
    }

    // 색상표
    let entries = if h.bpp <= 8 {
        let max = 1u32 << h.bpp;
        if h.colors_used == 0 || h.colors_used > max {
            max
        } else {
            h.colors_used
        }
    } else {
        0
    } as usize;
    let masks = h.compression == BI_BITFIELDS;
    let table_at = if masks { h.size.max(52) } else { h.size };
    let entry = match usage {
        DIB_RGB_COLORS if h.size == 12 => 3,
        DIB_RGB_COLORS => 4,
        DIB_PAL_COLORS => 2,
        _ => 0, // DIB_PAL_INDICES: 색상표 없음
    };
    let Some(table) = rd::slice(info, table_at, entries * entry) else {
        return Ok(None);
    };

    let stride = (w * h.bpp as u64).div_ceil(32) * 4;
    let lines = match rows {
        Some(r) if (r as u64) < ah => r as u64,
        _ => ah,
    };
    let need = stride * lines;
    let pixels = match h.compression {
        BI_RLE8 | BI_RLE4 => {
            if rows.is_some_and(|r| (r as u64) < ah) {
                return Ok(None);
            }
            match rle(bits, h.width as usize, ah as usize, stride as usize, h.bpp) {
                Some(p) => p,
                None => return Ok(None),
            }
        }
        _ => match bits.get(..need as usize) {
            Some(b) => b.to_vec(),
            None => return Ok(None),
        },
    };

    let mut out = Vec::with_capacity(40 + 12 + table.len());
    out.extend(40u32.to_le_bytes());
    out.extend(h.width.to_le_bytes());
    out.extend(h.height.to_le_bytes());
    out.extend(1u16.to_le_bytes());
    out.extend(h.bpp.to_le_bytes());
    out.extend(if masks { BI_BITFIELDS } else { BI_RGB }.to_le_bytes());
    out.extend((pixels.len() as u32).to_le_bytes());
    out.extend(h.x_ppm.to_le_bytes());
    out.extend(h.y_ppm.to_le_bytes());
    out.extend((entries as u32).to_le_bytes());
    out.extend(0u32.to_le_bytes());
    if masks {
        let Some(m) = rd::slice(info, 40, 12) else {
            return Ok(None);
        };
        out.extend(m);
    }
    if entry == 3 {
        for c in table.as_chunks::<3>().0 {
            out.extend([c[0], c[1], c[2], 0]);
        }
    } else if entry == 4 {
        for c in table.as_chunks::<4>().0 {
            out.extend([c[0], c[1], c[2], 0]);
        }
    } else {
        out.extend(table);
    }
    Ok(Some(Dib {
        info: out,
        bits: pixels,
    }))
}

/// 헤더·색상표·화소가 이어 붙은 DIB(WMF, OfficeArt)를 정규화한다
pub fn canonical_packed(
    data: &[u8],
    usage: u32,
    rows: Option<u32>,
    policy: &Policy,
    budget: &mut PixelBudget,
) -> Result<Option<Dib>> {
    let Some(h) = header(data) else {
        return Ok(None);
    };
    let entries = if h.bpp <= 8 && !matches!(h.compression, BI_JPEG | BI_PNG) {
        let max = 1u32 << h.bpp.min(8);
        if h.colors_used == 0 || h.colors_used > max {
            max as usize
        } else {
            h.colors_used as usize
        }
    } else {
        0
    };
    let entry = match usage {
        DIB_RGB_COLORS if h.size == 12 => 3,
        DIB_RGB_COLORS => 4,
        DIB_PAL_COLORS => 2,
        _ => 0,
    };
    let masks = if h.compression == BI_BITFIELDS && h.size == 40 {
        12
    } else {
        0
    };
    let bits_at = h.size + masks + entries * entry;
    let Some(bits) = data.get(bits_at..) else {
        return Ok(None);
    };
    canonical(&data[..bits_at], bits, usage, rows, policy, budget)
}

/// DIB 헤더 뒤의 화소를 조립된 DIB 로 다시 이어 붙인다
pub fn packed(d: &Dib) -> Vec<u8> {
    let mut v = d.info.clone();
    v.extend(&d.bits);
    v
}

/// BI_JPEG/BI_PNG 비트맵: 픽셀만 디코딩해 24비트 무압축 DIB 로 쓴다
fn decode_embedded(h: &Header, bits: &[u8], policy: &Policy) -> Option<Dib> {
    let data = match h.size_image as usize {
        0 => bits,
        n => bits.get(..n)?,
    };
    let kind = ImageKind::sniff(data).filter(|k| matches!(k, ImageKind::Jpeg | ImageKind::Png))?;
    let img = imaging::decode(data, kind, policy).ok()?.to_rgb8();
    let (w, hh) = img.dimensions();
    let stride = (w as usize * 3).div_ceil(4) * 4;
    let mut pixels = vec![0u8; stride * hh as usize];
    for (y, row) in img.rows().enumerate() {
        let line = &mut pixels[(hh as usize - 1 - y) * stride..];
        for (x, p) in row.enumerate() {
            line[x * 3..x * 3 + 3].copy_from_slice(&[p[2], p[1], p[0]]);
        }
    }
    let mut info = Vec::with_capacity(40);
    info.extend(40u32.to_le_bytes());
    info.extend((w as i32).to_le_bytes());
    info.extend((hh as i32).to_le_bytes());
    info.extend(1u16.to_le_bytes());
    info.extend(24u16.to_le_bytes());
    info.extend(BI_RGB.to_le_bytes());
    info.extend((pixels.len() as u32).to_le_bytes());
    info.extend(h.x_ppm.to_le_bytes());
    info.extend(h.y_ppm.to_le_bytes());
    info.extend([0; 8]);
    Some(Dib { info, bits: pixels })
}

/// RLE8/RLE4 압축을 풀어 아래에서 위로 쌓인 무압축 화소로 만든다
fn rle(src: &[u8], width: usize, height: usize, stride: usize, bpp: u16) -> Option<Vec<u8>> {
    let mut out = vec![0u8; stride.checked_mul(height)?];
    let (mut x, mut y) = (0usize, 0usize);
    let put = |out: &mut [u8], x: usize, y: usize, v: u8| {
        if x >= width || y >= height {
            return;
        }
        let row = &mut out[y * stride..(y + 1) * stride];
        if bpp == 8 {
            row[x] = v;
        } else if x.is_multiple_of(2) {
            row[x / 2] = (row[x / 2] & 0x0F) | (v << 4);
        } else {
            row[x / 2] = (row[x / 2] & 0xF0) | (v & 0x0F);
        }
    };
    let mut p = 0;
    while p + 1 < src.len() {
        let (a, b) = (src[p], src[p + 1]);
        p += 2;
        if a > 0 {
            // 반복 구간
            for i in 0..a as usize {
                let v = if bpp == 8 {
                    b
                } else if i % 2 == 0 {
                    b >> 4
                } else {
                    b & 0x0F
                };
                put(&mut out, x, y, v);
                x += 1;
            }
            continue;
        }
        match b {
            0 => {
                x = 0;
                y += 1;
            }
            1 => break,
            2 => {
                let (dx, dy) = (*src.get(p)? as usize, *src.get(p + 1)? as usize);
                p += 2;
                x += dx;
                y += dy;
            }
            n => {
                // 그대로 쓰는 구간 (2바이트 경계로 채움)
                let n = n as usize;
                let bytes = if bpp == 8 { n } else { n.div_ceil(2) };
                let data = src.get(p..p + bytes)?;
                for i in 0..n {
                    let v = if bpp == 8 {
                        data[i]
                    } else if i % 2 == 0 {
                        data[i / 2] >> 4
                    } else {
                        data[i / 2] & 0x0F
                    };
                    put(&mut out, x, y, v);
                    x += 1;
                }
                p += bytes + bytes % 2;
            }
        }
        if y >= height {
            break;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rle8_decodes_runs_and_literals() {
        // 4×2: 1행 = 반복(1×7) + 그대로(3바이트: 1,2,3 + 채움), 줄 끝, 2행 = 반복(4×9), 끝
        let src = [1, 7, 0, 3, 1, 2, 3, 0, 0, 0, 4, 9, 0, 1];
        let out = rle(&src, 4, 2, 4, 8).unwrap();
        assert_eq!(out, [7, 1, 2, 3, 9, 9, 9, 9]);
    }

    #[test]
    fn rle_never_writes_outside() {
        // 너비를 넘는 반복·델타도 버퍼 밖으로 나가지 않는다
        let src = [255, 1, 0, 2, 255, 255, 200, 3, 0, 0, 0, 0];
        let out = rle(&src, 3, 2, 4, 8).unwrap();
        assert_eq!(out.len(), 8);
    }
}
