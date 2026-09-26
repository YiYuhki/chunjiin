//! Office 그리기(OfficeArt) 그림 저장소 재조합.
//!
//! PPT 의 `Pictures` 스트림은 그림 레코드(OfficeArtBlip)를 이어 붙인 "지연 스트림"이고,
//! 본문의 그림 목록(OfficeArtBStoreContainer 의 FBSE 레코드)이 고정 크기 필드(foDelay, size)로
//! 각 그림을 가리킨다. 그림 스트림은 새로 만들고, 본문은 이 고정 크기 필드만 제자리에서 고친다.
//!
//! - JPEG/PNG: 픽셀만 디코딩해 같은 형식으로 새로 인코딩
//! - DIB(비트맵): 24비트 비트맵으로 새로 인코딩
//! - 메타파일(EMF/WMF/PICT)·기타: 그대로 옮김 (형식 변환 불가)
//! - 어떤 FBSE 도 가리키지 않는 그림 레코드와 레코드 사이·끝의 데이터는 옮기지 않음
//! - 디코딩할 수 없는 래스터 그림은 같은 형식의 1×1 빈 그림으로 대체

use std::collections::{BTreeMap, HashMap};
use std::io::Cursor;

use crate::imaging::{self, ImageKind};
use crate::policy::Policy;
use crate::report::{Findings, Severity};

const RT_BSTORE_CONTAINER: u16 = 0xF001;
const RT_FBSE: u16 = 0xF007;
const RT_BLIP_FIRST: u16 = 0xF018;
const RT_BLIP_LAST: u16 = 0xF117;
const RT_JPEG: u16 = 0xF01D;
const RT_PNG: u16 = 0xF01E;
const RT_DIB: u16 = 0xF01F;

struct Header {
    ver: u16,
    instance: u16,
    rtype: u16,
    body: usize,
    len: usize,
}

fn header(d: &[u8], at: usize) -> Option<Header> {
    let vi = u16::from_le_bytes(d.get(at..at + 2)?.try_into().ok()?);
    let rtype = u16::from_le_bytes(d.get(at + 2..at + 4)?.try_into().ok()?);
    let len = u32::from_le_bytes(d.get(at + 4..at + 8)?.try_into().ok()?) as usize;
    d.get(at + 8..(at + 8).checked_add(len)?)?;
    Some(Header {
        ver: vi & 0xF,
        instance: vi >> 4,
        rtype,
        body: at + 8,
        len,
    })
}

/// FBSE 가 가리키는 그림 (본문 안 FBSE 본문 위치, foDelay)
struct Fbse {
    body: usize,
    fo_delay: u32,
}

/// 본문에서 그림 저장소 컨테이너 안의 FBSE 레코드를 찾는다 (컨테이너 구조를 따라감)
fn find_fbse(doc: &[u8]) -> Vec<Fbse> {
    let mut out = Vec::new();
    let pat = RT_BSTORE_CONTAINER.to_le_bytes();
    let mut p = 0;
    while p + 8 <= doc.len() {
        if doc[p + 2..p + 4] == pat {
            if let Some(c) = header(doc, p).filter(|h| h.ver == 0xF) {
                let mut q = c.body;
                while let Some(h) = header(doc, q).filter(|h| h.body + h.len <= c.body + c.len) {
                    if h.rtype == RT_FBSE && h.ver == 2 && h.len >= 36 {
                        let fo =
                            u32::from_le_bytes(doc[h.body + 28..h.body + 32].try_into().unwrap());
                        out.push(Fbse {
                            body: h.body,
                            fo_delay: fo,
                        });
                    }
                    q = h.body + h.len;
                }
            }
        }
        p += 1;
    }
    out
}

/// 그림 레코드 본문 앞의 식별자(rgbUid 1~2개) + 태그 바이트 길이
fn raster_prefix(rtype: u16, instance: u16) -> Option<usize> {
    let single = match rtype {
        RT_JPEG => [0x46A, 0x6E2],
        RT_PNG => [0x6E0, 0x6E0],
        RT_DIB => [0x7A8, 0x7A8],
        _ => return None,
    };
    if single.contains(&instance) {
        Some(17)
    } else if single.iter().any(|s| s + 1 == instance) {
        Some(33)
    } else {
        None
    }
}

pub struct Rebuilt {
    pub pictures: Vec<u8>,
    pub document: Vec<u8>,
}

/// 그림 스트림을 재조합하고 본문의 FBSE 를 고친다. 그림 목록 구조를 해석할 수 없으면 None
/// (호출 측은 원본 그림 스트림을 유지한다).
pub fn rebuild(
    pictures: &[u8],
    document: &[u8],
    policy: &Policy,
    findings: &mut Findings,
    location: &str,
) -> Option<Rebuilt> {
    let fbse = find_fbse(document);
    let referenced: BTreeMap<u32, ()> = fbse
        .iter()
        .filter(|f| f.fo_delay != u32::MAX)
        .map(|f| (f.fo_delay, ()))
        .collect();

    let mut out = Vec::with_capacity(pictures.len());
    let mut moved: HashMap<u32, (u32, u32)> = HashMap::new();
    let (mut reencoded, mut kept, mut replaced) = (0u64, 0u64, 0u64);
    for &old in referenced.keys() {
        let h = header(pictures, old as usize)
            .filter(|h| (RT_BLIP_FIRST..=RT_BLIP_LAST).contains(&h.rtype))?;
        let body = &pictures[h.body..h.body + h.len];
        let new_body = match raster_prefix(h.rtype, h.instance) {
            Some(prefix) if body.len() > prefix => {
                let (head, image) = body.split_at(prefix);
                let rebuilt = match h.rtype {
                    RT_DIB => reencode_dib(image, policy),
                    RT_JPEG => reencode(image, ImageKind::Jpeg, policy),
                    _ => reencode(image, ImageKind::Png, policy),
                };
                let image = match rebuilt {
                    Some(d) => {
                        reencoded += 1;
                        d
                    }
                    None => {
                        replaced += 1;
                        placeholder(h.rtype)
                    }
                };
                let mut b = head.to_vec();
                b.extend(image);
                b
            }
            _ => {
                kept += 1;
                body.to_vec()
            }
        };
        let at = u32::try_from(out.len()).ok()?;
        out.extend(((h.instance << 4) | h.ver).to_le_bytes());
        out.extend(h.rtype.to_le_bytes());
        out.extend((new_body.len() as u32).to_le_bytes());
        out.extend(&new_body);
        moved.insert(old, (at, new_body.len() as u32 + 8));
    }

    let mut document = document.to_vec();
    for f in &fbse {
        if f.fo_delay == u32::MAX {
            continue;
        }
        let (at, size) = moved[&f.fo_delay];
        document[f.body + 20..f.body + 24].copy_from_slice(&size.to_le_bytes());
        document[f.body + 28..f.body + 32].copy_from_slice(&at.to_le_bytes());
    }

    findings.count("images_reencoded", reencoded);
    if kept > 0 {
        findings.count("metafiles_passthrough", kept);
    }
    if replaced > 0 {
        findings.add(
            "image",
            Severity::Low,
            format!("해석할 수 없는 그림 {replaced}개를 빈 그림으로 대체"),
            location,
        );
    }
    let dropped = pictures.len().saturating_sub(
        referenced
            .keys()
            .map(|&o| header(pictures, o as usize).map_or(0, |h| h.len + 8))
            .sum(),
    );
    if dropped > 0 {
        findings.add(
            "hidden-data",
            Severity::Low,
            format!("그림 목록이 가리키지 않는 데이터 {dropped}바이트 제거"),
            location,
        );
    }
    Some(Rebuilt {
        pictures: out,
        document,
    })
}

fn reencode(data: &[u8], kind: ImageKind, policy: &Policy) -> Option<Vec<u8>> {
    if ImageKind::sniff(data) != Some(kind) {
        return None;
    }
    imaging::reencode_same(data, kind, policy).ok()
}

/// DIB(파일 헤더 없는 BMP)를 24비트 DIB 로 다시 만든다
fn reencode_dib(dib: &[u8], policy: &Policy) -> Option<Vec<u8>> {
    let header_size = u32::from_le_bytes(dib.get(0..4)?.try_into().ok()?) as usize;
    let bpp = u16::from_le_bytes(dib.get(14..16)?.try_into().ok()?) as usize;
    let colors_used = u32::from_le_bytes(dib.get(32..36)?.try_into().ok()?) as usize;
    let palette = if bpp <= 8 {
        if colors_used == 0 {
            1 << bpp
        } else {
            colors_used
        }
    } else {
        0
    };
    let pixel_offset = 14 + header_size + palette * 4;
    let mut bmp = b"BM".to_vec();
    bmp.extend(((dib.len() + 14) as u32).to_le_bytes());
    bmp.extend([0; 4]);
    bmp.extend((pixel_offset as u32).to_le_bytes());
    bmp.extend(dib);
    if policy.media_passthrough {
        imaging::reencode_same(&bmp, ImageKind::Bmp, policy).ok()?;
        return Some(dib.to_vec());
    }
    let img = imaging::decode(&bmp, ImageKind::Bmp, policy).ok()?;
    let mut out = Cursor::new(Vec::new());
    image::DynamicImage::ImageRgb8(img.to_rgb8())
        .write_to(&mut out, image::ImageFormat::Bmp)
        .ok()?;
    out.into_inner().get(14..).map(<[u8]>::to_vec)
}

/// 같은 형식의 1×1 흰색 그림
fn placeholder(rtype: u16) -> Vec<u8> {
    let img =
        image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(1, 1, image::Rgb([255; 3])));
    let mut out = Cursor::new(Vec::new());
    let format = match rtype {
        RT_JPEG => image::ImageFormat::Jpeg,
        RT_DIB => image::ImageFormat::Bmp,
        _ => image::ImageFormat::Png,
    };
    let _ = img.write_to(&mut out, format);
    let data = out.into_inner();
    if rtype == RT_DIB {
        data.get(14..).map(<[u8]>::to_vec).unwrap_or_default()
    } else {
        data
    }
}

/// 제자리 재인코딩 결과 통계
#[derive(Default)]
pub struct InPlace {
    pub reencoded: u64,
    /// 새 인코딩이 원래 자리에 들어가지 않아 원본을 유지한 그림
    pub kept: u64,
    /// 디코딩할 수 없어 빈 그림으로 대체한 그림
    pub replaced: u64,
}

/// 오프셋이 얽힌 스트림(doc 의 Data·WordDocument, xls 의 Workbook) 안의 래스터 그림 레코드를
/// 찾아 **길이를 바꾸지 않고** 재인코딩한다. 새 인코딩을 원래 자리에 쓰고 남는 부분은 0 으로 채운다
/// (PNG/JPEG 디코더는 끝 표시 뒤를 읽지 않는다). 레코드 길이와 모든 오프셋은 그대로다.
/// `allowed` 는 그림 레코드 전체가 들어 있어야 하는 구간(예: BIFF 레코드 본문)을 판정한다.
pub fn reencode_in_place(
    stream: &mut [u8],
    policy: &Policy,
    allowed: &dyn Fn(usize, usize) -> bool,
) -> InPlace {
    let mut stats = InPlace::default();
    if policy.media_passthrough {
        return stats;
    }
    let mut p = 0;
    while p + 8 <= stream.len() {
        let found = header(stream, p).and_then(|h| {
            let kind = match h.rtype {
                RT_JPEG => ImageKind::Jpeg,
                RT_PNG => ImageKind::Png,
                _ => return None,
            };
            let prefix = raster_prefix(h.rtype, h.instance)?;
            let image_at = h.body + prefix;
            let ok = h.ver == 0
                && h.len > prefix + 8
                && ImageKind::sniff(&stream[image_at..h.body + h.len]) == Some(kind)
                && allowed(p, h.body + h.len);
            ok.then_some((image_at, h.body + h.len, kind, h.rtype))
        });
        let Some((start, end, kind, rtype)) = found else {
            p += 1;
            continue;
        };
        let slot = &mut stream[start..end];
        let (new, broken) = match reencode(slot, kind, policy) {
            Some(first) => (fit(first, slot, kind, policy), false),
            None => (Some(placeholder(rtype)), true),
        };
        match new {
            Some(bytes) if bytes.len() <= slot.len() => {
                slot[..bytes.len()].copy_from_slice(&bytes);
                slot[bytes.len()..].fill(0);
                if broken {
                    stats.replaced += 1;
                } else {
                    stats.reencoded += 1;
                }
            }
            _ => stats.kept += 1,
        }
        p = end;
    }
    stats
}

/// 재인코딩 결과가 자리보다 크면 더 강하게 압축해 본다
fn fit(first: Vec<u8>, slot: &[u8], kind: ImageKind, policy: &Policy) -> Option<Vec<u8>> {
    if first.len() <= slot.len() {
        return Some(first);
    }
    let img = imaging::decode(slot, kind, policy).ok()?;
    let mut out = Cursor::new(Vec::new());
    match kind {
        ImageKind::Jpeg => {
            let rgb8 = img.to_rgb8();
            let gray = rgb8.pixels().all(|p| p[0] == p[1] && p[1] == p[2]);
            let rgb = if gray {
                image::DynamicImage::ImageLuma8(img.to_luma8())
            } else {
                image::DynamicImage::ImageRgb8(rgb8)
            };
            for q in [92u8, 85, 75, 60, 45] {
                out.get_mut().clear();
                out.set_position(0);
                let enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, q);
                rgb.write_with_encoder(enc).ok()?;
                if out.get_ref().len() <= slot.len() {
                    return Some(out.into_inner());
                }
            }
            None
        }
        _ => {
            // 색이 256개 이하면 색상표(indexed) PNG 로, 아니면 최고 압축으로 다시 시도
            if let Some(data) = indexed_png(&img).filter(|d| d.len() <= slot.len()) {
                return Some(data);
            }
            reduced_png(&img).filter(|d| d.len() <= slot.len())
        }
    }
}

/// PNG 를 직접 쓴다: 행마다 필터를 고르고(색상표·저비트 이미지는 필터 없음) zlib 최고 압축.
/// `color`: 0 회색조, 2 RGB, 3 색상표, 4 회색조+알파, 6 RGBA
#[allow(clippy::too_many_arguments)]
fn write_png(
    w: u32,
    h: u32,
    color: u8,
    depth: u8,
    bpp: usize,
    rows: &[u8],
    palette: Option<(&[u8], Option<&[u8]>)>,
    fixed: Option<u8>,
) -> Option<Vec<u8>> {
    let stride = rows.len() / h.max(1) as usize;
    let mut filtered = Vec::with_capacity(rows.len() + h as usize);
    let mut prev = vec![0u8; stride];
    let adaptive = color != 3 && depth == 8;
    let mut cand = vec![0u8; stride];
    for row in rows.chunks(stride) {
        if !adaptive {
            filtered.push(0);
            filtered.extend(row);
        } else {
            // 절대값 합이 가장 작은 필터 (libpng 과 같은 경험칙)
            let mut best: Option<(u64, u8, Vec<u8>)> = None;
            let filters = match fixed {
                Some(f) => f..f + 1,
                None => 0..5u8,
            };
            for ft in filters {
                for i in 0..stride {
                    let a = if i >= bpp { row[i - bpp] as i16 } else { 0 };
                    let b = prev[i] as i16;
                    let c = if i >= bpp { prev[i - bpp] as i16 } else { 0 };
                    let pred = match ft {
                        0 => 0,
                        1 => a,
                        2 => b,
                        3 => (a + b) / 2,
                        _ => {
                            let p = a + b - c;
                            let (pa, pb, pc) = ((p - a).abs(), (p - b).abs(), (p - c).abs());
                            if pa <= pb && pa <= pc {
                                a
                            } else if pb <= pc {
                                b
                            } else {
                                c
                            }
                        }
                    };
                    cand[i] = (row[i] as i16 - pred) as u8;
                }
                let score: u64 = cand.iter().map(|&v| (v as i8).unsigned_abs() as u64).sum();
                if best.as_ref().is_none_or(|(s, _, _)| score < *s) {
                    best = Some((score, ft, cand.clone()));
                }
            }
            let (_, ft, data) = best?;
            filtered.push(ft);
            filtered.extend(data);
        }
        prev.copy_from_slice(row);
    }
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    std::io::Write::write_all(&mut z, &filtered).ok()?;
    let idat = z.finish().ok()?;

    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut chunk = |tag: &[u8; 4], data: &[u8]| {
        out.extend((data.len() as u32).to_be_bytes());
        let mut crc = flate2::Crc::new();
        crc.update(tag);
        crc.update(data);
        out.extend(tag);
        out.extend(data);
        out.extend(crc.sum().to_be_bytes());
    };
    let mut ihdr = w.to_be_bytes().to_vec();
    ihdr.extend(h.to_be_bytes());
    ihdr.extend([depth, color, 0, 0, 0]);
    chunk(b"IHDR", &ihdr);
    if let Some((plte, trns)) = palette {
        chunk(b"PLTE", plte);
        if let Some(t) = trns {
            chunk(b"tRNS", t);
        }
    }
    chunk(b"IDAT", &idat);
    chunk(b"IEND", &[]);
    Some(out)
}

/// 색이 256개 이하인 이미지를 색상표 PNG(1/2/4/8비트)로 인코딩한다. 색이 더 많으면 None
fn indexed_png(img: &image::DynamicImage) -> Option<Vec<u8>> {
    let rgba = img.to_rgba8();
    let (w, h) = rgba.dimensions();
    let mut palette: Vec<[u8; 4]> = Vec::new();
    let mut lookup: HashMap<[u8; 4], u8> = HashMap::new();
    let mut indices = Vec::with_capacity((w * h) as usize);
    for px in rgba.pixels() {
        let idx = match lookup.get(&px.0) {
            Some(&i) => i,
            None => {
                if palette.len() == 256 {
                    return None;
                }
                let i = palette.len() as u8;
                palette.push(px.0);
                lookup.insert(px.0, i);
                i
            }
        };
        indices.push(idx);
    }
    let bits = match palette.len() {
        0..=2 => 1,
        3..=4 => 2,
        5..=16 => 4,
        _ => 8,
    };
    let per_byte = 8 / bits;
    let row_bytes = (w as usize).div_ceil(per_byte);
    let mut packed = vec![0u8; row_bytes * h as usize];
    for y in 0..h as usize {
        for x in 0..w as usize {
            let v = indices[y * w as usize + x];
            let shift = 8 - bits * (x % per_byte + 1);
            packed[y * row_bytes + x / per_byte] |= v << shift;
        }
    }
    let plte: Vec<u8> = palette.iter().flat_map(|c| [c[0], c[1], c[2]]).collect();
    // 투명도는 마지막 불투명하지 않은 색까지만 기록
    let trns: Option<Vec<u8>> = palette
        .iter()
        .rposition(|c| c[3] != 255)
        .map(|last| palette[..=last].iter().map(|c| c[3]).collect());
    write_png(
        w,
        h,
        3,
        bits as u8,
        1,
        &packed,
        Some((&plte, trns.as_deref())),
        None,
    )
}

/// 색 형식을 줄여(불투명하면 알파 제거, 무채색이면 회색조) PNG 를 만든다
fn reduced_png(img: &image::DynamicImage) -> Option<Vec<u8>> {
    let rgba = img.to_rgba8();
    let (w, h) = rgba.dimensions();
    let opaque = rgba.pixels().all(|p| p[3] == 255);
    let gray = rgba.pixels().all(|p| p[0] == p[1] && p[1] == p[2]);
    let (color, bpp, data): (u8, usize, Vec<u8>) = match (gray, opaque) {
        (true, true) => (0, 1, rgba.pixels().map(|p| p[0]).collect()),
        (true, false) => (4, 2, rgba.pixels().flat_map(|p| [p[0], p[3]]).collect()),
        (false, true) => (
            2,
            3,
            rgba.pixels().flat_map(|p| [p[0], p[1], p[2]]).collect(),
        ),
        (false, false) => (6, 4, rgba.into_raw()),
    };
    // 행별 적응 필터와 전체 고정 필터(5종) 중 가장 작은 결과
    [None, Some(0), Some(1), Some(2), Some(3), Some(4)]
        .into_iter()
        .filter_map(|f| write_png(w, h, color, 8, bpp, &data, None, f))
        .min_by_key(Vec::len)
}

/// 제자리 재인코딩 결과를 보고서에 기록한다
pub fn report(stats: &InPlace, findings: &mut Findings, location: &str) {
    if stats.reencoded > 0 {
        findings.count("images_reencoded", stats.reencoded);
    }
    if stats.kept > 0 {
        findings.count("images_kept_original", stats.kept);
    }
    if stats.replaced > 0 {
        findings.add(
            "image",
            Severity::Low,
            format!(
                "해석할 수 없는 그림 {}개를 빈 그림으로 대체",
                stats.replaced
            ),
            location,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(img: image::DynamicImage) {
        let want = img.to_rgba8();
        let mut outs = vec![reduced_png(&img).unwrap()];
        if let Some(i) = indexed_png(&img) {
            outs.push(i);
        }
        for png in outs {
            let got = image::load_from_memory(&png).unwrap().to_rgba8();
            assert_eq!(got.dimensions(), want.dimensions());
            assert!(got.pixels().zip(want.pixels()).all(|(a, b)| a == b));
        }
    }

    #[test]
    fn png_writer_preserves_pixels() {
        let (w, h) = (37, 23);
        for colors in [2u32, 4, 16, 200, 5000] {
            let img = image::RgbaImage::from_fn(w, h, |x, y| {
                let v = (x * 7 + y * 13) % colors;
                image::Rgba([(v * 37) as u8, (v * 11) as u8, (v >> 8) as u8 * 50, 255])
            });
            roundtrip(image::DynamicImage::ImageRgba8(img));
        }
        // 투명도가 있는 색상표, 회색조, 회색조+알파, RGBA
        let alpha =
            image::RgbaImage::from_fn(w, h, |x, _| image::Rgba([x as u8, 0, 0, (x * 7) as u8]));
        roundtrip(image::DynamicImage::ImageRgba8(alpha));
        let gray = image::RgbaImage::from_fn(w, h, |x, y| {
            let v = (x * y) as u8;
            image::Rgba([v, v, v, 255])
        });
        roundtrip(image::DynamicImage::ImageRgba8(gray));
        let gray_alpha = image::RgbaImage::from_fn(w, h, |x, y| {
            let v = (x * y) as u8;
            image::Rgba([v, v, v, (x * 3) as u8])
        });
        roundtrip(image::DynamicImage::ImageRgba8(gray_alpha));
        let noisy = image::RgbaImage::from_fn(w, h, |x, y| {
            image::Rgba([
                (x * 31 + y) as u8,
                (y * 17) as u8,
                (x ^ y) as u8,
                (x + y) as u8,
            ])
        });
        roundtrip(image::DynamicImage::ImageRgba8(noisy));
    }
}
