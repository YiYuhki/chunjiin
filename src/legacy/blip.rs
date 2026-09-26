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
