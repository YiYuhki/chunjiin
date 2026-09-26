//! 내장 TrueType 글꼴 프로그램 재조합.
//!
//! 원본 sfnt 를 그대로 옮기지 않고 렌더링에 필요한 테이블만 골라 새 글꼴 파일을 만든다.
//! - 힌팅 바이트코드(fpgm/prep/cvt 테이블과 글리프마다 붙은 명령어)는 TrueType 가상 머신에서
//!   실행되는 코드로, 과거 글꼴 엔진 취약점 공격에 쓰였기 때문에 모두 제거한다.
//! - glyf/loca 를 다시 쓰고(긴 형식), 체크섬을 새로 계산한다.
//! - 결과물은 독립 파서(ttf-parser)로 모든 글리프 외곽선을 해석해 검증한다.

use std::collections::BTreeMap;

/// 새 글꼴에 옮기는 테이블. 그 밖의 테이블(힌팅, 레이아웃, 서명, 비표준 테이블)은 버린다.
const KEEP_TABLES: &[&[u8; 4]] = &[
    b"cmap", b"glyf", b"head", b"hhea", b"hmtx", b"loca", b"maxp", b"name", b"OS/2", b"post",
    b"vhea", b"vmtx",
];
const REQUIRED_TABLES: &[&[u8; 4]] = &[b"glyf", b"head", b"hhea", b"hmtx", b"loca", b"maxp"];

pub struct Rebuilt {
    pub data: Vec<u8>,
    /// 제거한 테이블 태그
    pub dropped_tables: Vec<String>,
    /// 명령어를 제거한 글리프 수
    pub stripped_glyphs: usize,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// sfnt 가 TrueType 외곽선 글꼴인지 (CFF 기반 OpenType 'OTTO', 모음 'ttcf' 는 아님)
pub fn is_truetype(data: &[u8]) -> bool {
    matches!(data.get(..4), Some([0, 1, 0, 0]) | Some(b"true"))
}

pub fn rebuild_truetype(data: &[u8]) -> Result<Rebuilt, String> {
    if !is_truetype(data) {
        return Err("TrueType 형식이 아님".into());
    }
    let num_tables = u16_at(data, 4).ok_or("헤더 손상")? as usize;
    let mut tables: BTreeMap<[u8; 4], &[u8]> = BTreeMap::new();
    let mut dropped = Vec::new();
    for i in 0..num_tables {
        let rec = 12 + i * 16;
        let tag: [u8; 4] = data
            .get(rec..rec + 4)
            .ok_or("테이블 목록 손상")?
            .try_into()
            .unwrap();
        let off = u32_at(data, rec + 8).ok_or("테이블 목록 손상")? as usize;
        let len = u32_at(data, rec + 12).ok_or("테이블 목록 손상")? as usize;
        if !KEEP_TABLES.contains(&&tag) {
            dropped.push(String::from_utf8_lossy(&tag).trim().to_string());
            continue;
        }
        let body = off
            .checked_add(len)
            .and_then(|end| data.get(off..end))
            .ok_or_else(|| format!("{} 테이블 범위 오류", String::from_utf8_lossy(&tag)))?;
        if tables.insert(tag, body).is_some() {
            return Err("중복 테이블".into());
        }
    }
    for t in REQUIRED_TABLES {
        if !tables.contains_key(*t) {
            return Err(format!("필수 테이블 없음: {}", String::from_utf8_lossy(*t)));
        }
    }

    let head = tables[b"head"];
    let maxp = tables[b"maxp"];
    if head.len() < 54 || maxp.len() < 6 {
        return Err("head/maxp 손상".into());
    }
    let num_glyphs = u16_at(maxp, 4).unwrap() as usize;
    let long_loca = u16_at(head, 50).unwrap() == 1;
    let loca = tables[b"loca"];
    let glyf = tables[b"glyf"];
    let offset = |i: usize| -> Option<usize> {
        if long_loca {
            u32_at(loca, i * 4).map(|v| v as usize)
        } else {
            u16_at(loca, i * 2).map(|v| v as usize * 2)
        }
    };

    let mut new_glyf = Vec::with_capacity(glyf.len());
    let mut new_loca = Vec::with_capacity((num_glyphs + 1) * 4);
    let mut stripped = 0;
    for gid in 0..num_glyphs {
        let (start, end) = match (offset(gid), offset(gid + 1)) {
            (Some(s), Some(e)) if s <= e && e <= glyf.len() => (s, e),
            // 일부 글꼴은 마지막 오프셋이 테이블 끝을 약간 넘는다: 빈 글리프로 처리
            (Some(s), Some(_)) if s >= glyf.len() => (0, 0),
            _ => return Err(format!("loca 손상 (글리프 {gid})")),
        };
        new_loca.extend((new_glyf.len() as u32).to_be_bytes());
        let (g, had_code) = strip_glyph(&glyf[start..end], num_glyphs)
            .ok_or_else(|| format!("글리프 {gid} 구조 오류"))?;
        stripped += had_code as usize;
        new_glyf.extend(g);
        while new_glyf.len() % 4 != 0 {
            new_glyf.push(0);
        }
    }
    new_loca.extend((new_glyf.len() as u32).to_be_bytes());

    let mut new_head = head[..54].to_vec();
    new_head[8..12].fill(0); // checkSumAdjustment: 전체 계산 후 기록
    new_head[50..52].copy_from_slice(&1u16.to_be_bytes()); // 긴 loca
    let mut new_maxp = maxp.to_vec();
    if u32_at(&new_maxp, 0) == Some(0x0001_0000) && new_maxp.len() >= 32 {
        // 힌팅이 없으므로 명령어 관련 최대값을 0 으로
        for at in [18usize, 20, 22, 26] {
            new_maxp[at..at + 2].fill(0);
        }
    }

    let mut out_tables: BTreeMap<[u8; 4], Vec<u8>> = BTreeMap::new();
    for (tag, body) in &tables {
        let body = match tag {
            b"glyf" => std::mem::take(&mut new_glyf),
            b"loca" => std::mem::take(&mut new_loca),
            b"head" => new_head.clone(),
            b"maxp" => new_maxp.clone(),
            _ => body.to_vec(),
        };
        out_tables.insert(*tag, body);
    }
    let data = write_sfnt(&out_tables);
    validate(&data, num_glyphs)?;
    Ok(Rebuilt {
        data,
        dropped_tables: dropped,
        stripped_glyphs: stripped,
    })
}

/// 글리프 하나에서 명령어를 제거한다. (새 글리프, 명령어가 있었는지)
fn strip_glyph(g: &[u8], num_glyphs: usize) -> Option<(Vec<u8>, bool)> {
    if g.is_empty() {
        return Some((Vec::new(), false));
    }
    let contours = i16::from_be_bytes(g.get(0..2)?.try_into().ok()?);
    if contours >= 0 {
        let n = contours as usize;
        let ilen_at = 10 + n * 2;
        let ilen = u16_at(g, ilen_at)? as usize;
        let rest = g.get(ilen_at + 2 + ilen..)?;
        let mut out = g[..ilen_at].to_vec();
        out.extend([0, 0]);
        out.extend(rest);
        return Some((out, ilen > 0));
    }
    // 복합 글리프: 구성 요소를 순회하며 WE_HAVE_INSTRUCTIONS 를 끄고 뒤의 명령어를 버린다
    const ARG_WORDS: u16 = 0x0001;
    const SCALE: u16 = 0x0008;
    const MORE: u16 = 0x0020;
    const XY_SCALE: u16 = 0x0040;
    const TWO_BY_TWO: u16 = 0x0080;
    const INSTRUCTIONS: u16 = 0x0100;
    let mut out = g.get(..10)?.to_vec();
    let mut p = 10;
    let mut had = false;
    for _ in 0..num_glyphs.max(1) {
        let flags = u16_at(g, p)?;
        let glyph = u16_at(g, p + 2)? as usize;
        if glyph >= num_glyphs {
            return None;
        }
        let mut len = 4 + if flags & ARG_WORDS != 0 { 4 } else { 2 };
        len += if flags & SCALE != 0 {
            2
        } else if flags & XY_SCALE != 0 {
            4
        } else if flags & TWO_BY_TWO != 0 {
            8
        } else {
            0
        };
        let comp = g.get(p..p + len)?;
        had |= flags & INSTRUCTIONS != 0;
        out.extend((flags & !INSTRUCTIONS).to_be_bytes());
        out.extend(&comp[2..]);
        p += len;
        if flags & MORE == 0 {
            return Some((out, had));
        }
    }
    None
}

fn checksum(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    for chunk in data.chunks(4) {
        let mut w = [0u8; 4];
        w[..chunk.len()].copy_from_slice(chunk);
        sum = sum.wrapping_add(u32::from_be_bytes(w));
    }
    sum
}

fn write_sfnt(tables: &BTreeMap<[u8; 4], Vec<u8>>) -> Vec<u8> {
    let n = tables.len() as u16;
    let entry_selector = 15 - n.leading_zeros() as u16;
    let search_range = (1u16 << entry_selector) * 16;
    let mut out = Vec::new();
    out.extend(0x0001_0000u32.to_be_bytes());
    out.extend(n.to_be_bytes());
    out.extend(search_range.to_be_bytes());
    out.extend(entry_selector.to_be_bytes());
    out.extend((n * 16 - search_range).to_be_bytes());
    let mut offset = 12 + tables.len() * 16;
    let mut head_at = None;
    for (tag, body) in tables {
        out.extend(tag);
        out.extend(checksum(body).to_be_bytes());
        out.extend((offset as u32).to_be_bytes());
        out.extend((body.len() as u32).to_be_bytes());
        offset += body.len().div_ceil(4) * 4;
    }
    for (tag, body) in tables {
        if tag == b"head" {
            head_at = Some(out.len());
        }
        out.extend(body);
        while out.len() % 4 != 0 {
            out.push(0);
        }
    }
    if let Some(at) = head_at {
        let adj = 0xB1B0_AFBAu32.wrapping_sub(checksum(&out));
        out[at + 8..at + 12].copy_from_slice(&adj.to_be_bytes());
    }
    out
}

struct Sink;
impl ttf_parser::OutlineBuilder for Sink {
    fn move_to(&mut self, _: f32, _: f32) {}
    fn line_to(&mut self, _: f32, _: f32) {}
    fn quad_to(&mut self, _: f32, _: f32, _: f32, _: f32) {}
    fn curve_to(&mut self, _: f32, _: f32, _: f32, _: f32, _: f32, _: f32) {}
    fn close(&mut self) {}
}

/// 독립 파서로 새 글꼴을 열고 모든 글리프 외곽선을 해석해 본다
fn validate(data: &[u8], num_glyphs: usize) -> Result<(), String> {
    let face =
        ttf_parser::Face::parse(data, 0).map_err(|e| format!("재조합 글꼴 검증 실패: {e}"))?;
    if face.number_of_glyphs() as usize != num_glyphs {
        return Err("재조합 글꼴 글리프 수 불일치".into());
    }
    for gid in 0..num_glyphs {
        // 빈 글리프(공백 등)는 None 이 정상이다
        let _ = face.outline_glyph(ttf_parser::GlyphId(gid as u16), &mut Sink);
    }
    Ok(())
}

/// CFF 글꼴 프로그램(FontFile3 의 Type1C/CIDFontType0C, 또는 CFF 기반 OpenType)을 검증한다.
/// 글리프 프로그램(Type 2 charstring)은 글꼴 엔진이 해석·실행하는 코드이므로, 독립 해석기로
/// 모든 글리프를 끝까지 해석해 보고 하나라도 비정상(스택·중첩 한도 초과, 잘못된 연산자,
/// 서브루틴 범위 오류, 범위 밖 읽기 등)이면 거부한다. 반환값: 검증한 글리프 수
pub fn validate_cff(data: &[u8]) -> Result<usize, String> {
    let owned;
    let cff_data: &[u8] = if data.starts_with(b"OTTO") {
        let face =
            ttf_parser::RawFace::parse(data, 0).map_err(|e| format!("OpenType 해석 실패: {e}"))?;
        match face.table(ttf_parser::Tag::from_bytes(b"CFF ")) {
            Some(t) => {
                owned = t.to_vec();
                &owned
            }
            None => return Err("CFF 테이블이 없는 OpenType (CFF2 등 미지원)".into()),
        }
    } else {
        data
    };
    let table = ttf_parser::cff::Table::parse(cff_data).ok_or("CFF 구조 해석 실패")?;
    let n = table.number_of_glyphs();
    if n == 0 {
        return Err("글리프가 없음".into());
    }
    let mut bad = 0usize;
    let mut first = None;
    for gid in 0..n {
        match table.outline(ttf_parser::GlyphId(gid), &mut Sink) {
            Ok(_) | Err(ttf_parser::CFFError::ZeroBBox) => {}
            Err(e) => {
                bad += 1;
                first.get_or_insert((gid, e));
            }
        }
    }
    match first {
        None => Ok(n as usize),
        Some((gid, e)) => Err(format!(
            "비정상 글리프 프로그램 {bad}개 (글리프 {gid}: {e:?})"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 사각형 글리프 하나(+ 명령어)와 힌팅 테이블을 가진 최소 TrueType 글꼴
    pub(crate) fn sample_font() -> Vec<u8> {
        let mut glyph = Vec::new();
        glyph.extend(1i16.to_be_bytes()); // 윤곽선 1개
        for v in [0i16, 0, 100, 100] {
            glyph.extend(v.to_be_bytes());
        }
        glyph.extend(3u16.to_be_bytes()); // endPts
        glyph.extend(4u16.to_be_bytes()); // 명령어 4바이트
        glyph.extend([0xB0, 0x01, 0x2B, 0x2B]); // PUSHB, 임의 명령
        glyph.extend([0x01, 0x01, 0x01, 0x01]); // flags (on-curve, 좌표는 워드)
        for v in [0i16, 100, 0, -100] {
            glyph.extend(v.to_be_bytes());
        }
        for v in [0i16, 0, 100, 0] {
            glyph.extend(v.to_be_bytes());
        }
        let mut composite = Vec::new();
        composite.extend((-1i16).to_be_bytes());
        for v in [0i16, 0, 100, 100] {
            composite.extend(v.to_be_bytes());
        }
        composite.extend((0x0001u16 | 0x0002 | 0x0100).to_be_bytes());
        composite.extend(1u16.to_be_bytes());
        composite.extend([0, 10, 0, 10]);
        composite.extend(2u16.to_be_bytes());
        composite.extend([0x2B, 0x2B]);

        let mut glyf = Vec::new();
        let mut loca = vec![0u16];
        glyf.extend(&glyph);
        glyf.resize(glyf.len().div_ceil(2) * 2, 0);
        loca.push((glyf.len() / 2) as u16);
        glyf.extend(&glyph);
        glyf.resize(glyf.len().div_ceil(2) * 2, 0);
        loca.push((glyf.len() / 2) as u16);
        glyf.extend(&composite);
        glyf.resize(glyf.len().div_ceil(2) * 2, 0);
        loca.push((glyf.len() / 2) as u16);

        let mut head = vec![0u8; 54];
        head[0..4].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        head[12..16].copy_from_slice(&0x5F0F_3CF5u32.to_be_bytes());
        head[18..20].copy_from_slice(&1000u16.to_be_bytes());
        let mut hhea = vec![0u8; 36];
        hhea[0..4].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        hhea[34..36].copy_from_slice(&3u16.to_be_bytes());
        let mut maxp = vec![0u8; 32];
        maxp[0..4].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        maxp[4..6].copy_from_slice(&3u16.to_be_bytes());
        maxp[26..28].copy_from_slice(&4u16.to_be_bytes());
        let hmtx: Vec<u8> = (0..3).flat_map(|_| [0x01, 0xF4, 0, 0]).collect();

        let mut t: BTreeMap<[u8; 4], Vec<u8>> = BTreeMap::new();
        t.insert(*b"glyf", glyf);
        t.insert(
            *b"loca",
            loca.iter().flat_map(|v| v.to_be_bytes()).collect(),
        );
        t.insert(*b"head", head);
        t.insert(*b"hhea", hhea);
        t.insert(*b"maxp", maxp);
        t.insert(*b"hmtx", hmtx);
        t.insert(*b"fpgm", vec![0xB0, 0x00, 0x2C, 0x2D]);
        t.insert(*b"prep", vec![0xB0, 0x00]);
        t.insert(*b"cvt ", vec![0, 1, 0, 2]);
        t.insert(*b"EVIL", b"payload".to_vec());
        write_sfnt(&t)
    }

    #[test]
    fn hinting_and_unknown_tables_are_removed() {
        let src = sample_font();
        assert!(ttf_parser::Face::parse(&src, 0).is_ok());
        let r = rebuild_truetype(&src).unwrap();
        let mut dropped = r.dropped_tables.clone();
        dropped.sort();
        assert_eq!(dropped, vec!["EVIL", "cvt", "fpgm", "prep"]);
        assert_eq!(r.stripped_glyphs, 3);
        let face = ttf_parser::Face::parse(&r.data, 0).unwrap();
        assert_eq!(face.number_of_glyphs(), 3);
        let bbox = face.glyph_bounding_box(ttf_parser::GlyphId(1)).unwrap();
        assert_eq!((bbox.x_max, bbox.y_max), (100, 100));
        assert!(!r.data.windows(7).any(|w| w == b"payload"));
        // 재조합 결과를 다시 재조합해도 동일 (안정)
        let again = rebuild_truetype(&r.data).unwrap();
        assert_eq!(again.data, r.data);
        assert_eq!(again.stripped_glyphs, 0);
    }

    #[test]
    fn malformed_fonts_are_rejected() {
        let src = sample_font();
        assert!(rebuild_truetype(b"OTTO....").is_err());
        assert!(rebuild_truetype(&src[..40]).is_err());
        let mut bad = src.clone();
        // loca 가 가리키는 범위를 망가뜨림
        let loca_at = (0..u16_at(&src, 4).unwrap() as usize)
            .map(|i| 12 + i * 16)
            .find(|&r| &src[r..r + 4] == b"loca")
            .map(|r| u32_at(&src, r + 8).unwrap() as usize)
            .unwrap();
        bad[loca_at + 2..loca_at + 4].copy_from_slice(&0xFFFFu16.to_be_bytes());
        assert!(rebuild_truetype(&bad).is_err());
    }

    #[test]
    fn embedded_truetype_is_rebuilt_inside_pdf() {
        use lopdf::{dictionary, Document, Object, Stream};
        let font = sample_font();
        let mut doc = Document::with_version("1.7");
        let pages = doc.new_object_id();
        let ff = doc.add_object(Stream::new(
            dictionary! { "Length1" => font.len() as i64 },
            font,
        ));
        let desc = doc.add_object(dictionary! {
            "Type" => "FontDescriptor", "FontName" => "Box", "Flags" => 4,
            "FontBBox" => vec![0.into(), 0.into(), 100.into(), 100.into()],
            "ItalicAngle" => 0, "Ascent" => 100, "Descent" => 0, "CapHeight" => 100, "StemV" => 10,
            "FontFile2" => ff,
        });
        let f = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "TrueType", "BaseFont" => "Box",
            "FirstChar" => 65, "LastChar" => 66, "Widths" => vec![500.into(), 500.into()], "FontDescriptor" => desc,
        });
        let content = doc.add_object(Stream::new(
            dictionary! {},
            b"BT /F1 20 Tf 10 10 Td (AB) Tj ET".to_vec(),
        ));
        let page = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages, "Contents" => content,
            "Resources" => dictionary! { "Font" => dictionary! { "F1" => f } },
        });
        doc.objects.insert(
            pages,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => vec![page.into()], "Count" => 1,
                "MediaBox" => vec![0.into(), 0.into(), 200.into(), 200.into()],
            }),
        );
        let cat = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages });
        doc.trailer.set("Root", cat);
        let mut src = Vec::new();
        doc.save_to(&mut src).unwrap();

        let mut findings = crate::report::Findings::default();
        let out =
            crate::pdf::reassemble(&src, &crate::policy::Policy::default(), &mut findings).unwrap();
        assert_eq!(findings.stats.get("fonts_rebuilt"), Some(&1));
        let out = Document::load_mem(&out).unwrap();
        let program = out
            .objects
            .values()
            .filter_map(|o| o.as_stream().ok())
            .filter_map(|s| s.get_plain_content().ok())
            .find(|d| is_truetype(d))
            .expect("글꼴 프로그램");
        assert!(!program.windows(7).any(|w| w == b"payload"));
        let face = ttf_parser::Face::parse(&program, 0).unwrap();
        assert!(face
            .raw_face()
            .table(ttf_parser::Tag::from_bytes(b"fpgm"))
            .is_none());
    }

    #[test]
    fn mutated_fonts_never_panic() {
        let src = sample_font();
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..5000 {
            let mut d = src.clone();
            for _ in 0..1 + next() % 6 {
                let i = (next() % d.len() as u64) as usize;
                d[i] = next() as u8;
            }
            if next() % 4 == 0 {
                d.truncate((next() % d.len() as u64) as usize);
            }
            if let Ok(r) = rebuild_truetype(&d) {
                // 결과물은 항상 독립 파서로 열리고, 다시 재조합해도 같다
                assert!(ttf_parser::Face::parse(&r.data, 0).is_ok());
                assert_eq!(rebuild_truetype(&r.data).unwrap().data, r.data);
            }
        }
    }

    /// 글리프 2개(.notdef, 사각형)짜리 최소 CFF. `glyph1` 로 두 번째 글리프 프로그램을 바꿀 수 있다
    pub(crate) fn sample_cff(glyph1: &[u8]) -> Vec<u8> {
        let index = |items: &[&[u8]]| {
            let mut v = (items.len() as u16).to_be_bytes().to_vec();
            v.push(1);
            let mut off = 1u8;
            v.push(off);
            for it in items {
                off += it.len() as u8;
                v.push(off);
            }
            for it in items {
                v.extend(*it);
            }
            v
        };
        let int5 = |n: i32| {
            let mut v = vec![29];
            v.extend(n.to_be_bytes());
            v
        };
        let notdef: &[u8] = &[14];
        let charstrings = index(&[notdef, glyph1]);
        let private = [139u8, 20]; // defaultWidthX 0
                                   // 헤더(4) + 이름 INDEX(8) + Top DICT INDEX(22) + 문자열 INDEX(2) + 전역 서브루틴 INDEX(2)
        let cs_at = 4 + 8 + 22 + 2 + 2;
        let private_at = cs_at + charstrings.len();
        let mut top = int5(cs_at as i32);
        top.push(17);
        top.extend(int5(private.len() as i32));
        top.extend(int5(private_at as i32));
        top.push(18);
        let mut out = vec![1, 0, 4, 1];
        out.extend(index(&[b"Box"]));
        out.extend(index(&[&top]));
        out.extend([0, 0, 0, 0]);
        assert_eq!(out.len(), cs_at);
        out.extend(charstrings);
        out.extend(private);
        out
    }

    const BOX: &[u8] = &[139, 139, 21, 239, 139, 5, 139, 239, 5, 39, 139, 5, 14];

    #[test]
    fn cff_glyph_programs_are_validated() {
        assert_eq!(validate_cff(&sample_cff(BOX)), Ok(2));
        // 로컬 서브루틴이 없는데 callsubr 을 부르는 글리프, 정의되지 않은 연산자
        for bad in [
            &[139u8, 139, 21, 139, 10, 14][..],
            &[139, 139, 21, 2, 14],
            &[139, 139, 21],
        ] {
            let e = validate_cff(&sample_cff(bad)).unwrap_err();
            assert!(e.contains("글리프 1"), "{e}");
        }
        assert!(validate_cff(b"not a font").is_err());
    }

    #[test]
    fn mutated_cff_never_panics() {
        let src = sample_cff(BOX);
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..5000 {
            let mut d = src.clone();
            for _ in 0..1 + next() % 4 {
                let i = (next() % d.len() as u64) as usize;
                d[i] = next() as u8;
            }
            let _ = validate_cff(&d);
        }
    }

    #[test]
    fn invalid_cff_font_program_is_dropped_from_pdf() {
        use lopdf::{dictionary, Document, Object, Stream};
        let build = |cff: Vec<u8>| {
            let mut doc = Document::with_version("1.7");
            let pages = doc.new_object_id();
            let ff = doc.add_object(Stream::new(dictionary! { "Subtype" => "Type1C" }, cff));
            let desc = doc.add_object(dictionary! {
                "Type" => "FontDescriptor", "FontName" => "Box", "Flags" => 4,
                "FontBBox" => vec![0.into(), 0.into(), 100.into(), 100.into()],
                "ItalicAngle" => 0, "Ascent" => 100, "Descent" => 0, "CapHeight" => 100, "StemV" => 10,
                "FontFile3" => ff,
            });
            let f = doc.add_object(dictionary! {
                "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Box",
                "FirstChar" => 65, "LastChar" => 65, "Widths" => vec![500.into()], "FontDescriptor" => desc,
            });
            let content = doc.add_object(Stream::new(
                dictionary! {},
                b"BT /F1 20 Tf 10 10 Td (A) Tj ET".to_vec(),
            ));
            let page = doc.add_object(dictionary! {
                "Type" => "Page", "Parent" => pages, "Contents" => content,
                "Resources" => dictionary! { "Font" => dictionary! { "F1" => f } },
            });
            doc.objects.insert(
                pages,
                Object::Dictionary(dictionary! {
                    "Type" => "Pages", "Kids" => vec![page.into()], "Count" => 1,
                    "MediaBox" => vec![0.into(), 0.into(), 200.into(), 200.into()],
                }),
            );
            let cat = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages });
            doc.trailer.set("Root", cat);
            let mut src = Vec::new();
            doc.save_to(&mut src).unwrap();
            let mut findings = crate::report::Findings::default();
            let out =
                crate::pdf::reassemble(&src, &crate::policy::Policy::default(), &mut findings)
                    .unwrap();
            let out = Document::load_mem(&out).unwrap();
            let has_program = out
                .objects
                .values()
                .any(|o| o.as_dict().is_ok_and(|d| d.has(b"FontFile3")));
            (findings, has_program)
        };
        let (f, kept) = build(sample_cff(BOX));
        assert!(kept);
        assert_eq!(f.stats.get("cff_fonts_validated"), Some(&1));
        let (f, kept) = build(sample_cff(&[139, 139, 21, 139, 10, 14]));
        assert!(!kept, "검증 실패 글꼴 프로그램이 남아 있음");
        assert!(f.items.iter().any(|x| x.category == "font"));
    }
}
