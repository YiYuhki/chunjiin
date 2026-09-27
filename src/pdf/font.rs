//! 내장 글꼴 프로그램 재조합·검증.
//!
//! TrueType(FontFile2, TrueType 외곽선 OpenType)과 CFF 기반 OpenType 은 원본 sfnt 를 옮기지 않고
//! 렌더링에 필요한 테이블만 **다시 만들어** 새 글꼴 파일을 조립한다.
//! - 힌팅 바이트코드(fpgm/prep/cvt 와 글리프별 명령어)는 TrueType 가상 머신에서 실행되는 코드라 제거
//! - glyf 는 글리프마다 구조(플래그·좌표·복합 구성 요소)를 해석한 길이만 옮기고 loca 를 새로 씀
//! - cmap 은 해석한 문자→글리프 대응으로 새로 만들고(형식 4/12), post 는 이름 없는 형식 3 으로,
//!   나머지 테이블은 규격 길이로 잘라 옮긴다. name 등 그 밖의 테이블은 버린다
//! - 결과물은 독립 파서(ttf-parser)로 모든 글리프 외곽선을 해석해 검증한다
//!
//! CFF(Type1C/CIDFontType0C)와 Type 1(FontFile) 글꼴은 독립 해석기로 모든 글리프를 실행해 얻은
//! 외곽선에서 새 CFF 를 만든다([`super::cffw`]). 새로 만들 수 없으면 모든 글리프 프로그램을
//! 끝까지 실행해 보고, 하나라도 비정상이면 거부한다.

use std::collections::BTreeMap;

/// TrueType 글꼴에 옮기는 테이블
const KEEP_TABLES: &[&[u8; 4]] = &[
    b"cmap", b"glyf", b"head", b"hhea", b"hmtx", b"loca", b"maxp", b"OS/2", b"post", b"vhea",
    b"vmtx",
];
/// CFF 기반 OpenType 에 옮기는 테이블
const KEEP_TABLES_CFF: &[&[u8; 4]] = &[
    b"CFF ", b"cmap", b"head", b"hhea", b"hmtx", b"maxp", b"OS/2", b"post", b"vhea", b"vmtx",
];
const REQUIRED_TABLES: &[&[u8; 4]] = &[b"glyf", b"head", b"hhea", b"hmtx", b"loca", b"maxp"];
/// cmap 에서 옮길 수 있는 최대 대응 수
const MAX_CMAP_MAPPINGS: usize = 1_200_000;

#[derive(Debug)]
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

/// 태그 → 테이블 본문
type Tables<'a> = BTreeMap<[u8; 4], &'a [u8]>;

/// sfnt 테이블 목록을 읽어 허용 테이블만 돌려준다
fn read_tables<'a>(data: &'a [u8], keep: &[&[u8; 4]]) -> Result<(Tables<'a>, Vec<String>), String> {
    let num_tables = u16_at(data, 4).ok_or("헤더 손상")? as usize;
    let mut tables = BTreeMap::new();
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
        if !keep.contains(&&tag) {
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
    Ok((tables, dropped))
}

/// 글리프 공통 테이블(head, hhea, hmtx, maxp, OS/2, post, vhea/vmtx, cmap)을 규격대로 다시 만든다
fn rebuild_common(
    tables: &BTreeMap<[u8; 4], &[u8]>,
    num_glyphs: usize,
    maxp_v1: bool,
    out: &mut BTreeMap<[u8; 4], Vec<u8>>,
) -> Result<(), String> {
    let head = tables.get(b"head").ok_or("head 없음")?;
    let hhea = tables.get(b"hhea").ok_or("hhea 없음")?;
    let hmtx = tables.get(b"hmtx").ok_or("hmtx 없음")?;
    if head.len() < 54 || hhea.len() < 36 {
        return Err("head/hhea 손상".into());
    }
    let mut new_head = head[..54].to_vec();
    new_head[8..12].fill(0); // checkSumAdjustment: 전체 계산 후 기록
    out.insert(*b"head", new_head);
    out.insert(*b"hhea", hhea[..36].to_vec());
    out.insert(
        *b"hmtx",
        metrics(hmtx, u16_at(hhea, 34).unwrap() as usize, num_glyphs).ok_or("hmtx 손상")?,
    );

    let maxp = tables.get(b"maxp").ok_or("maxp 없음")?;
    let new_maxp = if maxp_v1 {
        if maxp.len() < 32 || u32_at(maxp, 0) != Some(0x0001_0000) {
            return Err("maxp 손상".into());
        }
        let mut m = maxp[..32].to_vec();
        // 힌팅이 없으므로 명령어 관련 최대값을 0 으로
        for at in [16usize, 18, 20, 22, 24, 26] {
            m[at..at + 2].fill(0);
        }
        m
    } else {
        let mut m = 0x0000_5000u32.to_be_bytes().to_vec();
        m.extend((num_glyphs as u16).to_be_bytes());
        m
    };
    out.insert(*b"maxp", new_maxp);

    if let Some(os2) = tables.get(b"OS/2") {
        let need = match u16_at(os2, 0) {
            Some(0) => 78,
            Some(1) => 86,
            Some(2..=4) => 96,
            Some(5) => 100,
            _ => usize::MAX,
        };
        if os2.len() >= need {
            out.insert(*b"OS/2", os2[..need].to_vec());
        }
    }
    // post: 글리프 이름 없는 형식 3 (기울기·밑줄·고정폭 값만 유지)
    let mut post = 0x0003_0000u32.to_be_bytes().to_vec();
    match tables.get(b"post").filter(|p| p.len() >= 32) {
        Some(p) => post.extend(&p[4..16]),
        None => post.extend([0u8; 12]),
    }
    post.extend([0u8; 16]);
    out.insert(*b"post", post);

    if let (Some(vhea), Some(vmtx)) = (tables.get(b"vhea"), tables.get(b"vmtx")) {
        if vhea.len() >= 36 {
            if let Some(v) = metrics(vmtx, u16_at(vhea, 34).unwrap() as usize, num_glyphs) {
                out.insert(*b"vhea", vhea[..36].to_vec());
                out.insert(*b"vmtx", v);
            }
        }
    }
    if let Some(cmap) = tables.get(b"cmap") {
        out.insert(*b"cmap", rebuild_cmap(cmap, num_glyphs)?);
    }
    Ok(())
}

/// hmtx/vmtx: 긴 항목 n 개 + 짧은 항목 (글리프 수 - n) 개 길이로 자른다
fn metrics(table: &[u8], long: usize, num_glyphs: usize) -> Option<Vec<u8>> {
    if long == 0 || long > num_glyphs {
        return None;
    }
    let len = long * 4 + (num_glyphs - long) * 2;
    table.get(..len).map(<[u8]>::to_vec)
}

/// cmap 의 하위 테이블마다 문자→글리프 대응을 해석해 형식 4(BMP) 또는 12 로 새로 만든다.
/// 이체자 선택(형식 14) 등 대응으로 표현되지 않는 하위 테이블은 버린다.
fn rebuild_cmap(cmap: &[u8], num_glyphs: usize) -> Result<Vec<u8>, String> {
    let table = ttf_parser::cmap::Table::parse(cmap).ok_or("cmap 해석 실패")?;
    let mut subtables: BTreeMap<(u16, u16), Vec<(u32, u16)>> = BTreeMap::new();
    let mut total = 0usize;
    for sub in table.subtables {
        if matches!(
            sub.format,
            ttf_parser::cmap::Format::UnicodeVariationSequences(_)
        ) {
            continue;
        }
        let key = (sub.platform_id as u16, sub.encoding_id);
        if subtables.contains_key(&key) {
            continue;
        }
        let mut codes = Vec::new();
        let mut too_many = false;
        sub.codepoints(|cp| {
            if codes.len() < MAX_CMAP_MAPPINGS {
                codes.push(cp);
            } else {
                too_many = true;
            }
        });
        if too_many {
            return Err("cmap 대응 수 초과".into());
        }
        let mut map: Vec<(u32, u16)> = codes
            .into_iter()
            .filter_map(|cp| sub.glyph_index(cp).map(|g| (cp, g.0)))
            .filter(|&(_, g)| g != 0 && (g as usize) < num_glyphs)
            .collect();
        map.sort_unstable();
        map.dedup_by_key(|m| m.0);
        total += map.len();
        if total > MAX_CMAP_MAPPINGS {
            return Err("cmap 대응 수 초과".into());
        }
        subtables.insert(key, map);
    }
    let mut records = Vec::new();
    let mut bodies: Vec<u8> = Vec::new();
    let header = 4 + subtables.len() * 8;
    for ((platform, encoding), map) in &subtables {
        let body = if map.last().is_none_or(|m| m.0 <= 0xFFFF) {
            cmap_format4(map)
        } else {
            // 연속 증가 구간(12)과 같은 글리프 구간(13) 중 작은 쪽
            let (a, b) = (cmap_groups(map, 12), cmap_groups(map, 13));
            if a.len() <= b.len() {
                a
            } else {
                b
            }
        };
        records.push((*platform, *encoding, (header + bodies.len()) as u32));
        bodies.extend(body);
    }
    let mut out = 0u16.to_be_bytes().to_vec();
    out.extend((records.len() as u16).to_be_bytes());
    for (p, e, off) in records {
        out.extend(p.to_be_bytes());
        out.extend(e.to_be_bytes());
        out.extend(off.to_be_bytes());
    }
    out.extend(bodies);
    // 작은 cmap 을 거대하게 풀어내는 증폭 방지
    if out.len() > cmap.len().saturating_mul(4).max(1 << 20) {
        return Err("재조합한 cmap 이 비정상적으로 큼".into());
    }
    Ok(out)
}

fn cmap_format4(map: &[(u32, u16)]) -> Vec<u8> {
    // 코드와 글리프가 함께 1씩 늘어나는 구간을 한 세그먼트로 (idDelta 사용)
    let mut segs: Vec<(u16, u16, u16)> = Vec::new(); // (start, end, delta)
    for &(cp, g) in map {
        let cp = cp as u16;
        let delta = g.wrapping_sub(cp);
        match segs.last_mut() {
            Some(last) if last.1.wrapping_add(1) == cp && last.2 == delta && cp != 0xFFFF => {
                last.1 = cp
            }
            _ if cp == 0xFFFF => {}
            _ => segs.push((cp, cp, delta)),
        }
    }
    segs.push((0xFFFF, 0xFFFF, 1));
    let n = segs.len() as u16;
    let entry_selector = 15 - n.leading_zeros() as u16;
    let search_range = 2 * (1u16 << entry_selector);
    let len = 16 + segs.len() * 8;
    let mut out = Vec::with_capacity(len);
    out.extend(4u16.to_be_bytes());
    out.extend((len as u16).to_be_bytes());
    out.extend(0u16.to_be_bytes());
    out.extend((n * 2).to_be_bytes());
    out.extend(search_range.to_be_bytes());
    out.extend(entry_selector.to_be_bytes());
    out.extend((n * 2 - search_range).to_be_bytes());
    segs.iter().for_each(|s| out.extend(s.1.to_be_bytes()));
    out.extend(0u16.to_be_bytes());
    segs.iter().for_each(|s| out.extend(s.0.to_be_bytes()));
    segs.iter().for_each(|s| out.extend(s.2.to_be_bytes()));
    segs.iter().for_each(|_| out.extend(0u16.to_be_bytes()));
    out
}

/// 형식 12(코드·글리프가 함께 증가하는 구간) 또는 13(같은 글리프로 대응하는 구간)
fn cmap_groups(map: &[(u32, u16)], format: u16) -> Vec<u8> {
    let mut groups: Vec<(u32, u32, u32)> = Vec::new(); // (start, end, glyph)
    for &(cp, g) in map {
        let g = g as u32;
        match groups.last_mut() {
            Some(last)
                if last.1 + 1 == cp
                    && if format == 12 {
                        last.2 + (cp - last.0) == g
                    } else {
                        last.2 == g
                    } =>
            {
                last.1 = cp
            }
            _ => groups.push((cp, cp, g)),
        }
    }
    let mut out = format.to_be_bytes().to_vec();
    out.extend(0u16.to_be_bytes());
    out.extend(((16 + groups.len() * 12) as u32).to_be_bytes());
    out.extend(0u32.to_be_bytes());
    out.extend((groups.len() as u32).to_be_bytes());
    for (a, b, g) in groups {
        out.extend(a.to_be_bytes());
        out.extend(b.to_be_bytes());
        out.extend(g.to_be_bytes());
    }
    out
}

pub fn rebuild_truetype(data: &[u8]) -> Result<Rebuilt, String> {
    if !is_truetype(data) {
        return Err("TrueType 형식이 아님".into());
    }
    let (tables, dropped) = read_tables(data, KEEP_TABLES)?;
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
    if num_glyphs == 0 {
        return Err("글리프가 없음".into());
    }
    let long_loca = u16_at(head, 50).unwrap() == 1;
    let loca = tables[b"loca"];
    let glyf = tables[b"glyf"];

    // loca 는 단조 증가해야 한다 (겹치는 구간으로 같은 데이터를 여러 번 부풀리는 공격 방지).
    // 테이블 끝을 넘는 마지막 오프셋은 끝으로 맞춘다.
    let mut offsets = Vec::with_capacity(num_glyphs + 1);
    for i in 0..=num_glyphs {
        let o = if long_loca {
            u32_at(loca, i * 4).map(|v| v as usize)
        } else {
            u16_at(loca, i * 2).map(|v| v as usize * 2)
        }
        .ok_or("loca 손상")?;
        if offsets.last().is_some_and(|&prev| o < prev) {
            return Err(format!("loca 가 단조 증가하지 않음 (글리프 {i})"));
        }
        offsets.push(o);
    }
    let offsets: Vec<usize> = offsets.into_iter().map(|o| o.min(glyf.len())).collect();

    let mut new_glyf = Vec::with_capacity(glyf.len());
    let mut new_loca = Vec::with_capacity((num_glyphs + 1) * 4);
    let mut components: Vec<Vec<u16>> = vec![Vec::new(); num_glyphs];
    let mut has_outline = vec![false; num_glyphs];
    let mut stripped = 0;
    for gid in 0..num_glyphs {
        new_loca.extend((new_glyf.len() as u32).to_be_bytes());
        let parsed = strip_glyph(&glyf[offsets[gid]..offsets[gid + 1]], num_glyphs)
            .ok_or_else(|| format!("글리프 {gid} 구조 오류"))?;
        stripped += parsed.had_code as usize;
        has_outline[gid] = parsed.has_outline;
        components[gid] = parsed.components;
        new_glyf.extend(parsed.data);
        while new_glyf.len() % 4 != 0 {
            new_glyf.push(0);
        }
    }
    new_loca.extend((new_glyf.len() as u32).to_be_bytes());
    check_components(&components)?;
    // 복합 글리프는 구성 요소 중 외곽선이 있는 것이 있을 때만 외곽선이 있어야 한다
    // (예: 공백으로만 된 줄바꿈 없는 공백). 순환이 없음을 확인했으므로 반복해서 전파한다.
    let simple_outline = has_outline.clone();
    let mut has_outline: Vec<bool> = (0..num_glyphs)
        .map(|g| components[g].is_empty() && simple_outline[g])
        .collect();
    for _ in 0..=16 {
        let mut changed = false;
        for g in 0..num_glyphs {
            if !has_outline[g] && components[g].iter().any(|&c| has_outline[c as usize]) {
                has_outline[g] = true;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let mut out: BTreeMap<[u8; 4], Vec<u8>> = BTreeMap::new();
    rebuild_common(&tables, num_glyphs, true, &mut out)?;
    out.get_mut(b"head").unwrap()[50..52].copy_from_slice(&1u16.to_be_bytes()); // 긴 loca
    out.insert(*b"glyf", new_glyf);
    out.insert(*b"loca", new_loca);
    let data = write_sfnt(&out, 0x0001_0000);
    validate(&data, &has_outline)?;
    Ok(Rebuilt {
        data,
        dropped_tables: dropped,
        stripped_glyphs: stripped,
    })
}

struct Glyph {
    data: Vec<u8>,
    had_code: bool,
    /// 외곽선이 있어야 하는 글리프 (윤곽선 1개 이상 또는 복합)
    has_outline: bool,
    components: Vec<u16>,
}

/// 글리프 하나를 구조대로 해석해 명령어를 뺀 새 글리프를 만든다. 해석한 길이 뒤의 바이트는 버린다.
fn strip_glyph(g: &[u8], num_glyphs: usize) -> Option<Glyph> {
    if g.is_empty() {
        return Some(Glyph {
            data: Vec::new(),
            had_code: false,
            has_outline: false,
            components: Vec::new(),
        });
    }
    let contours = i16::from_be_bytes(g.get(0..2)?.try_into().ok()?);
    if contours >= 0 {
        let n = contours as usize;
        let ilen_at = 10 + n * 2;
        let ilen = u16_at(g, ilen_at)? as usize;
        let points = if n == 0 {
            0
        } else {
            let mut prev: Option<u16> = None;
            for i in 0..n {
                let e = u16_at(g, 10 + i * 2)?;
                if prev.is_some_and(|p| e <= p) {
                    return None;
                }
                prev = Some(e);
            }
            prev? as usize + 1
        };
        // 플래그(반복 포함)와 좌표 길이를 계산해 정확히 그만큼만 옮긴다
        let mut p = ilen_at + 2 + ilen;
        let flags_at = p;
        let (mut xs, mut ys, mut count) = (0usize, 0usize, 0usize);
        while count < points {
            let f = *g.get(p)?;
            p += 1;
            let repeat = if f & 0x08 != 0 {
                p += 1;
                *g.get(p - 1)? as usize
            } else {
                0
            };
            let k = repeat + 1;
            if count + k > points {
                return None;
            }
            count += k;
            xs += k * if f & 0x02 != 0 {
                1
            } else if f & 0x10 != 0 {
                0
            } else {
                2
            };
            ys += k * if f & 0x04 != 0 {
                1
            } else if f & 0x20 != 0 {
                0
            } else {
                2
            };
        }
        let end = p + xs + ys;
        let body = g.get(flags_at..end)?;
        let mut data = g[..ilen_at].to_vec();
        data.extend([0, 0]);
        data.extend(body);
        return Some(Glyph {
            data,
            had_code: ilen > 0,
            has_outline: n > 0,
            components: Vec::new(),
        });
    }
    // 복합 글리프: 구성 요소를 순회하며 WE_HAVE_INSTRUCTIONS 를 끄고 뒤의 명령어를 버린다
    const ARG_WORDS: u16 = 0x0001;
    const SCALE: u16 = 0x0008;
    const MORE: u16 = 0x0020;
    const XY_SCALE: u16 = 0x0040;
    const TWO_BY_TWO: u16 = 0x0080;
    const INSTRUCTIONS: u16 = 0x0100;
    let mut data = g.get(..10)?.to_vec();
    let mut p = 10;
    let mut had = false;
    let mut components = Vec::new();
    for _ in 0..num_glyphs.clamp(1, 4096) {
        let flags = u16_at(g, p)?;
        let glyph = u16_at(g, p + 2)?;
        if glyph as usize >= num_glyphs {
            return None;
        }
        components.push(glyph);
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
        data.extend((flags & !INSTRUCTIONS).to_be_bytes());
        data.extend(&comp[2..]);
        p += len;
        if flags & MORE == 0 {
            return Some(Glyph {
                data,
                had_code: had,
                has_outline: true,
                components,
            });
        }
    }
    None
}

/// 복합 글리프 참조에 순환이 없고 중첩이 깊지 않은지 확인한다
fn check_components(components: &[Vec<u16>]) -> Result<(), String> {
    const MAX_DEPTH: usize = 16;
    // 0: 미방문, 1: 방문 중, 2: 완료(깊이 확인됨)
    let mut state = vec![0u8; components.len()];
    let mut depth = vec![0usize; components.len()];
    fn visit(
        g: usize,
        components: &[Vec<u16>],
        state: &mut [u8],
        depth: &mut [usize],
        level: usize,
    ) -> Result<usize, String> {
        if level > MAX_DEPTH {
            return Err("복합 글리프 중첩이 너무 깊음".into());
        }
        match state[g] {
            1 => return Err(format!("복합 글리프 순환 참조 (글리프 {g})")),
            2 => return Ok(depth[g]),
            _ => {}
        }
        state[g] = 1;
        let mut d = 0;
        for &c in &components[g] {
            d = d.max(1 + visit(c as usize, components, state, depth, level + 1)?);
        }
        state[g] = 2;
        depth[g] = d;
        if d > MAX_DEPTH {
            return Err("복합 글리프 중첩이 너무 깊음".into());
        }
        Ok(d)
    }
    for g in 0..components.len() {
        if !components[g].is_empty() {
            visit(g, components, &mut state, &mut depth, 0)?;
        }
    }
    Ok(())
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

fn write_sfnt(tables: &BTreeMap<[u8; 4], Vec<u8>>, version: u32) -> Vec<u8> {
    let n = tables.len() as u16;
    let entry_selector = 15 - n.leading_zeros() as u16;
    let search_range = (1u16 << entry_selector) * 16;
    let mut out = Vec::new();
    out.extend(version.to_be_bytes());
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

/// 독립 파서로 새 글꼴을 열고 외곽선이 있어야 하는 모든 글리프가 해석되는지 확인한다
fn validate(data: &[u8], has_outline: &[bool]) -> Result<(), String> {
    let face =
        ttf_parser::Face::parse(data, 0).map_err(|e| format!("재조합 글꼴 검증 실패: {e}"))?;
    if face.number_of_glyphs() as usize != has_outline.len() {
        return Err("재조합 글꼴 글리프 수 불일치".into());
    }
    let mut bad = 0usize;
    let mut first = None;
    for (gid, &needed) in has_outline.iter().enumerate() {
        // 외곽선이 없는 글리프(공백 등)는 None 이 정상이다
        let ok = face
            .outline_glyph(ttf_parser::GlyphId(gid as u16), &mut Sink)
            .is_some();
        if needed && !ok {
            bad += 1;
            first.get_or_insert(gid);
        }
    }
    match first {
        None => Ok(()),
        Some(g) => Err(format!("해석되지 않는 글리프 {bad}개 (글리프 {g})")),
    }
}

/// CFF 기반 OpenType('OTTO')을 CFF 와 필수 테이블만으로 다시 조립한다 (CFF 는 전 글리프 검증)
pub fn rebuild_opentype_cff(data: &[u8]) -> Result<Rebuilt, String> {
    if !data.starts_with(b"OTTO") {
        return Err("CFF 기반 OpenType 이 아님".into());
    }
    let (tables, dropped) = read_tables(data, KEEP_TABLES_CFF)?;
    let cff = tables
        .get(b"CFF ")
        .ok_or("CFF 테이블이 없는 OpenType (CFF2 등 미지원)")?;
    let glyphs = validate_cff(cff)?;
    let mut out: BTreeMap<[u8; 4], Vec<u8>> = BTreeMap::new();
    rebuild_common(&tables, glyphs, false, &mut out)?;
    // CFF 테이블도 외곽선에서 새로 만든다 (실패하면 검증한 원본)
    let cff = match rebuild_cff(cff) {
        Ok((new, _)) => new,
        Err(_) => cff.to_vec(),
    };
    out.insert(*b"CFF ", cff);
    let data = write_sfnt(&out, u32::from_be_bytes(*b"OTTO"));
    ttf_parser::Face::parse(&data, 0).map_err(|e| format!("재조합 글꼴 검증 실패: {e}"))?;
    Ok(Rebuilt {
        data,
        dropped_tables: dropped,
        stripped_glyphs: 0,
    })
}

/// CFF 글꼴 프로그램(FontFile3 의 Type1C/CIDFontType0C, 또는 OpenType 의 CFF 테이블)을 검증한다.
/// 글리프 프로그램(Type 2 charstring)은 글꼴 엔진이 해석·실행하는 코드이므로, 독립 해석기로
/// 모든 글리프를 끝까지 해석해 보고 하나라도 비정상(스택·중첩 한도 초과, 잘못된 연산자,
/// 서브루틴 범위 오류, 범위 밖 읽기 등)이면 거부한다. 반환값: 검증한 글리프 수
pub fn validate_cff(cff_data: &[u8]) -> Result<usize, String> {
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

/// Type 1 글꼴 프로그램(FontFile)의 모든 글리프 프로그램(Type 1 charstring)을 독립 해석기로
/// 끝까지 실행해 본다. 반환값: 검증한 글리프 수
pub fn validate_type1(data: &[u8]) -> Result<usize, String> {
    use read_fonts::ps::type1::Type1Font;
    use read_fonts::types::GlyphId;
    struct Pen;
    impl read_fonts::model::pen::OutlinePen for Pen {
        fn move_to(&mut self, _: f32, _: f32) {}
        fn line_to(&mut self, _: f32, _: f32) {}
        fn quad_to(&mut self, _: f32, _: f32, _: f32, _: f32) {}
        fn curve_to(&mut self, _: f32, _: f32, _: f32, _: f32, _: f32, _: f32) {}
        fn close(&mut self) {}
    }
    let font = Type1Font::new(data).map_err(|_| "Type 1 구조 해석 실패".to_string())?;
    let n = font.num_glyphs();
    if n == 0 {
        return Err("글리프가 없음".into());
    }
    if n > 65_535 {
        return Err("글리프 수 초과".into());
    }
    let mut bad = 0usize;
    let mut first = None;
    for gid in 0..n {
        if let Err(e) = font.draw(GlyphId::new(gid), None, &mut Pen) {
            bad += 1;
            first.get_or_insert((gid, format!("{e:?}")));
        }
    }
    match first {
        None => Ok(n as usize),
        Some((gid, e)) => Err(format!(
            "비정상 글리프 프로그램 {bad}개 (글리프 {gid}: {e})"
        )),
    }
}

/// 새로 만든 CFF 를 독립 파서로 다시 열어, 글리프마다 외곽 경계와 폭이 원본과 같은지 확인한다
fn verify_cff(data: &[u8], glyphs: &[super::cffw::Glyph]) -> Result<(), String> {
    use super::cffw::{bounds, PathSink};
    let t = ttf_parser::cff::Table::parse(data).ok_or("재조합 CFF 해석 실패")?;
    if t.number_of_glyphs() as usize != glyphs.len() {
        return Err("재조합 CFF 글리프 수 불일치".into());
    }
    for (gid, g) in glyphs.iter().enumerate() {
        let mut sink = PathSink::default();
        match t.outline(ttf_parser::GlyphId(gid as u16), &mut sink) {
            Ok(_) | Err(ttf_parser::CFFError::ZeroBBox) => {}
            Err(e) => return Err(format!("재조합 글리프 {gid} 해석 실패: {e:?}")),
        }
        let same = match (bounds(&sink.path), bounds(&g.path)) {
            (None, None) => true,
            (Some(a), Some(b)) => a.iter().zip(b).all(|(x, y)| (x - y).abs() < 0.05),
            _ => false,
        };
        if !same {
            return Err(format!("재조합 글리프 {gid} 외곽선 불일치"));
        }
    }
    Ok(())
}

/// CFF 글꼴 프로그램(Type1C / CIDFontType0C)을 외곽선에서 새로 만든다. 반환: (CFF, 글리프 수)
pub fn rebuild_cff(cff_data: &[u8]) -> Result<(Vec<u8>, usize), String> {
    use super::cffw::{bounds, Font, Glyph, PathSink};
    let t = ttf_parser::cff::Table::parse(cff_data).ok_or("CFF 구조 해석 실패")?;
    let n = t.number_of_glyphs();
    if n == 0 {
        return Err("글리프가 없음".into());
    }
    let cid = t.glyph_cid(ttf_parser::GlyphId(0)).is_some();
    let mut glyphs = Vec::with_capacity(n as usize);
    let mut bbox: Option<[f64; 4]> = None;
    for gid in 0..n {
        let id = ttf_parser::GlyphId(gid);
        let mut sink = PathSink::default();
        match t.outline(id, &mut sink) {
            Ok(_) | Err(ttf_parser::CFFError::ZeroBBox) => {}
            Err(e) => return Err(format!("비정상 글리프 프로그램 (글리프 {gid}: {e:?})")),
        }
        if let Some(b) = bounds(&sink.path) {
            let u = bbox.get_or_insert(b);
            *u = [
                u[0].min(b[0]),
                u[1].min(b[1]),
                u[2].max(b[2]),
                u[3].max(b[3]),
            ];
        }
        glyphs.push(Glyph {
            name: if gid == 0 {
                ".notdef".into()
            } else {
                t.glyph_name(id)
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("g{gid}"))
            },
            cid: t.glyph_cid(id).unwrap_or(gid),
            width: t.glyph_width(id).map_or(0.0, f64::from),
            path: sink.path,
        });
    }
    let encoding = if cid {
        Vec::new()
    } else {
        (0..=255u8)
            .filter_map(|c| t.glyph_index(c).map(|g| (c, g.0)))
            .filter(|&(_, g)| g != 0)
            .collect()
    };
    // CID 글꼴은 FD 마다 행렬이 다를 수 있다: 0번 글리프의 FD 행렬로 맞추고 나머지는 좌표를 옮긴다
    let m = t.matrix();
    let mut matrix = super::cffw::top_matrix(cff_data)
        .unwrap_or([m.sx, m.ky, m.kx, m.sy, m.tx, m.ty].map(f64::from));
    if cid {
        let per =
            super::cffw::cid_matrices(cff_data, n as usize).ok_or("CID 글꼴 FD 행렬 해석 실패")?;
        matrix = per[0];
        let inv = super::cffw::invert(&matrix).ok_or("비정상 FontMatrix")?;
        for (g, fm) in glyphs.iter_mut().zip(&per) {
            if fm.iter().zip(&matrix).any(|(a, b)| (a - b).abs() > 1e-12) {
                super::cffw::transform(&mut g.path, &super::cffw::mul(fm, &inv));
            }
        }
        // 경계도 다시 계산
        bbox = None;
        for g in &glyphs {
            if let Some(b) = bounds(&g.path) {
                let u = bbox.get_or_insert(b);
                *u = [
                    u[0].min(b[0]),
                    u[1].min(b[1]),
                    u[2].max(b[2]),
                    u[3].max(b[3]),
                ];
            }
        }
    }
    let font = Font {
        name: super::cffw::font_name(cff_data).unwrap_or_else(|| "CDRFont".into()),
        matrix,
        bbox: bbox.unwrap_or([0.0; 4]),
        glyphs,
        encoding,
        cid,
    };
    let data = super::cffw::write(&font);
    verify_cff(&data, &font.glyphs)?;
    Ok((data, n as usize))
}

/// Type 1 글꼴 프로그램(FontFile)을 외곽선에서 CFF(Type1C)로 새로 만든다. 반환: (CFF, 글리프 수)
pub fn rebuild_type1(data: &[u8]) -> Result<(Vec<u8>, usize), String> {
    use super::cffw::{bounds, Font, Glyph, PathSink};
    use read_fonts::ps::cs::CommandSink;
    use read_fonts::ps::type1::Type1Font;
    use read_fonts::types::{Fixed, GlyphId};
    struct Sink<'a>(&'a mut PathSink);
    impl CommandSink for Sink<'_> {
        fn move_to(&mut self, x: Fixed, y: Fixed) {
            self.0.move_to(x.to_f64(), y.to_f64());
        }
        fn line_to(&mut self, x: Fixed, y: Fixed) {
            self.0.line_to(x.to_f64(), y.to_f64());
        }
        fn curve_to(&mut self, a: Fixed, b: Fixed, c: Fixed, d: Fixed, x: Fixed, y: Fixed) {
            self.0.curve_to(
                a.to_f64(),
                b.to_f64(),
                c.to_f64(),
                d.to_f64(),
                x.to_f64(),
                y.to_f64(),
            );
        }
        fn close(&mut self) {}
    }
    let font = Type1Font::new(data).map_err(|_| "Type 1 구조 해석 실패".to_string())?;
    let n = font.num_glyphs();
    if n == 0 || n > 65_535 {
        return Err("글리프 수 오류".into());
    }
    if font.glyph_name(GlyphId::new(0)) != Some(".notdef") {
        return Err(".notdef 가 첫 글리프가 아님".into());
    }
    let mut glyphs = Vec::with_capacity(n as usize);
    let mut bbox: Option<[f64; 4]> = None;
    for gid in 0..n {
        let mut path = PathSink::default();
        let width = font
            .evaluate_charstring(GlyphId::new(gid), &mut Sink(&mut path))
            .map_err(|e| format!("비정상 글리프 프로그램 (글리프 {gid}: {e:?})"))?;
        if let Some(b) = bounds(&path.path) {
            let u = bbox.get_or_insert(b);
            *u = [
                u[0].min(b[0]),
                u[1].min(b[1]),
                u[2].max(b[2]),
                u[3].max(b[3]),
            ];
        }
        glyphs.push(Glyph {
            name: font
                .glyph_name(GlyphId::new(gid))
                .map(str::to_string)
                .unwrap_or_else(|| format!("g{gid}")),
            cid: gid as u16,
            width: width.map_or(0.0, |w| w.to_f64()),
            path: path.path,
        });
    }
    let encoding = font
        .encoding()
        .map(|e| {
            (0..=255u8)
                .filter_map(|c| e.map(c).map(|g| (c, g.to_u32() as u16)))
                .filter(|&(_, g)| g != 0)
                .collect()
        })
        .unwrap_or_default();
    let upem = f64::from(font.upem().max(1));
    let m = font.matrix();
    let cff = Font {
        name: font.name().unwrap_or("CDRFont").to_string(),
        matrix: [m.xx, m.yx, m.xy, m.yy, m.dx, m.dy].map(|v| v.to_f64() / upem),
        bbox: bbox.unwrap_or([0.0; 4]),
        glyphs,
        encoding,
        cid: false,
    };
    let data = super::cffw::write(&cff);
    verify_cff(&data, &cff.glyphs)?;
    Ok((data, n as usize))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 사각형 글리프 하나(+ 명령어)와 힌팅 테이블을 가진 최소 TrueType 글꼴
    pub(crate) fn sample_font() -> Vec<u8> {
        write_sfnt(&sample_tables(), 0x0001_0000)
    }

    /// 샘플 글꼴의 테이블들 (테스트에서 일부를 바꿔 쓰기 위함)
    pub(crate) fn sample_tables() -> BTreeMap<[u8; 4], Vec<u8>> {
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
        t.insert(*b"name", b"name-payload".to_vec());
        // cmap: 'A' → 1, 'B' → 2 (형식 4) + 하위 테이블 뒤에 숨긴 데이터
        let mut cmap = 0u16.to_be_bytes().to_vec();
        cmap.extend(1u16.to_be_bytes());
        cmap.extend([0, 3, 0, 1, 0, 0, 0, 12]);
        cmap.extend(cmap_format4(&[(65, 1), (66, 2)]));
        cmap.extend(b"cmap-payload");
        t.insert(*b"cmap", cmap);
        t
    }

    #[test]
    fn hinting_and_unknown_tables_are_removed() {
        let src = sample_font();
        assert!(ttf_parser::Face::parse(&src, 0).is_ok());
        let r = rebuild_truetype(&src).unwrap();
        let mut dropped = r.dropped_tables.clone();
        dropped.sort();
        assert_eq!(dropped, vec!["EVIL", "cvt", "fpgm", "name", "prep"]);
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
            let _ = rebuild_cff(&d);
        }
        // Type 1 도 (eexec 부분을 변조)
        let src = sample_type1();
        let start = src.windows(6).position(|w| w == b"eexec\n").unwrap() + 6;
        for _ in 0..2000 {
            let mut d = src.clone();
            for _ in 0..1 + next() % 3 {
                let i = start + (next() % (d.len() - start) as u64) as usize;
                d[i] = b"0123456789abcdef"[(next() % 16) as usize];
            }
            let _ = rebuild_type1(&d);
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
        assert_eq!(f.stats.get("fonts_rebuilt"), Some(&1), "{:?}", f.stats);
        assert_eq!(f.stats.get("fonts_validated"), None);
        let (f, kept) = build(sample_cff(&[139, 139, 21, 139, 10, 14]));
        assert!(!kept, "검증 실패 글꼴 프로그램이 남아 있음");
        assert!(f.items.iter().any(|x| x.category == "font"));
    }

    #[test]
    fn tables_are_regenerated_not_copied() {
        let r = rebuild_truetype(&sample_font()).unwrap();
        for junk in [&b"payload"[..], b"name-payload", b"cmap-payload"] {
            assert!(
                !r.data.windows(junk.len()).any(|w| w == junk),
                "{:?}",
                String::from_utf8_lossy(junk)
            );
        }
        let face = ttf_parser::Face::parse(&r.data, 0).unwrap();
        assert_eq!(face.glyph_index('A').map(|g| g.0), Some(1));
        assert_eq!(face.glyph_index('B').map(|g| g.0), Some(2));
        assert!(face
            .raw_face()
            .table(ttf_parser::Tag::from_bytes(b"name"))
            .is_none());
    }

    #[test]
    fn overlapping_loca_and_composite_cycles_are_rejected() {
        // loca 가 되돌아가며 같은 데이터를 여러 번 가리키는 글꼴 (메모리 증폭 공격)
        let mut t = sample_tables();
        let loca: Vec<u8> = [0u16, 20, 0, 20]
            .iter()
            .flat_map(|v| v.to_be_bytes())
            .collect();
        t.insert(*b"loca", loca);
        let e = rebuild_truetype(&write_sfnt(&t, 0x0001_0000)).unwrap_err();
        assert!(e.contains("단조"), "{e}");

        // 자기 자신을 구성 요소로 참조하는 복합 글리프
        let mut t = sample_tables();
        let glyf = t.get_mut(b"glyf").unwrap();
        let comp_at = glyf.len() - 16; // 마지막 글리프(복합)의 구성 요소 글리프 번호 위치
        let pos = (comp_at..glyf.len() - 1)
            .find(|&i| glyf[i - 2..i] == (0x0001u16 | 0x0002 | 0x0100).to_be_bytes())
            .unwrap();
        glyf[pos..pos + 2].copy_from_slice(&2u16.to_be_bytes());
        let e = rebuild_truetype(&write_sfnt(&t, 0x0001_0000)).unwrap_err();
        assert!(e.contains("순환"), "{e}");
    }

    #[test]
    fn opentype_cff_is_reassembled_with_needed_tables_only() {
        let mut t = sample_tables();
        for k in [b"glyf", b"loca", b"fpgm", b"prep", b"cvt "] {
            t.remove(k);
        }
        t.insert(*b"CFF ", sample_cff(BOX));
        t.get_mut(b"maxp").unwrap()[4..6].copy_from_slice(&2u16.to_be_bytes());
        let hhea = t.get_mut(b"hhea").unwrap();
        hhea[34..36].copy_from_slice(&2u16.to_be_bytes());
        t.insert(*b"GSUB", b"layout-payload".to_vec());
        let otf = write_sfnt(&t, u32::from_be_bytes(*b"OTTO"));
        let r = rebuild_opentype_cff(&otf).unwrap();
        assert!(r.data.starts_with(b"OTTO"));
        for junk in [&b"payload"[..], b"layout-payload", b"name-payload"] {
            assert!(!r.data.windows(junk.len()).any(|w| w == junk));
        }
        let face = ttf_parser::Face::parse(&r.data, 0).unwrap();
        assert_eq!(face.glyph_index('A').map(|g| g.0), Some(1));
        // 비정상 글리프 프로그램을 가진 CFF 는 거부
        t.insert(*b"CFF ", sample_cff(&[139, 139, 21, 139, 10, 14]));
        assert!(rebuild_opentype_cff(&write_sfnt(&t, u32::from_be_bytes(*b"OTTO"))).is_err());
    }

    /// eexec 로 암호화한 최소 Type 1 글꼴 (PFA): .notdef, A(사각형), B(서브루틴 호출)
    fn sample_type1() -> Vec<u8> {
        fn enc(data: &[u8], mut r: u16) -> Vec<u8> {
            data.iter()
                .map(|&p| {
                    let c = p ^ (r >> 8) as u8;
                    r = (u16::from(c).wrapping_add(r))
                        .wrapping_mul(52845)
                        .wrapping_add(22719);
                    c
                })
                .collect()
        }
        fn num(v: i32, out: &mut Vec<u8>) {
            match v {
                -107..=107 => out.push((v + 139) as u8),
                108..=1131 => {
                    out.push(((v - 108) / 256 + 247) as u8);
                    out.push(((v - 108) % 256) as u8);
                }
                _ => {
                    out.push(255);
                    out.extend(v.to_be_bytes());
                }
            }
        }
        let cs = |ops: &[(&[i32], u8)]| {
            let mut v = vec![0u8; 4]; // lenIV
            for (args, op) in ops {
                for a in *args {
                    num(*a, &mut v);
                }
                v.push(*op);
            }
            enc(&v, 4330)
        };
        let notdef = cs(&[(&[0, 500], 13), (&[], 14)]);
        let a = cs(&[
            (&[0, 600], 13),
            (&[50, 0], 21),
            (&[400, 0], 5),
            (&[0, 700], 5),
            (&[-400, 0], 5),
            (&[], 9),
            (&[], 14),
        ]);
        // B: 서브루틴 0 이 사각형을 그린다
        let sub = cs(&[
            (&[100, 100], 21),
            (&[200, 0], 5),
            (&[0, 200], 5),
            (&[], 9),
            (&[], 11),
        ]);
        let b = cs(&[(&[0, 400], 13), (&[0], 10), (&[], 14)]);
        let mut private: Vec<u8> = Vec::new();
        private.extend(b"dup /Private 8 dict dup begin\n/RD{string currentfile exch readstring pop}executeonly def\n/ND{noaccess def}executeonly def\n/NP{noaccess put}executeonly def\n/lenIV 4 def\n/Subrs 1 array\n");
        private.extend(format!("dup 0 {} RD ", sub.len()).as_bytes());
        private.extend(&sub);
        private.extend(b" NP\nND\n2 index /CharStrings 3 dict dup begin\n");
        for (name, c) in [(".notdef", &notdef), ("A", &a), ("B", &b)] {
            private.extend(format!("/{name} {} RD ", c.len()).as_bytes());
            private.extend(c.iter());
            private.extend(b" ND\n");
        }
        private.extend(b"end\nend\nreadonly put\nnoaccess put\ndup/FontName get exch definefont pop\nmark currentfile closefile\n");
        let mut plain = vec![0u8; 4];
        plain.extend(private);
        let hex: String = enc(&plain, 55665)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let mut out = b"%!PS-AdobeFont-1.0: T1Test 001\n11 dict begin\n/FontName /T1Test def\n/PaintType 0 def\n/FontType 1 def\n/FontMatrix [0.001 0 0 0.001 0 0] readonly def\n/Encoding StandardEncoding def\n/FontBBox {0 0 500 700} readonly def\ncurrentdict end\ncurrentfile eexec\n".to_vec();
        for line in hex.as_bytes().chunks(64) {
            out.extend(line);
            out.push(b'\n');
        }
        for _ in 0..8 {
            out.extend([b'0'; 64]);
            out.push(b'\n');
        }
        out.extend(b"cleartomark\n");
        out
    }

    #[test]
    fn type1_is_rebuilt_as_cff() {
        let t1 = sample_type1();
        validate_type1(&t1).expect("표본 Type 1");
        let (cff, n) = rebuild_type1(&t1).unwrap();
        assert_eq!(n, 3);
        let t = ttf_parser::cff::Table::parse(&cff).unwrap();
        assert_eq!(t.glyph_name(ttf_parser::GlyphId(1)), Some("A"));
        assert_eq!(t.glyph_width(ttf_parser::GlyphId(1)), Some(600));
        // 표준 인코딩 그대로: 65 → A, 66 → B
        assert_eq!(t.glyph_index(65), Some(ttf_parser::GlyphId(1)));
        assert_eq!(t.glyph_index(66), Some(ttf_parser::GlyphId(2)));
        let mut sink = super::super::cffw::PathSink::default();
        let r = t.outline(ttf_parser::GlyphId(2), &mut sink).unwrap();
        // 서브루틴이 펼쳐져 같은 사각형이 된다
        assert_eq!((r.x_min, r.y_min, r.x_max, r.y_max), (100, 100, 300, 300));
        assert!((t.matrix().sx - 0.001).abs() < 1e-7);
        // CFF 로 다시 만든 것도 다시 만들면 같은 결과
        let (again, _) = rebuild_cff(&cff).unwrap();
        assert_eq!(again, cff, "고정점");
    }

    #[test]
    fn type1_font_file_becomes_type1c_in_pdf() {
        use lopdf::{dictionary, Document, Object, Stream};
        let mut doc = Document::with_version("1.7");
        let pages = doc.new_object_id();
        let ff = doc.add_object(Stream::new(dictionary! {}, sample_type1()));
        let desc = doc.add_object(dictionary! {
            "Type" => "FontDescriptor", "FontName" => "T1Test", "Flags" => 32,
            "FontBBox" => vec![0.into(), 0.into(), 500.into(), 700.into()],
            "ItalicAngle" => 0, "Ascent" => 700, "Descent" => 0, "CapHeight" => 700, "StemV" => 10,
            "FontFile" => ff,
        });
        let f = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "T1Test",
            "FirstChar" => 65, "LastChar" => 66,
            "Widths" => vec![600.into(), 400.into()], "FontDescriptor" => desc,
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
        let out = Document::load_mem(&out).unwrap();
        let desc = out
            .objects
            .values()
            .find_map(|o| o.as_dict().ok().filter(|d| d.has(b"FontName")))
            .unwrap();
        assert!(!desc.has(b"FontFile") && desc.has(b"FontFile3"), "{desc:?}");
        let id = desc.get(b"FontFile3").unwrap().as_reference().unwrap();
        let s = out.get_object(id).unwrap().as_stream().unwrap();
        assert_eq!(
            s.dict.get(b"Subtype").unwrap().as_name().unwrap(),
            b"Type1C"
        );
        let cff = s.get_plain_content().unwrap();
        assert!(ttf_parser::cff::Table::parse(&cff).is_some());
        assert_eq!(findings.stats.get("fonts_rebuilt"), Some(&1));
    }

    #[test]
    fn type1_programs_are_validated() {
        assert!(validate_type1(
            b"%!PS-AdobeFont-1.0: X\n/FontName /X def\ncurrentfile eexec\n\x00\x01"
        )
        .is_err());
        assert!(validate_type1(b"not a font").is_err());
    }
}
