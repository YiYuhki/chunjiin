//! EMF(Enhanced Metafile) 재조합 ([MS-EMF]).

use super::dib::{self, Dib};
use super::{pad4, rd, Stats};
use crate::error::{blocked, Result};
use crate::legacy::blip::PixelBudget;
use crate::policy::Policy;

const EMR_HEADER: u32 = 1;
const EMR_EOF: u32 = 14;
const EMR_COMMENT: u32 = 70;
const SIGNATURE: u32 = 0x464D_4520; // " EMF"
const EMF_PLUS: u32 = 0x2B46_4D45; // "EMF+"
const HEADER_SIZE: usize = 108;
/// 스톡 개체(WHITE_BRUSH ~ DC_PEN)
const STOCK_FIRST: u32 = 0x8000_0000;
const STOCK_LAST: u32 = 0x8000_0013;
const DEFAULT_PALETTE: u32 = 0x8000_000F;

pub fn is_emf(d: &[u8]) -> bool {
    rd::u32(d, 0) == Some(EMR_HEADER) && rd::u32(d, 40) == Some(SIGNATURE)
}

fn fail<T>(msg: &str) -> Result<T> {
    blocked("metafile", format!("EMF 구조 오류: {msg}"))
}

struct Ctx<'a> {
    policy: &'a Policy,
    budget: &'a mut PixelBudget,
    handles: u32,
    bitmaps: u64,
}

impl Ctx<'_> {
    fn handle(&self, ih: u32) -> bool {
        ih >= 1 && ih < self.handles
    }

    fn selectable(&self, ih: u32) -> bool {
        self.handle(ih) || (STOCK_FIRST..=STOCK_LAST).contains(&ih)
    }
}

pub fn rebuild(
    data: &[u8],
    policy: &Policy,
    budget: &mut PixelBudget,
    stats: &mut Stats,
) -> Result<Vec<u8>> {
    if !is_emf(data) {
        return fail("머리글");
    }
    let hsize = rd::u32(data, 4).unwrap_or(0) as usize;
    if hsize < 88 || !hsize.is_multiple_of(4) || hsize > data.len() {
        return fail("머리글 크기");
    }
    let handles = rd::u16(data, 56).unwrap_or(0);
    let n_desc = rd::u32(data, 60).unwrap_or(0);
    let off_desc = rd::u32(data, 64).unwrap_or(0) as usize;
    // 확장 머리글(픽셀 형식, 마이크로미터 크기)은 설명 문자열과 겹치지 않을 때만 믿는다
    let ext = |end: usize| hsize >= end && (n_desc == 0 || off_desc >= end);
    let micrometers = if ext(108) && rd::u32(data, 88).unwrap_or(0) == 0 {
        data[100..108].to_vec()
    } else {
        let mm_x = rd::i32(data, 80).unwrap_or(0).saturating_mul(1000);
        let mm_y = rd::i32(data, 84).unwrap_or(0).saturating_mul(1000);
        [mm_x.to_le_bytes(), mm_y.to_le_bytes()].concat()
    };

    let mut out = Vec::with_capacity(data.len().min(1 << 24));
    out.extend(EMR_HEADER.to_le_bytes());
    out.extend((HEADER_SIZE as u32).to_le_bytes());
    out.extend(&data[8..40]); // Bounds, Frame
    out.extend(SIGNATURE.to_le_bytes());
    out.extend(0x0001_0000u32.to_le_bytes());
    out.extend([0; 8]); // Bytes, Records (나중에 채움)
    out.extend(handles.to_le_bytes());
    out.extend([0; 2]);
    out.extend([0; 12]); // nDescription, offDescription, nPalEntries
    out.extend(&data[72..88]); // Device, Millimeters
    out.extend([0; 12]); // cbPixelFormat, offPixelFormat, bOpenGL
    out.extend(&micrometers);
    debug_assert_eq!(out.len(), HEADER_SIZE);

    let mut ctx = Ctx {
        policy,
        budget,
        handles: handles as u32,
        bitmaps: 0,
    };
    let mut records: u32 = 1;
    let mut emf_plus = false;
    let mut emf_plus_only = false;
    let mut gdi_drawing = false;
    let mut p = hsize;
    while let (Some(t), Some(size)) = (rd::u32(data, p), rd::u32(data, p + 4)) {
        let size = size as usize;
        if size < 8 || !size.is_multiple_of(4) || size > data.len() - p {
            // 깨진 레코드에서 멈춘다 (렌더러도 여기서 멈춤)
            stats.invalid += 1;
            break;
        }
        let rec = &data[p..p + size];
        p += size;
        if t == EMR_EOF {
            break;
        }
        stats.records += 1;
        if t == EMR_COMMENT {
            if rd::u32(rec, 12) == Some(EMF_PLUS) {
                // 첫 EMF+ 레코드가 머리글이면 이중(EMF+ + GDI) 여부를 확인한다
                if !emf_plus && rd::u16(rec, 16) == Some(0x4001) {
                    emf_plus_only = rd::u16(rec, 18).is_some_and(|f| f & 1 == 0);
                }
                emf_plus = true;
            }
            stats.removed += 1;
            continue;
        }
        match record(t, rec, &mut ctx)? {
            Some(body) => {
                if is_drawing(t) {
                    gdi_drawing = true;
                }
                let mut r = Vec::with_capacity(body.len() + 8);
                r.extend(t.to_le_bytes());
                r.extend(((body.len() + 8) as u32).to_le_bytes());
                r.extend(&body);
                debug_assert_eq!(r.len() % 4, 0);
                out.extend(r);
                records += 1;
            }
            None if supported(t) => stats.invalid += 1,
            None => stats.removed += 1,
        }
    }
    // EOF: 팔레트 없음
    out.extend(EMR_EOF.to_le_bytes());
    out.extend(20u32.to_le_bytes());
    out.extend(0u32.to_le_bytes());
    out.extend(16u32.to_le_bytes());
    out.extend(20u32.to_le_bytes());
    records += 1;

    let Ok(total) = u32::try_from(out.len()) else {
        return fail("크기");
    };
    out[48..52].copy_from_slice(&total.to_le_bytes());
    out[52..56].copy_from_slice(&records.to_le_bytes());
    stats.bitmaps += ctx.bitmaps;
    if emf_plus && (emf_plus_only || !gdi_drawing) {
        stats.emf_plus_only += 1;
    }
    Ok(out)
}

/// 검증해 옮기는 레코드 종류 (나머지는 형식과 무관하게 옮기지 않음)
fn supported(t: u32) -> bool {
    matches!(t, 2..=13 | 15..=69 | 71..=77 | 80..=95 | 98 | 114..=116 | 118 | 120)
        && !matches!(t, 69 | 78 | 79 | 96 | 97 | 99..=113 | 117 | 119)
}

/// 화면에 무언가를 그리는 레코드인지 (EMF+ 전용 판정용)
fn is_drawing(t: u32) -> bool {
    matches!(t, 2..=8 | 41..=47 | 53..=56 | 62..=64 | 71..=74 | 76..=81 | 83..=92 | 114 | 116 | 118)
}

/// 레코드 하나를 검증해 정규형 본문(레코드 머리 8바이트 제외)을 돌려준다. 옮기지 않으면 None.
fn record(t: u32, rec: &[u8], ctx: &mut Ctx) -> Result<Option<Vec<u8>>> {
    let b = &rec[8..];
    let fixed = |n: usize| b.get(..n).map(<[u8]>::to_vec);
    let u = |at: usize| rd::u32(b, at);
    Ok(match t {
        // 좌표·모드·상태 (고정 길이)
        9..=13 | 26 | 27 | 54 | 120 => fixed(8),
        15 => fixed(12),
        16..=22 | 24 | 25 | 34 | 57 | 58 | 67 | 98 | 115 => fixed(4),
        23 => fixed(24),
        28 | 33 | 52 | 59..=61 | 65 | 66 | 68 => Some(Vec::new()),
        29..=32 | 42 | 43 | 53 | 62..=64 => fixed(16),
        35 => fixed(24),
        36 => fixed(28),
        41 => fixed(20),
        44 => fixed(24),
        45..=47 | 55 => fixed(32),

        // 개체
        37 => u(0).filter(|&ih| ctx.selectable(ih)).and(fixed(4)),
        40 => u(0).filter(|&ih| ctx.handle(ih)).and(fixed(4)),
        48 => u(0)
            .filter(|&ih| ctx.handle(ih) || ih == DEFAULT_PALETTE)
            .and(fixed(4)),
        38 => u(0).filter(|&ih| ctx.handle(ih)).and(fixed(20)),
        39 => match (u(0).filter(|&ih| ctx.handle(ih)), fixed(16)) {
            (Some(_), Some(mut v)) => {
                // 이 레코드의 브러시 형식은 단색·빈 브러시·빗금만 허용된다
                if !matches!(rd::u32(&v, 4), Some(0..=2)) {
                    v[4..8].copy_from_slice(&0u32.to_le_bytes());
                }
                Some(v)
            }
            _ => None,
        },
        82 => font(b, ctx),
        49 => palette(b, ctx),
        50 => palette_entries(b, ctx),
        51 => u(0)
            .filter(|&ih| ctx.handle(ih))
            .and(u(4).filter(|&n| n <= 1024))
            .and(fixed(8)),
        95 => ext_pen(b, ctx),
        93 | 94 => {
            if !u(0).is_some_and(|ih| ctx.handle(ih)) {
                None
            } else {
                bitmap(rec, 24, 8, u(4).unwrap_or(0), None, false, ctx)?
            }
        }

        // 좌표 배열
        2..=6 => poly(b, 8),
        85..=89 => poly(b, 4),
        7 | 8 => poly_poly(b, 8),
        90 | 91 => poly_poly(b, 4),
        56 => poly_draw(b, 8),
        92 => poly_draw(b, 4),

        // 영역
        71 => region_record(b, 24, ctx.selectable_at(b, 20)),
        72 => region_record(b, 32, ctx.selectable_at(b, 20)),
        73 | 74 => region_record(b, 20, true),
        75 => clip_region(b),

        // 비트맵
        76 => bitmap(rec, 92, 76, u(72).unwrap_or(0), None, true, ctx)?,
        77 | 114 | 116 => bitmap(rec, 100, 76, u(72).unwrap_or(0), None, true, ctx)?,
        81 => bitmap(rec, 72, 40, u(56).unwrap_or(0), None, false, ctx)?,
        80 => bitmap(rec, 68, 40, u(56).unwrap_or(0), u(64), false, ctx)?,

        // 글자
        83 => text(b, 1),
        84 => text(b, 2),

        118 => gradient(b),

        // 그 밖(주석, 이스케이프, 색 프로필, OpenGL, MaskBlt/PlgBlt, PolyTextOut 등)은 옮기지 않는다
        _ => None,
    })
}

impl Ctx<'_> {
    fn selectable_at(&self, b: &[u8], at: usize) -> bool {
        rd::u32(b, at).is_some_and(|ih| self.selectable(ih))
    }
}

/// 한 레코드 안의 좌표 배열: Bounds(16) + 개수 + 좌표
fn poly(b: &[u8], pt: usize) -> Option<Vec<u8>> {
    let n = rd::u32(b, 16)? as usize;
    let len = 20usize.checked_add(n.checked_mul(pt)?)?;
    b.get(..len).map(|v| {
        let mut v = v.to_vec();
        pad4(&mut v);
        v
    })
}

/// 여러 도형: Bounds(16) + 도형 수 + 전체 좌표 수 + 도형별 좌표 수 + 좌표
fn poly_poly(b: &[u8], pt: usize) -> Option<Vec<u8>> {
    let polys = rd::u32(b, 16)? as usize;
    let count = rd::u32(b, 20)? as usize;
    let counts = rd::slice(b, 24, polys.checked_mul(4)?)?;
    let sum = counts.as_chunks::<4>().0.iter().try_fold(0usize, |s, c| {
        s.checked_add(u32::from_le_bytes(*c) as usize)
    })?;
    if sum != count {
        return None;
    }
    let len = (24 + polys * 4).checked_add(count.checked_mul(pt)?)?;
    b.get(..len).map(<[u8]>::to_vec)
}

/// PolyDraw: Bounds(16) + 개수 + 좌표 + 점 종류(바이트) + 채움
fn poly_draw(b: &[u8], pt: usize) -> Option<Vec<u8>> {
    let n = rd::u32(b, 16)? as usize;
    let len = 20usize.checked_add(n.checked_mul(pt)?)?.checked_add(n)?;
    let mut v = b.get(..len)?.to_vec();
    pad4(&mut v);
    Some(v)
}

/// RegionData(머리 32 + 사각형) 를 정규형으로 만든다
fn region_data(d: &[u8]) -> Option<Vec<u8>> {
    if rd::u32(d, 0)? != 32 || rd::u32(d, 4)? != 1 {
        return None;
    }
    let n = rd::u32(d, 8)? as usize;
    let rects = rd::slice(d, 32, n.checked_mul(16)?)?;
    let mut v = Vec::with_capacity(32 + rects.len());
    v.extend(32u32.to_le_bytes());
    v.extend(1u32.to_le_bytes());
    v.extend((n as u32).to_le_bytes());
    v.extend((rects.len() as u32).to_le_bytes());
    v.extend(&d[16..32]);
    v.extend(rects);
    Some(v)
}

/// 영역 레코드: 고정 부분(`at` 까지, 16..20 은 cbRgnData) + RegionData
fn region_record(b: &[u8], at: usize, handle_ok: bool) -> Option<Vec<u8>> {
    if !handle_ok {
        return None;
    }
    let cb = rd::u32(b, 16)? as usize;
    let rgn = region_data(rd::slice(b, at, cb)?)?;
    let mut v = b.get(..at)?.to_vec();
    v[16..20].copy_from_slice(&(rgn.len() as u32).to_le_bytes());
    v.extend(rgn);
    Some(v)
}

/// ExtSelectClipRgn: cbRgnData + 방식 + RegionData (RGN_COPY 이면 영역 없이 초기화 가능)
fn clip_region(b: &[u8]) -> Option<Vec<u8>> {
    let cb = rd::u32(b, 0)? as usize;
    let mode = rd::u32(b, 4)?;
    if !(1..=5).contains(&mode) {
        return None;
    }
    if cb == 0 {
        return (mode == 5).then(|| b[..8].to_vec());
    }
    let rgn = region_data(rd::slice(b, 8, cb)?)?;
    let mut v = Vec::with_capacity(8 + rgn.len());
    v.extend((rgn.len() as u32).to_le_bytes());
    v.extend(mode.to_le_bytes());
    v.extend(rgn);
    Some(v)
}

/// ExtCreateFontIndirectW: 개체 번호 + LogFont(92) 만 옮긴다 (글꼴 이름은 NUL 로 끝나게)
fn font(b: &[u8], ctx: &Ctx) -> Option<Vec<u8>> {
    if !ctx.handle(rd::u32(b, 0)?) {
        return None;
    }
    let mut v = b.get(..96)?.to_vec();
    v[94] = 0;
    v[95] = 0;
    Some(v)
}

/// CreatePalette: 개체 번호 + LogPalette(버전, 개수, 항목)
fn palette(b: &[u8], ctx: &Ctx) -> Option<Vec<u8>> {
    if !ctx.handle(rd::u32(b, 0)?) || rd::u16(b, 4)? != 0x0300 {
        return None;
    }
    let n = rd::u16(b, 6)? as usize;
    if n == 0 || n > 1024 {
        return None;
    }
    b.get(..8 + n * 4).map(<[u8]>::to_vec)
}

/// SetPaletteEntries: 개체 번호 + 시작 + 개수 + 항목
fn palette_entries(b: &[u8], ctx: &Ctx) -> Option<Vec<u8>> {
    if !ctx.handle(rd::u32(b, 0)?) {
        return None;
    }
    let start = rd::u32(b, 4)?;
    let n = rd::u32(b, 8)? as usize;
    if n > 1024 || start > 1024 {
        return None;
    }
    b.get(..12 + n * 4).map(<[u8]>::to_vec)
}

/// ExtCreatePen: 비트맵 무늬 펜은 단색 펜으로 바꾼다 (비트맵 없음)
fn ext_pen(b: &[u8], ctx: &Ctx) -> Option<Vec<u8>> {
    if !ctx.handle(rd::u32(b, 0)?) {
        return None;
    }
    let n = rd::u32(b, 40)? as usize;
    if n > 16 {
        return None;
    }
    let mut v = b.get(..44 + n * 4)?.to_vec();
    v[4..20].fill(0); // offBmi, cbBmi, offBits, cbBits
    if !matches!(rd::u32(&v, 28), Some(0..=2)) {
        v[28..32].copy_from_slice(&0u32.to_le_bytes());
        v[36..40].fill(0);
    }
    Some(v)
}

/// 비트맵을 담는 레코드. `fixed`: 고정 본문 길이, `offs`: 본문 안 offBmi 위치(이어서 cbBmi,
/// offBits, cbBits), `usage`: 색상표 형식, `rows`: 일부 줄만 담긴 경우 줄 수,
/// `optional`: 비트맵 없는 레코드(무늬 채우기)를 허용할지
fn bitmap(
    rec: &[u8],
    fixed: usize,
    offs: usize,
    usage: u32,
    rows: Option<u32>,
    optional: bool,
    ctx: &mut Ctx,
) -> Result<Option<Vec<u8>>> {
    let b = &rec[8..];
    let Some(mut body) = b.get(..fixed).map(<[u8]>::to_vec) else {
        return Ok(None);
    };
    let field = |i: usize| rd::u32(b, offs + i * 4).unwrap_or(0) as usize;
    let (off_bmi, cb_bmi, off_bits, cb_bits) = (field(0), field(1), field(2), field(3));
    if cb_bmi == 0 {
        if !optional {
            return Ok(None);
        }
        body[offs..offs + 16].fill(0);
        return Ok(Some(body));
    }
    let (Some(info), Some(bits)) = (
        rd::slice(rec, off_bmi, cb_bmi),
        rd::slice(rec, off_bits, cb_bits),
    ) else {
        return Ok(None);
    };
    let Some(Dib { mut info, bits }) =
        dib::canonical(info, bits, usage, rows, ctx.policy, ctx.budget)?
    else {
        return Ok(None);
    };
    ctx.bitmaps += 1;
    let cb_info = info.len();
    pad4(&mut info);
    let at_info = 8 + fixed;
    let at_bits = at_info + info.len();
    for (i, v) in [at_info, cb_info, at_bits, bits.len()]
        .into_iter()
        .enumerate()
    {
        body[offs + i * 4..offs + i * 4 + 4].copy_from_slice(&(v as u32).to_le_bytes());
    }
    body.extend(info);
    body.extend(bits);
    pad4(&mut body);
    Ok(Some(body))
}

/// ExtTextOutA/W: 문자열·글자 간격 배열을 정해진 위치에 다시 배치한다
fn text(b: &[u8], unit: usize) -> Option<Vec<u8>> {
    const NO_RECT: u32 = 0x100;
    const PDY: u32 = 0x2000;
    let rec_at = |off: u32| (off as usize).checked_sub(8);
    let chars = rd::u32(b, 36)? as usize;
    let off_string = rd::u32(b, 40)?;
    let options = rd::u32(b, 44)?;
    // ETO_NO_RECT 이면 사각형이 없어야 하지만, 많은 작성기가 사각형 자리를 그대로 둔다.
    // 문자열 위치가 사각형 뒤를 가리키면 사각형이 있는 배치로 본다.
    let has_rect = options & NO_RECT == 0 || off_string as usize >= 8 + 68;
    let fixed = if has_rect { 68 } else { 52 };
    let off_dx = rd::u32(b, fixed - 4)?;
    let string = rd::slice(b, rec_at(off_string)?, chars.checked_mul(unit)?)?;
    let dx_len = chars * 4 * if options & PDY != 0 { 2 } else { 1 };
    let dx = rec_at(off_dx).and_then(|at| rd::slice(b, at, dx_len));

    let mut v = b[..36].to_vec(); // Bounds, 그래픽 모드, 배율, 기준점
    v.extend((chars as u32).to_le_bytes());
    v.extend(((8 + fixed) as u32).to_le_bytes());
    v.extend(options.to_le_bytes());
    if has_rect {
        v.extend(&b[48..64]);
    }
    v.extend([0; 4]); // offDx (아래에서 채움)
    v.extend(string);
    pad4(&mut v);
    if let Some(dx) = dx {
        let at = (v.len() + 8) as u32;
        v[fixed - 4..fixed].copy_from_slice(&at.to_le_bytes());
        v.extend(dx);
    }
    Some(v)
}

/// GradientFill: 꼭짓점 + 사각형/삼각형 (색인이 꼭짓점 범위 안이어야 함)
fn gradient(b: &[u8]) -> Option<Vec<u8>> {
    let n_ver = rd::u32(b, 16)? as usize;
    let n_tri = rd::u32(b, 20)? as usize;
    let mode = rd::u32(b, 24)?;
    let per = match mode {
        0 | 1 => 8,
        2 => 12,
        _ => return None,
    };
    let at = 28usize.checked_add(n_ver.checked_mul(16)?)?;
    let objs = rd::slice(b, at, n_tri.checked_mul(per)?)?;
    if objs
        .as_chunks::<4>()
        .0
        .iter()
        .any(|c| u32::from_le_bytes(*c) as usize >= n_ver)
    {
        return None;
    }
    b.get(..at + objs.len()).map(<[u8]>::to_vec)
}
