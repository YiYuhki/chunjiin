//! WMF(Windows Metafile) 재조합 ([MS-WMF]).
//!
//! WMF 는 개체를 만들 때마다 개체 표의 비어 있는 가장 낮은 자리를 차지하고, 선택·삭제 레코드가
//! 그 자리 번호를 가리킨다. 개체 생성 레코드를 버리면 뒤의 번호가 모두 어긋나므로, 옮길 수 없는
//! 생성 레코드는 빈 브러시 생성 레코드로 바꿔 자리를 유지한다. 선택·삭제 레코드는 살아 있는
//! 개체를 가리킬 때만 옮긴다.
//!
//! 이스케이프에 나눠 담긴 EMF(META_ESCAPE_ENHANCED_METAFILE, Office·GDI 가 WMF 와 함께 넣는
//! 고품질 사본)는 모아서 EMF 재조합기로 다시 만든 뒤 같은 모양의 이스케이프로 나눠 쓴다.
//! 영역(CreateRegion)과 장치 종속 무늬 브러시(CreatePatternBrush)는 구조를 검증해 정규형으로 쓴다.

use super::dib::{self, Dib, DIB_RGB_COLORS};
use super::{rd, Stats};
use crate::error::{blocked, Result};
use crate::legacy::blip::PixelBudget;
use crate::policy::Policy;

const PLACEABLE_KEY: u32 = 0x9AC6_CDD7;
const META_EOF: u16 = 0x0000;

const CREATE_PEN: u16 = 0x02FA;
const CREATE_BRUSH: u16 = 0x02FC;
const CREATE_FONT: u16 = 0x02FB;
const CREATE_PALETTE: u16 = 0x00F7;
const CREATE_PATTERN_BRUSH: u16 = 0x01F9;
const DIB_CREATE_PATTERN_BRUSH: u16 = 0x0142;
const CREATE_REGION: u16 = 0x06FF;
const SELECT_OBJECT: u16 = 0x012D;
const DELETE_OBJECT: u16 = 0x01F0;
const SELECT_PALETTE: u16 = 0x0234;
const META_ESCAPE: u16 = 0x0626;
/// MFCOMMENT 이스케이프, "WMFC" 주석 식별자
const MFCOMMENT: u16 = 0x000F;
const WMFC: u32 = 0x4346_4D57;
/// 내장 EMF 를 나눠 담는 조각 크기 (GDI·LibreOffice 와 같은 8KB)
const EMF_CHUNK: usize = 0x2000;
/// 내장 EMF 크기 상한
const MAX_EMBEDDED_EMF: usize = 64 << 20;

/// 이스케이프 조각으로 모으는 내장 EMF
#[derive(Default)]
struct Embedded {
    /// 첫 조각이 있던 출력 위치
    at: Option<usize>,
    count: u32,
    total: usize,
    seen: u32,
    data: Vec<u8>,
    broken: bool,
}

impl Embedded {
    /// META_ESCAPE_ENHANCED_METAFILE 이면 조각을 모으고 true
    fn take(&mut self, params: &[u8], out_len: usize) -> bool {
        let (Some(esc), Some(id)) = (rd::u16(params, 0), rd::u32(params, 4)) else {
            return false;
        };
        if esc != MFCOMMENT || id != WMFC {
            return false;
        }
        let fields = (
            rd::u32(params, 8),
            rd::u32(params, 12),
            rd::u32(params, 22),
            rd::u32(params, 26),
            rd::u32(params, 34),
        );
        let (Some(1), Some(0x0001_0000), Some(count), Some(cur), Some(total)) = fields else {
            self.broken = true;
            return true;
        };
        let (cur, total) = (cur as usize, total as usize);
        let Some(chunk) = rd::slice(params, 38, cur) else {
            self.broken = true;
            return true;
        };
        if self.at.is_none() {
            self.at = Some(out_len);
            self.count = count;
            self.total = total;
            if total > MAX_EMBEDDED_EMF || count == 0 {
                self.broken = true;
            }
        } else if self.count != count || self.total != total {
            self.broken = true;
        }
        if !self.broken {
            self.seen += 1;
            self.data.extend_from_slice(chunk);
            if self.data.len() > self.total || self.seen > self.count {
                self.broken = true;
            }
        }
        true
    }

    fn complete(&self) -> bool {
        self.at.is_some()
            && !self.broken
            && self.seen == self.count
            && self.data.len() == self.total
    }
}

/// EMF 를 META_ESCAPE_ENHANCED_METAFILE 레코드들로 나눈다. 검사합은 EMF 의 16비트 워드 합이
/// 0 이 되게 하는 값을 첫 조각에 쓴다 (나머지 조각은 0)
fn embedded_records(emf: &[u8]) -> Vec<Vec<u8>> {
    let sum = emf
        .chunks(2)
        .map(|w| u16::from_le_bytes([w[0], *w.get(1).unwrap_or(&0)]))
        .fold(0u16, u16::wrapping_add);
    let count = emf.len().div_ceil(EMF_CHUNK) as u32;
    let mut remaining = emf.len();
    let mut out = Vec::new();
    for (i, chunk) in emf.chunks(EMF_CHUNK).enumerate() {
        remaining -= chunk.len();
        let mut v = Vec::with_capacity(chunk.len() + 44);
        v.extend(MFCOMMENT.to_le_bytes());
        v.extend(((34 + chunk.len()) as u16).to_le_bytes());
        v.extend(WMFC.to_le_bytes());
        v.extend(1u32.to_le_bytes());
        v.extend(0x0001_0000u32.to_le_bytes());
        v.extend((if i == 0 { sum.wrapping_neg() } else { 0 }).to_le_bytes());
        v.extend(0u32.to_le_bytes());
        v.extend(count.to_le_bytes());
        v.extend((chunk.len() as u32).to_le_bytes());
        v.extend((remaining as u32).to_le_bytes());
        v.extend((emf.len() as u32).to_le_bytes());
        v.extend(chunk);
        out.push(v);
    }
    out
}

/// 레코드 하나 (크기·함수·매개변수)
fn wmf_record(f: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(body.len() + 7);
    v.extend(((3 + body.len().div_ceil(2)) as u32).to_le_bytes());
    v.extend(f.to_le_bytes());
    v.extend(body);
    if body.len() % 2 == 1 {
        v.push(0);
    }
    v
}

pub fn is_wmf(d: &[u8]) -> bool {
    if rd::u32(d, 0) == Some(PLACEABLE_KEY) {
        return true;
    }
    meta_header(d, 0).is_some()
}

/// META_HEADER: 형식(1|2), 머리 크기(9 워드), 버전(0x100|0x300)
fn meta_header(d: &[u8], at: usize) -> Option<(u16, u16)> {
    let t = rd::u16(d, at)?;
    let size = rd::u16(d, at + 2)?;
    let version = rd::u16(d, at + 4)?;
    let objects = rd::u16(d, at + 10)?;
    (matches!(t, 1 | 2) && size == 9 && matches!(version, 0x0100 | 0x0300))
        .then_some((version, objects))
}

fn fail<T>(msg: &str) -> Result<T> {
    blocked("metafile", format!("WMF 구조 오류: {msg}"))
}

/// 매개변수 워드 수가 정해진 레코드: (최소, 최대)
fn fixed_words(f: u16) -> Option<(usize, usize)> {
    Some(match f {
        0x001E | 0x0035 => (0, 0), // SaveDC, RealizePalette
        0x0102 | 0x0104 | 0x0106 | 0x0107 | 0x012E => (1, 2), // 모드 (+예약)
        0x0103 | 0x0105 | 0x0108 | 0x0127 | 0x0139 => (1, 1),
        0x0149 => (1, 2), // SetLayout
        0x0201 | 0x0209 | 0x020A | 0x020B | 0x020C | 0x020D | 0x020E | 0x020F | 0x0211 | 0x0213
        | 0x0214 | 0x0220 | 0x0231 => (2, 2),
        0x0410 | 0x0412 | 0x0415 | 0x0416 | 0x0418 | 0x0419 | 0x041B | 0x041F => (4, 4),
        0x0548 => (5, 5),                   // ExtFloodFill
        0x061C | 0x061D => (6, 6),          // RoundRect, PatBlt
        0x0817 | 0x081A | 0x0830 => (8, 8), // Arc, Pie, Chord
        _ => return None,
    })
}

/// 검증해 옮기는 레코드 (생성 레코드 제외)
fn supported(f: u16) -> bool {
    fixed_words(f).is_some()
        || matches!(
            f,
            SELECT_OBJECT
                | SELECT_PALETTE
                | DELETE_OBJECT
                | 0x012A
                | 0x012B
                | 0x012C
                | 0x0228
                | 0x0429
                | 0x0037
                | 0x0436
                | 0x0324
                | 0x0325
                | 0x0538
                | 0x0521
                | 0x0A32
                | 0x0F43
                | 0x0B41
                | 0x0940
                | 0x0D33
                | 0x0922
                | 0x0B23
        )
}

/// WMF 개체 표. 비어 있는 가장 낮은 자리를 정렬된 집합으로 찾는다
/// (생성 레코드를 대량으로 넣어도 레코드마다 표 전체를 훑지 않도록).
struct Objects {
    live: Vec<bool>,
    free: std::collections::BTreeSet<usize>,
}

impl Objects {
    fn new(declared: u16) -> Self {
        Objects {
            live: vec![false; declared as usize],
            free: (0..declared as usize).collect(),
        }
    }

    /// 새 개체가 차지할 자리. 머리글의 개체 수보다 많이 만드는 파일도 흔해서(렌더러도 표를 늘림)
    /// 표를 늘리되 16비트 번호 범위를 넘지 않는다.
    fn create(&mut self) -> Option<usize> {
        let i = match self.free.pop_first() {
            Some(i) => i,
            None if self.live.len() < u16::MAX as usize => {
                self.live.push(false);
                self.live.len() - 1
            }
            None => return None,
        };
        self.live[i] = true;
        Some(i)
    }

    fn delete(&mut self, i: u16) {
        self.live[i as usize] = false;
        self.free.insert(i as usize);
    }

    fn is_live(&self, i: u16) -> bool {
        self.live.get(i as usize).copied().unwrap_or(false)
    }
}

pub fn rebuild(
    data: &[u8],
    policy: &Policy,
    budget: &mut PixelBudget,
    stats: &mut Stats,
) -> Result<Vec<u8>> {
    rebuild_nested(data, policy, budget, stats, 0)
}

/// `depth` 는 다른 메타파일 안에 들어 있는 깊이
pub(super) fn rebuild_nested(
    data: &[u8],
    policy: &Policy,
    budget: &mut PixelBudget,
    stats: &mut Stats,
    depth: usize,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len().min(1 << 24));
    let base = if rd::u32(data, 0) == Some(PLACEABLE_KEY) {
        let Some(ph) = rd::slice(data, 0, 22) else {
            return fail("배치 머리글");
        };
        let mut h = ph.to_vec();
        h[4..6].fill(0); // hWmf
        h[16..20].fill(0); // 예약
        let sum = h[..20]
            .as_chunks::<2>()
            .0
            .iter()
            .fold(0u16, |s, w| s ^ u16::from_le_bytes(*w));
        h[20..22].copy_from_slice(&sum.to_le_bytes());
        out.extend(h);
        22
    } else {
        0
    };
    let Some((version, objects)) = meta_header(data, base) else {
        return fail("머리글");
    };
    let head = out.len();
    out.extend(1u16.to_le_bytes()); // 메모리 메타파일
    out.extend(9u16.to_le_bytes());
    out.extend(version.to_le_bytes());
    out.extend([0; 4]); // 전체 크기(워드) — 나중에 채움
    out.extend(objects.to_le_bytes());
    out.extend([0; 4]); // 가장 큰 레코드(워드) — 나중에 채움
    out.extend([0; 2]);

    let mut table = Objects::new(objects);
    let mut max_record = 3usize;
    let mut bitmaps = 0u64;
    let mut embedded = Embedded::default();
    let mut p = base + 18;
    while let (Some(words), Some(f)) = (rd::u32(data, p), rd::u16(data, p + 4)) {
        let size = (words as usize).saturating_mul(2);
        if words < 3 || size > data.len() - p {
            stats.invalid += 1;
            break;
        }
        let params = &data[p + 6..p + size];
        p += size;
        if f == META_EOF {
            break;
        }
        stats.records += 1;
        if f == META_ESCAPE && embedded.take(params, out.len()) {
            continue;
        }
        let creates = matches!(
            f,
            CREATE_PEN
                | CREATE_BRUSH
                | CREATE_FONT
                | CREATE_PALETTE
                | CREATE_PATTERN_BRUSH
                | DIB_CREATE_PATTERN_BRUSH
                | CREATE_REGION
        );
        let rebuilt = if creates {
            if table.create().is_none() {
                stats.invalid += 1;
                continue;
            }
            match create(f, params, policy, budget, &mut bitmaps)? {
                Some(body) => Some((f, body)),
                None => {
                    // 자리를 유지하도록 빈 브러시(BS_NULL)로 바꾼다
                    stats.invalid += 1;
                    Some((CREATE_BRUSH, [1u16, 0, 0, 0].map(u16::to_le_bytes).concat()))
                }
            }
        } else {
            record(f, params, &mut table, policy, budget, &mut bitmaps)?.map(|b| (f, b))
        };
        let Some((f, mut body)) = rebuilt else {
            if supported(f) {
                stats.invalid += 1;
            } else {
                stats.removed += 1;
            }
            continue;
        };
        if body.len() % 2 == 1 {
            body.push(0);
        }
        let words = 3 + body.len() / 2;
        max_record = max_record.max(words);
        out.extend((words as u32).to_le_bytes());
        out.extend(f.to_le_bytes());
        out.extend(body);
    }
    // 내장 EMF: 다시 만들어 첫 조각이 있던 자리에 넣는다
    if let Some(at) = embedded.at {
        let rebuilt = if embedded.complete() && depth < super::MAX_NESTED {
            let mut s = Stats::default();
            match super::emf::rebuild_nested(&embedded.data, policy, budget, &mut s, depth + 1) {
                Ok(emf) => {
                    s.nested += 1;
                    stats.add(&s);
                    Some(emf)
                }
                Err(_) => None,
            }
        } else {
            None
        };
        match rebuilt {
            Some(emf) => {
                let recs: Vec<u8> = embedded_records(&emf)
                    .iter()
                    .map(|b| {
                        let r = wmf_record(META_ESCAPE, b);
                        max_record = max_record.max(r.len() / 2);
                        r
                    })
                    .collect::<Vec<_>>()
                    .concat();
                out.splice(at..at, recs);
            }
            None => stats.removed += embedded.seen.max(1) as u64,
        }
    }
    out.extend(3u32.to_le_bytes());
    out.extend(META_EOF.to_le_bytes());

    let Ok(total) = u32::try_from((out.len() - head) / 2) else {
        return fail("크기");
    };
    out[head + 6..head + 10].copy_from_slice(&total.to_le_bytes());
    out[head + 12..head + 16].copy_from_slice(&(max_record as u32).to_le_bytes());
    stats.bitmaps += bitmaps;
    Ok(out)
}

/// 개체 생성 레코드를 검증해 정규형으로 만든다. 옮길 수 없으면 None (호출 측이 빈 브러시로 대체)
fn create(
    f: u16,
    b: &[u8],
    policy: &Policy,
    budget: &mut PixelBudget,
    bitmaps: &mut u64,
) -> Result<Option<Vec<u8>>> {
    Ok(match f {
        CREATE_PEN => b.get(..10).map(<[u8]>::to_vec),
        CREATE_BRUSH => b.get(..8).map(|v| {
            let mut v = v.to_vec();
            if !matches!(rd::u16(&v, 0), Some(0..=2)) {
                v[0..2].fill(0);
            }
            v
        }),
        CREATE_FONT => {
            // LogFont 18바이트 + 글꼴 이름(최대 32바이트, NUL 로 끝나게)
            b.get(..18).map(|head| {
                let name = &b[18..b.len().min(18 + 32)];
                let end = name
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(name.len())
                    .min(31);
                let mut v = head.to_vec();
                v.extend(&name[..end]);
                v.resize(18 + 32, 0);
                v
            })
        }
        CREATE_PALETTE => {
            let n = rd::u16(b, 2).unwrap_or(0) as usize;
            (rd::u16(b, 0) == Some(0x0300) && (1..=1024).contains(&n))
                .then(|| b.get(..4 + n * 4).map(<[u8]>::to_vec))
                .flatten()
        }
        DIB_CREATE_PATTERN_BRUSH => {
            let (Some(style), Some(usage)) = (rd::u16(b, 0), rd::u16(b, 2)) else {
                return Ok(None);
            };
            let usage = if style == 3 {
                DIB_RGB_COLORS
            } else {
                usage as u32
            };
            match dib::canonical_packed(&b[4..], usage, None, policy, budget)? {
                Some(d) => {
                    *bitmaps += 1;
                    let mut v = [style.to_le_bytes(), (usage as u16).to_le_bytes()].concat();
                    v.extend(dib::packed(&d));
                    Some(v)
                }
                None => None,
            }
        }
        CREATE_PATTERN_BRUSH => pattern_brush(b, budget)?,
        CREATE_REGION => region(b),
        _ => None,
    })
}

/// CreatePatternBrush: Bitmap16(14바이트, 비트 포인터 무시) + 예약 18바이트 + 무늬 비트
fn pattern_brush(b: &[u8], budget: &mut PixelBudget) -> Result<Option<Vec<u8>>> {
    let (Some(width), Some(height), Some(stride)) = (rd::u16(b, 2), rd::u16(b, 4), rd::u16(b, 6))
    else {
        return Ok(None);
    };
    let (width, height) = (width as i16, height as i16);
    let (planes, bpp) = (b.get(8).copied(), b.get(9).copied());
    if width <= 0
        || height <= 0
        || planes != Some(1)
        || !matches!(bpp, Some(1 | 4 | 8 | 16 | 24 | 32))
    {
        return Ok(None);
    }
    let bpp = bpp.unwrap_or(1) as usize;
    let min_stride = (width as usize * bpp).div_ceil(16) * 2;
    if (stride as usize) < min_stride || stride % 2 != 0 {
        return Ok(None);
    }
    let Some(bits) = rd::slice(b, 32, stride as usize * height as usize) else {
        return Ok(None);
    };
    budget.charge_pixels(width as u64 * height as u64)?;
    let mut v = vec![0u8; 32];
    v[2..10].copy_from_slice(&b[2..10]);
    v.extend(bits);
    Ok(Some(v))
}

/// CreateRegion: 머리글(22바이트) + 스캔(개수, 위, 아래, (왼쪽, 오른쪽)…, 개수)
fn region(b: &[u8]) -> Option<Vec<u8>> {
    const MAX_SCANS: usize = 16_384;
    if rd::u16(b, 2)? != 6 {
        return None;
    }
    let scans = rd::u16(b, 10)? as usize;
    if scans > MAX_SCANS {
        return None;
    }
    let bounds = rd::slice(b, 14, 8)?;
    let mut body: Vec<u8> = Vec::new();
    let mut max_scan = 0u16;
    let mut p = 22;
    for _ in 0..scans {
        let count = rd::u16(b, p)?;
        let (top, bottom) = (rd::u16(b, p + 2)? as i16, rd::u16(b, p + 4)? as i16);
        if count % 2 != 0 || top > bottom {
            return None;
        }
        let lines = rd::slice(b, p + 6, count as usize * 2)?;
        if rd::u16(b, p + 6 + count as usize * 2)? != count {
            return None;
        }
        for pair in lines.as_chunks::<4>().0 {
            let l = i16::from_le_bytes([pair[0], pair[1]]);
            let r = i16::from_le_bytes([pair[2], pair[3]]);
            if l > r {
                return None;
            }
        }
        max_scan = max_scan.max(count / 2);
        body.extend(&b[p..p + 6 + count as usize * 2 + 2]);
        p += 6 + count as usize * 2 + 2;
    }
    let size = u16::try_from(22 + body.len()).ok()?;
    let mut v = Vec::with_capacity(22 + body.len());
    v.extend(0u16.to_le_bytes()); // nextInChain
    v.extend(6u16.to_le_bytes()); // 형식: 영역
    v.extend(0u32.to_le_bytes()); // ObjectCount
    v.extend(size.to_le_bytes());
    v.extend((scans as u16).to_le_bytes());
    v.extend(max_scan.to_le_bytes());
    v.extend(bounds);
    v.extend(body);
    Some(v)
}

fn record(
    f: u16,
    b: &[u8],
    table: &mut Objects,
    policy: &Policy,
    budget: &mut PixelBudget,
    bitmaps: &mut u64,
) -> Result<Option<Vec<u8>>> {
    let w = |i: usize| rd::u16(b, i * 2);
    let live = |i: usize, t: &Objects| w(i).is_some_and(|x| t.is_live(x));
    if let Some((min, max)) = fixed_words(f) {
        let n = b.len() / 2;
        return Ok((n >= min).then(|| b[..n.min(max) * 2].to_vec()));
    }
    Ok(match f {
        SELECT_OBJECT | SELECT_PALETTE | 0x012A | 0x012B | 0x012C => {
            live(0, table).then(|| b[..2].to_vec())
        }
        DELETE_OBJECT => {
            if live(0, table) {
                table.delete(w(0).unwrap());
                Some(b[..2].to_vec())
            } else {
                None
            }
        }
        0x0228 => (live(0, table) && live(1, table)).then(|| b[..4].to_vec()), // FillRegion
        0x0429 => (live(0, table) && live(1, table))
            .then(|| b.get(..8).map(<[u8]>::to_vec))
            .flatten(), // FrameRegion
        0x0037 | 0x0436 => {
            // SetPalEntries, AnimatePalette: 시작, 개수, 항목
            let n = w(1).unwrap_or(u16::MAX) as usize;
            (n <= 1024)
                .then(|| b.get(..4 + n * 4).map(<[u8]>::to_vec))
                .flatten()
        }
        0x0324 | 0x0325 => {
            // Polygon, Polyline
            let n = w(0).unwrap_or(0) as usize;
            b.get(..2 + n * 4).map(<[u8]>::to_vec)
        }
        0x0538 => {
            // PolyPolygon: 도형 수, 도형별 점 수, 점
            let polys = w(0).unwrap_or(0) as usize;
            let Some(counts) = rd::slice(b, 2, polys * 2) else {
                return Ok(None);
            };
            let points: usize = counts
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c) as usize)
                .sum();
            b.get(..2 + polys * 2 + points * 4).map(<[u8]>::to_vec)
        }
        0x0521 => {
            // TextOut: 길이, 문자열(짝수 채움), y, x
            let n = w(0).unwrap_or(0) as usize;
            let padded = n + n % 2;
            b.get(..2 + padded + 4).map(<[u8]>::to_vec)
        }
        0x0A32 => ext_text(b),
        0x0F43 => bitmap(
            b,
            22,
            w(2).unwrap_or(0) as u32,
            None,
            policy,
            budget,
            bitmaps,
        )?, // StretchDIB
        0x0B41 if b.len() == 22 => Some(b.to_vec()), // DIBStretchBlt (비트맵 없음)
        0x0B41 => bitmap(b, 20, DIB_RGB_COLORS, None, policy, budget, bitmaps)?,
        0x0940 if b.len() == 18 => Some(b.to_vec()), // DIBBitBlt (비트맵 없음)
        0x0940 => bitmap(b, 16, DIB_RGB_COLORS, None, policy, budget, bitmaps)?,
        0x0D33 => {
            // SetDIBitsToDevice: 색상표 형식, 줄 수, ...
            let rows = w(1).map(u32::from);
            bitmap(
                b,
                18,
                w(0).unwrap_or(0) as u32,
                rows,
                policy,
                budget,
                bitmaps,
            )?
        }
        0x0922 if b.len() == 18 => Some(b.to_vec()), // BitBlt (비트맵 없음)
        0x0922 => bitmap16(b, 16),
        0x0B23 if b.len() == 22 => Some(b.to_vec()), // StretchBlt (비트맵 없음)
        0x0B23 => bitmap16(b, 20),
        // Escape 등은 옮기지 않는다
        _ => None,
    })
}

/// ExtTextOut: y, x, 길이, 옵션, [사각형], 문자열(짝수 채움), [글자 간격]
fn ext_text(b: &[u8]) -> Option<Vec<u8>> {
    let n = rd::u16(b, 4)? as usize;
    let opts = rd::u16(b, 6)?;
    let rect = if opts & 0x6 != 0 { 8 } else { 0 };
    let at = 8 + rect;
    let padded = n + n % 2;
    let mut v = b.get(..at + padded)?.to_vec();
    // 글자 간격: ETO_PDY 면 (x, y) 쌍
    let pairs = if opts & 0x2000 != 0 { 2 } else { 1 };
    if let Some(dx) = rd::slice(b, at + padded, n * 2 * pairs).or(rd::slice(b, at + padded, n * 2))
    {
        v.extend(dx);
    }
    Some(v)
}

/// 장치 종속 비트맵(Bitmap16)을 담는 레코드: 고정 매개변수 + 형식, 너비, 높이, 줄 바이트 수,
/// 평면 수, 화소 비트 수 + 화소
fn bitmap16(b: &[u8], fixed: usize) -> Option<Vec<u8>> {
    let h = rd::slice(b, fixed, 10)?;
    let (width, height, stride) = (rd::u16(h, 2)?, rd::u16(h, 4)?, rd::u16(h, 6)?);
    let (planes, bpp) = (h[8], h[9]);
    let (width, height) = (width as i16, height as i16);
    if width <= 0 || height <= 0 || planes != 1 || ![1, 4, 8, 16, 24, 32].contains(&bpp) {
        return None;
    }
    let min_stride = (width as usize * bpp as usize).div_ceil(16) * 2;
    if (stride as usize) < min_stride || stride % 2 != 0 {
        return None;
    }
    let bits = rd::slice(b, fixed + 10, stride as usize * height as usize)?;
    let mut v = b[..fixed].to_vec();
    v.extend([0, 0]); // 형식
    v.extend(&h[2..10]);
    v.extend(bits);
    Some(v)
}

/// DIB 를 담는 레코드: 고정 매개변수(`fixed` 바이트) + DIB
fn bitmap(
    b: &[u8],
    fixed: usize,
    usage: u32,
    rows: Option<u32>,
    policy: &Policy,
    budget: &mut PixelBudget,
    bitmaps: &mut u64,
) -> Result<Option<Vec<u8>>> {
    let Some(head) = b.get(..fixed) else {
        return Ok(None);
    };
    let Some(Dib { info, bits }) = dib::canonical_packed(&b[fixed..], usage, rows, policy, budget)?
    else {
        return Ok(None);
    };
    *bitmaps += 1;
    let mut v = head.to_vec();
    v.extend(info);
    v.extend(bits);
    Ok(Some(v))
}
