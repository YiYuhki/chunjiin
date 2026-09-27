//! 콘텐츠 스트림의 인라인 이미지(`BI … ID … EI`) 정규화.
//!
//! lopdf 는 필터가 걸린 인라인 이미지와 리소스 이름·Indexed 색 공간을 해석하지 못하고,
//! `ID` 뒤의 공백을 모두 건너뛰어 공백 값으로 시작하는 표본 데이터를 어긋나게 읽는다.
//! 콘텐츠를 해석하기 전에 인라인 이미지를 직접 찾아 필터를 풀고, 장치 색 공간의 필터 없는
//! 표본으로 바꾼 이미지 스트림을 만든 뒤 자리에 자리표시 연산자(`n CdrInlineImage`)를 둔다.
//! 해석 후 [`restore`] 가 자리표시를 `BI` 연산으로 되돌린다.
//! - 풀 수 있는 필터: ASCIIHex, ASCII85, LZW, Flate, RunLength, DCT(JPEG 는 화소로 디코딩),
//!   CCITT 팩스(G4·G3 1차원, 1비트 표본으로 디코딩)
//! - JBIG2·JPX·Crypt, CCITT G3 2차원과 변환할 수 없는 색 공간(Separation·DeviceN·Lab·Pattern)은 뺀다
//! - Indexed 색 공간은 기준 색 공간의 8비트 표본으로 펼친다

use lopdf::content::{Content, Operation};
use lopdf::{Dictionary, Object, Stream};

use crate::imaging::{self, ImageKind};
use crate::policy::Policy;

pub const PLACEHOLDER: &str = "CdrInlineImage";

/// 인라인 이미지 하나의 최대 표본 크기
const MAX_IMAGE_BYTES: usize = 32 << 20;
/// 사전 부분의 최대 길이
const MAX_DICT_BYTES: usize = 64 << 10;
/// 필터가 걸린 데이터의 끝(`EI`)을 찾을 때 시도하는 후보 수
const MAX_EI_CANDIDATES: usize = 64;
/// 앞에 공백이 없는(규격 밖) `EI` 후보 수
const MAX_LOOSE_CANDIDATES: usize = 8;
/// 이미지 하나에서 후보마다 필터를 풀어 보는 입력 총량
const MAX_ATTEMPT_BYTES: usize = 64 << 20;
/// 스트림 하나에서 필터를 풀어 보는 횟수
const MAX_STREAM_ATTEMPTS: usize = 20_000;

/// 해석된 색 공간
pub enum Cs {
    /// 장치 색 공간 (성분 수 1·3·4)
    Device(u8),
    Indexed {
        base: u8,
        hival: usize,
        lookup: Vec<u8>,
    },
}

#[derive(Default)]
pub struct Outcome {
    pub images: Vec<Stream>,
    pub normalized: u64,
    /// 뺀 이미지 (사유별)
    pub dropped: Vec<&'static str>,
}

fn is_ws(b: u8) -> bool {
    matches!(b, 0 | 9 | 10 | 12 | 13 | 32)
}

fn is_delim(b: u8) -> bool {
    b"()<>[]{}/%".contains(&b)
}

/// 토큰 하나를 건너뛴다. 정규 토큰이면 그 범위를 돌려준다.
/// 건너뛴 공백 중 NUL·폼피드(lopdf 가 공백으로 보지 않는 것)의 위치를 `odd_ws` 에 모은다
fn next_token(d: &[u8], i: &mut usize, odd_ws: &mut Vec<usize>) -> Option<(usize, usize)> {
    while *i < d.len() && is_ws(d[*i]) {
        if matches!(d[*i], 0 | 12) {
            odd_ws.push(*i);
        }
        *i += 1;
    }
    let r = next_token_raw(d, i);
    // 닫히지 않은 문자열·끝의 역슬래시 등으로 끝을 넘어가지 않도록
    *i = (*i).min(d.len());
    r.map(|(s, e)| (s.min(d.len()), e.min(d.len())))
}

fn next_token_raw(d: &[u8], i: &mut usize) -> Option<(usize, usize)> {
    while *i < d.len() && is_ws(d[*i]) {
        *i += 1;
    }
    if *i >= d.len() {
        return None;
    }
    match d[*i] {
        b'%' => {
            while *i < d.len() && d[*i] != b'\n' && d[*i] != b'\r' {
                *i += 1;
            }
        }
        b'(' => {
            let mut depth = 0usize;
            while *i < d.len() {
                match d[*i] {
                    b'\\' => *i += 1,
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            *i += 1;
                            break;
                        }
                    }
                    _ => {}
                }
                *i += 1;
            }
        }
        b'<' if d.get(*i + 1) == Some(&b'<') => *i += 2,
        b'<' => {
            while *i < d.len() && d[*i] != b'>' {
                *i += 1;
            }
            *i += 1;
        }
        b'>' if d.get(*i + 1) == Some(&b'>') => *i += 2,
        b'/' => {
            *i += 1;
            while *i < d.len() && !is_ws(d[*i]) && !is_delim(d[*i]) {
                *i += 1;
            }
        }
        c if is_delim(c) => *i += 1,
        _ => {
            let s = *i;
            while *i < d.len() && !is_ws(d[*i]) && !is_delim(d[*i]) {
                *i += 1;
            }
            return Some((s, *i));
        }
    }
    Some((*i, *i))
}

/// 콘텐츠의 인라인 이미지를 정규화하고, 토큰 사이의 NUL·폼피드를 공백으로 바꾼다.
/// 바꿀 것이 없으면 None.
pub fn normalize(
    data: &[u8],
    resolve: &mut dyn FnMut(&Object) -> Option<Cs>,
    policy: &Policy,
    budget: &mut usize,
) -> Option<(Vec<u8>, Outcome)> {
    if crate::detect::find(data, b"BI").is_none() && !data.iter().any(|&c| matches!(c, 0 | 12)) {
        return None;
    }
    let mut out = Vec::with_capacity(data.len());
    let mut odd_ws: Vec<usize> = Vec::new();
    let mut patched = 0usize;
    // data[from..to] 를 옮기면서 토큰 사이의 NUL·폼피드를 공백으로
    let copy =
        |out: &mut Vec<u8>, from: usize, to: usize, odd_ws: &[usize], patched: &mut usize| {
            let base = out.len();
            out.extend_from_slice(&data[from..to]);
            while *patched < odd_ws.len() && odd_ws[*patched] < to {
                if odd_ws[*patched] >= from {
                    out[base + odd_ws[*patched] - from] = b' ';
                }
                *patched += 1;
            }
        };
    let mut res = Outcome::default();
    let mut copied = 0usize;
    let mut i = 0usize;
    let mut found = false;
    let mut eis: Option<Eis> = None;
    while let Some((s, e)) = next_token(data, &mut i, &mut odd_ws) {
        if &data[s..e] != b"BI" {
            continue;
        }
        found = true;
        let eis = eis.get_or_insert_with(|| Eis::new(data));
        copy(&mut out, copied, s, &odd_ws, &mut patched);
        // 사전: `ID` 토큰까지
        let dict_start = e;
        let mut j = e;
        let mut id_end = None;
        let mut dict_ws = Vec::new();
        while let Some((ts, te)) = next_token(data, &mut j, &mut dict_ws) {
            if j - dict_start > MAX_DICT_BYTES {
                break;
            }
            if ts < te && &data[ts..te] == b"ID" {
                id_end = Some((ts, te));
                break;
            }
            if ts < te && (&data[ts..te] == b"EI" || &data[ts..te] == b"BI") {
                break;
            }
        }
        let Some((id_start, id_end)) = id_end else {
            // 형식이 깨진 인라인 이미지: 나머지 콘텐츠를 버린다
            res.dropped.push("형식 오류");
            copied = data.len();
            break;
        };
        let data_start = (id_end + 1).min(data.len());
        let dict = parse_dict(&data[dict_start..id_start]);
        let (image, after) = match dict {
            Some(dict) => image(data, eis, data_start, &dict, resolve, policy, budget),
            None => (Err("사전 해석 실패"), None),
        };
        let after = after.or_else(|| ei_candidates(eis, data_start).next());
        match image {
            Ok(stream) => {
                out.extend_from_slice(format!(" {} {PLACEHOLDER} ", res.images.len()).as_bytes());
                res.images.push(stream);
                res.normalized += 1;
            }
            Err(reason) => res.dropped.push(reason),
        }
        match after {
            Some(p) => {
                copied = p + 2;
                i = copied;
            }
            None => {
                res.dropped.push("EI 없음");
                copied = data.len();
                break;
            }
        }
    }
    if !found && odd_ws.is_empty() {
        return None;
    }
    copy(&mut out, copied, data.len(), &odd_ws, &mut patched);
    Some((out, res))
}

/// 해석된 연산에서 자리표시를 인라인 이미지 연산으로 되돌린다
pub fn restore(ops: &mut Vec<Operation>, images: &mut [Option<Stream>]) {
    ops.retain_mut(|op| {
        if op.operator != PLACEHOLDER {
            return true;
        }
        let idx = match op.operands.as_slice() {
            [Object::Integer(n)] => usize::try_from(*n).ok(),
            _ => None,
        };
        match idx.and_then(|n| images.get_mut(n)).and_then(Option::take) {
            Some(s) => {
                *op = Operation::new("BI", vec![Object::Stream(s)]);
                true
            }
            None => false,
        }
    });
}

fn parse_dict(bytes: &[u8]) -> Option<Dictionary> {
    let mut src = Vec::with_capacity(bytes.len() + 8);
    src.extend_from_slice(b"<<");
    src.extend_from_slice(bytes);
    src.extend_from_slice(b">> x");
    let content = Content::decode(&src).ok()?;
    match content.operations.as_slice() {
        [op] if op.operator == "x" => match op.operands.as_slice() {
            [Object::Dictionary(d)] => Some(d.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// 스트림의 `EI` 후보 위치 (뒤는 공백·구분자·끝). 스트림마다 한 번만 찾는다
/// (이미지마다 끝까지 다시 찾으면 조작된 스트림에서 시간이 제곱으로 는다)
struct Eis {
    /// 앞이 공백인 것 (규격대로)
    strict: Vec<usize>,
    /// 앞에 공백이 없는 것 (표본 바로 뒤에 붙여 쓴 파일)
    loose: Vec<usize>,
    /// 남은 필터 해제 시도 횟수 (스트림 단위)
    attempts: std::cell::Cell<usize>,
}

impl Eis {
    fn new(data: &[u8]) -> Self {
        let (mut strict, mut loose) = (Vec::new(), Vec::new());
        for p in 1..data.len().saturating_sub(1) {
            if data[p] == b'E'
                && data[p + 1] == b'I'
                && data.get(p + 2).is_none_or(|&c| is_ws(c) || is_delim(c))
            {
                if is_ws(data[p - 1]) {
                    strict.push(p);
                } else {
                    loose.push(p);
                }
            }
        }
        Eis {
            strict,
            loose,
            attempts: std::cell::Cell::new(MAX_STREAM_ATTEMPTS),
        }
    }
}

/// `from` 이후의 `EI` 후보: 규격대로인 것을 먼저, 그다음 붙여 쓴 것
fn ei_candidates(eis: &Eis, from: usize) -> impl Iterator<Item = usize> + '_ {
    fn after(v: &[usize], from: usize, n: usize) -> impl Iterator<Item = usize> + '_ {
        let i = v.partition_point(|&p| p < from);
        v[i..].iter().copied().take(n)
    }
    after(&eis.strict, from, MAX_EI_CANDIDATES).chain(after(&eis.loose, from, MAX_LOOSE_CANDIDATES))
}

/// 필터 없는 표본 바로 뒤의 `EI` (공백을 건너뛰고)
fn ei_after(data: &[u8], end: usize) -> Option<usize> {
    let mut p = end;
    while p < data.len() && is_ws(data[p]) {
        p += 1;
    }
    (data.get(p..p + 2) == Some(b"EI") && data.get(p + 2).is_none_or(|&c| is_ws(c) || is_delim(c)))
        .then_some(p)
}

fn get<'d>(d: &'d Dictionary, abbr: &[u8], full: &[u8]) -> Option<&'d Object> {
    d.get(abbr).or_else(|_| d.get(full)).ok()
}

fn filter_name(n: &[u8]) -> Option<&'static [u8]> {
    Some(match n {
        b"AHx" | b"ASCIIHexDecode" => b"ASCIIHexDecode",
        b"A85" | b"ASCII85Decode" => b"ASCII85Decode",
        b"LZW" | b"LZWDecode" => b"LZWDecode",
        b"Fl" | b"FlateDecode" => b"FlateDecode",
        b"RL" | b"RunLengthDecode" => b"RunLengthDecode",
        b"DCT" | b"DCTDecode" => b"DCTDecode",
        b"CCF" | b"CCITTFaxDecode" => b"CCITTFaxDecode",
        _ => return None,
    })
}

type Found = (Result<Stream, &'static str>, Option<usize>);

/// 인라인 이미지 하나를 해석한다. 반환: (정규화한 이미지, 끝 `EI` 위치)
fn image(
    data: &[u8],
    eis: &Eis,
    start: usize,
    d: &Dictionary,
    resolve: &mut dyn FnMut(&Object) -> Option<Cs>,
    policy: &Policy,
    budget: &mut usize,
) -> Found {
    let num = |o: Option<&Object>| o.and_then(|o| o.as_i64().ok());
    let (Some(w), Some(h)) = (num(get(d, b"W", b"Width")), num(get(d, b"H", b"Height"))) else {
        return (Err("크기 없음"), None);
    };
    if w <= 0 || h <= 0 || (w as u64).saturating_mul(h as u64) > policy.max_image_pixels {
        return (Err("크기 오류·초과"), None);
    }
    let (w, h) = (w as usize, h as usize);
    let mask = matches!(get(d, b"IM", b"ImageMask"), Some(Object::Boolean(true)));
    let bpc = if mask {
        1
    } else {
        num(get(d, b"BPC", b"BitsPerComponent")).unwrap_or(8)
    };
    if !matches!(bpc, 1 | 2 | 4 | 8 | 16) {
        return (Err("비트 수 오류"), None);
    }
    let bpc = bpc as usize;
    let cs = if mask {
        None
    } else {
        match get(d, b"CS", b"ColorSpace").and_then(&mut *resolve) {
            Some(cs) => Some(cs),
            None => return (Err("지원하지 않는 색 공간"), None),
        }
    };
    let ncomp = match &cs {
        None | Some(Cs::Indexed { .. }) => 1,
        Some(Cs::Device(n)) => usize::from(*n),
    };
    if matches!(cs, Some(Cs::Indexed { .. })) && bpc > 8 {
        return (Err("비트 수 오류"), None);
    }
    let Some(stride) = w.checked_mul(ncomp * bpc).map(|b| b.div_ceil(8)) else {
        return (Err("크기 오류·초과"), None);
    };
    let needed = stride.saturating_mul(h);
    if needed > MAX_IMAGE_BYTES || needed > *budget {
        return (Err("크기 오류·초과"), None);
    }

    // 필터
    let filters: Vec<&[u8]> = match get(d, b"F", b"Filter") {
        None => Vec::new(),
        Some(Object::Name(n)) => vec![n.as_slice()],
        Some(Object::Array(a)) => a.iter().filter_map(|o| o.as_name().ok()).collect(),
        Some(_) => return (Err("필터 오류"), None),
    };
    let Some(filters) = filters
        .iter()
        .map(|f| filter_name(f))
        .collect::<Option<Vec<_>>>()
    else {
        return (Err("지원하지 않는 필터(JBIG2·JPX 등)"), None);
    };
    let codec = |f: &&[u8]| *f == b"DCTDecode" || *f == b"CCITTFaxDecode";
    let dct = filters.last() == Some(&b"DCTDecode".as_slice());
    let fax = filters.last() == Some(&b"CCITTFaxDecode".as_slice());
    if filters.iter().rev().skip(1).any(codec) {
        return (Err("필터 오류"), None);
    }
    if fax && (bpc != 1 || ncomp != 1) {
        return (Err("필터 오류"), None);
    }
    let pre: Vec<&[u8]> = if dct || fax {
        filters[..filters.len() - 1].to_vec()
    } else {
        filters.clone()
    };
    let parms = get(d, b"DP", b"DecodeParms").cloned();

    let decode_pre = |raw: &[u8]| -> Option<Vec<u8>> {
        if pre.is_empty() {
            return Some(raw.to_vec());
        }
        let mut sd = Dictionary::new();
        sd.set(
            "Filter",
            Object::Array(pre.iter().map(|f| Object::Name(f.to_vec())).collect()),
        );
        if let Some(p) = &parms {
            // 마지막 필터(DCT·CCITT)의 매개변수는 빼고 앞 필터 것만
            let p = match p {
                Object::Array(a) => Object::Array(a[..pre.len().min(a.len())].to_vec()),
                o if pre.len() == filters.len() => Object::Array(vec![o.clone()]),
                _ => Object::Null,
            };
            sd.set("DecodeParms", p);
        }
        plain_content(
            &Stream::new(sd, raw.to_vec()),
            MAX_IMAGE_BYTES.min(policy.max_stream_size),
        )
        .ok()
    };

    // 표본과 끝 위치
    let (samples, out_ncomp, out_bpc, end) = if filters.is_empty() {
        // `ID` 뒤를 CRLF 로 쓴 파일: 표본 뒤에 바로 EI 가 오는 쪽을 고른다
        let start = if data.get(start - 1..start + 1) == Some(b"\r\n")
            && ei_after(data, start + needed).is_none()
            && ei_after(data, start + 1 + needed).is_some()
        {
            start + 1
        } else {
            start
        };
        let Some(raw) = data.get(start..start + needed) else {
            return (Err("데이터 부족"), None);
        };
        let end =
            ei_after(data, start + needed).or_else(|| ei_candidates(eis, start + needed).next());
        (raw.to_vec(), ncomp, bpc, end)
    } else {
        let fax_parms = if fax {
            match ccitt_params(parms.as_ref(), filters.len(), w) {
                Some(p) => Some(p),
                None => return (Err("지원하지 않는 CCITT 매개변수"), None),
            }
        } else {
            None
        };
        // CCITT 는 데이터가 모자라도 흰 줄로 채워 성공할 수 있으므로, 줄이 다 찬 후보를 먼저 쓴다
        let mut partial: Option<(Vec<u8>, usize, usize)> = None;
        let mut found = None;
        // `ID` 뒤를 CRLF 로 쓴 파일은 한 바이트 뒤에서도 시도한다
        let starts: &[usize] = if data.get(start).is_some_and(|&c| is_ws(c)) {
            &[start, start + 1]
        } else {
            &[start]
        };
        // 후보마다 필터를 풀어 보는 총량 상한 (끝이 맞지 않는 데이터로 CPU 를 소모시키는 입력 방어)
        let mut attempted = 0usize;
        for (p, start) in
            ei_candidates(eis, start).flat_map(|p| starts.iter().map(move |&s| (p, s)))
        {
            if p <= start {
                continue;
            }
            let raw = &data[start..p - 1];
            attempted += raw.len();
            if attempted > MAX_ATTEMPT_BYTES || eis.attempts.get() == 0 {
                break;
            }
            eis.attempts.set(eis.attempts.get() - 1);
            let Some(plain) = decode_pre(raw) else {
                continue;
            };
            if dct {
                let Ok(img) = imaging::decode(&plain, ImageKind::Jpeg, policy) else {
                    continue;
                };
                if img.width() as usize != w || img.height() as usize != h {
                    continue;
                }
                let (bytes, n) = if img.color().channel_count() == 1 {
                    (img.to_luma8().into_raw(), 1)
                } else {
                    (img.to_rgb8().into_raw(), 3)
                };
                found = Some((bytes, n, 8, p));
                break;
            }
            if let Some(fp) = &fax_parms {
                let Some((bits, lines)) = ccitt_decode(&plain, fp, w, h) else {
                    continue;
                };
                if lines >= h {
                    found = Some((bits, 1, 1, p));
                    break;
                }
                if partial.as_ref().is_none_or(|(_, l, _)| lines > *l) {
                    partial = Some((bits, lines, p));
                }
                continue;
            }
            if plain.len() >= needed {
                found = Some((plain[..needed].to_vec(), ncomp, bpc, p));
                break;
            }
        }
        if found.is_none() {
            found = partial.map(|(bits, _, p)| (bits, 1, 1, p));
        }
        match found {
            Some((s, n, b, p)) => (s, n, b, Some(p)),
            None => return (Err("데이터 해석 실패"), None),
        }
    };

    // 색 공간 정규화
    let mut dict = Dictionary::new();
    dict.set("W", Object::Integer(w as i64));
    dict.set("H", Object::Integer(h as i64));
    let decode = match get(d, b"D", b"Decode") {
        Some(Object::Array(a)) if a.iter().all(|o| o.as_float().is_ok()) => Some(a.clone()),
        _ => None,
    };
    let samples = match (&cs, dct) {
        (None, _) => {
            dict.set("IM", Object::Boolean(true));
            dict.set("BPC", Object::Integer(1));
            if let Some(a) = decode.filter(|a| a.len() == 2) {
                dict.set("D", Object::Array(a));
            }
            samples
        }
        (Some(Cs::Indexed { .. }), true) => return (Err("지원하지 않는 색 공간"), end),
        (
            Some(Cs::Indexed {
                base,
                hival,
                lookup,
            }),
            false,
        ) => {
            if decode.is_some() {
                return (Err("지원하지 않는 색 공간"), end);
            }
            let base = usize::from(*base);
            let mut out = Vec::with_capacity(w * h * base);
            for row in samples.chunks(stride).take(h) {
                for x in 0..w {
                    let bit = x * bpc;
                    let byte = row.get(bit / 8).copied().unwrap_or(0);
                    let idx = if bpc == 8 {
                        usize::from(byte)
                    } else {
                        usize::from((byte >> (8 - bpc - bit % 8)) & ((1u8 << bpc) - 1))
                    };
                    let at = idx.min(*hival) * base;
                    for k in 0..base {
                        out.push(lookup.get(at + k).copied().unwrap_or(0));
                    }
                }
            }
            dict.set("CS", device_name(base as u8));
            dict.set("BPC", Object::Integer(8));
            out
        }
        (Some(Cs::Device(_)), _) => {
            dict.set("CS", device_name(out_ncomp as u8));
            dict.set("BPC", Object::Integer(out_bpc as i64));
            if let Some(a) = decode.filter(|a| a.len() == 2 * out_ncomp && !dct) {
                dict.set("D", Object::Array(a));
            }
            samples
        }
    };
    if matches!(get(d, b"I", b"Interpolate"), Some(Object::Boolean(true))) {
        dict.set("I", Object::Boolean(true));
    }
    if samples.len() > *budget {
        return (Err("크기 오류·초과"), end);
    }
    *budget -= samples.len();
    (Ok(Stream::new(dict, samples)), end)
}

/// CCITT 매개변수 (K, BlackIs1)
struct Ccitt {
    k: i64,
    black_is_1: bool,
}

fn ccitt_params(parms: Option<&Object>, nfilters: usize, w: usize) -> Option<Ccitt> {
    let d = match parms {
        None | Some(Object::Null) => None,
        Some(Object::Dictionary(d)) => Some(d),
        Some(Object::Array(a)) => match a.get(nfilters - 1) {
            Some(Object::Dictionary(d)) => Some(d),
            _ => None,
        },
        Some(_) => return None,
    };
    let int = |k: &[u8], def: i64| {
        d.and_then(|d| d.get(k).ok())
            .and_then(|o| o.as_i64().ok())
            .unwrap_or(def)
    };
    let flag = |k: &[u8]| {
        d.and_then(|d| d.get(k).ok())
            .and_then(|o| o.as_bool().ok())
            .unwrap_or(false)
    };
    let k = int(b"K", 0);
    // 폭은 이미지 폭과 같아야 하고, G3 2차원(K>0)과 바이트 정렬은 지원하지 않는다
    if int(b"Columns", 1728) != w as i64 || k > 0 || flag(b"EncodedByteAlign") {
        return None;
    }
    Some(Ccitt {
        k,
        black_is_1: flag(b"BlackIs1"),
    })
}

/// CCITT 데이터를 1비트 표본(행마다 바이트 정렬)으로 푼다. 반환: (표본, 실제로 디코딩한 줄 수)
fn ccitt_decode(data: &[u8], p: &Ccitt, w: usize, h: usize) -> Option<(Vec<u8>, usize)> {
    let stride = w.div_ceil(8);
    let mut out = vec![0u8; stride * h];
    let mut lines = 0usize;
    // 흰색 비트: BlackIs1 이 아니면 1
    let white_bit = !p.black_is_1;
    let mut put = |transitions: &[u32]| {
        if lines >= h {
            return;
        }
        let row = &mut out[lines * stride..(lines + 1) * stride];
        for (x, c) in fax::decoder::pels(transitions, w as u32).enumerate() {
            let bit = (c == fax::Color::White) == white_bit;
            if bit {
                row[x / 8] |= 0x80 >> (x % 8);
            }
        }
        lines += 1;
    };
    let ok = if p.k < 0 {
        fax::decoder::decode_g4(data.iter().copied(), w as u32, None, &mut put)
    } else {
        fax::decoder::decode_g3(data.iter().copied(), &mut put)
    };
    if ok.is_none() && lines == 0 {
        return None;
    }
    // 모자란 줄은 흰색으로
    if lines < h && white_bit {
        for b in &mut out[lines * stride..] {
            *b = 0xFF;
        }
    }
    Some((out, lines))
}

/// 스트림의 필터를 푼다. `DecodeParms` 가 배열(필터마다 매개변수)이면 필터를 하나씩 적용한다.
/// lopdf 는 사전 형태의 매개변수만 읽어, 배열이면 Flate 예측자 등이 빠진 채로 풀린다
pub fn plain_content(s: &Stream, limit: usize) -> lopdf::Result<Vec<u8>> {
    let Ok(Object::Array(parms)) = s.dict.get(b"DecodeParms") else {
        return s.get_plain_content_with_limit(limit);
    };
    let filters: Vec<Vec<u8>> = s
        .filters()
        .map(|f| f.into_iter().map(<[u8]>::to_vec).collect())
        .unwrap_or_default();
    let mut data = s.content.clone();
    for (i, f) in filters.iter().enumerate() {
        let mut d = Dictionary::new();
        d.set("Filter", Object::Name(f.clone()));
        if let Some(Object::Dictionary(p)) = parms.get(i) {
            d.set("DecodeParms", Object::Dictionary(p.clone()));
        }
        data = Stream::new(d, data).get_plain_content_with_limit(limit)?;
    }
    Ok(data)
}

fn device_name(n: u8) -> Object {
    Object::Name(
        match n {
            1 => b"DeviceGray".as_slice(),
            4 => b"DeviceCMYK",
            _ => b"DeviceRGB",
        }
        .to_vec(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(o: &Object) -> Option<Cs> {
        match o.as_name().ok()? {
            b"G" | b"DeviceGray" => Some(Cs::Device(1)),
            b"RGB" | b"DeviceRGB" => Some(Cs::Device(3)),
            _ => None,
        }
    }

    fn run(content: &[u8]) -> (Vec<u8>, Outcome) {
        let mut budget = usize::MAX;
        normalize(content, &mut device, &Policy::default(), &mut budget).unwrap()
    }

    #[test]
    fn flate_inline_image_is_decoded() {
        let raw = [0x20u8, 0x0a, 0x00, 0xff];
        let comp = {
            use std::io::Write;
            let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            z.write_all(&raw).unwrap();
            z.finish().unwrap()
        };
        let mut c = b"q BI /W 2 /H 2 /BPC 8 /CS /G /F /Fl ID ".to_vec();
        c.extend(&comp);
        c.extend(b"\nEI Q (BI) Tj");
        let (out, res) = run(&c);
        assert_eq!(res.normalized, 1, "{:?}", res.dropped);
        assert_eq!(res.images[0].content, raw);
        assert_eq!(out, b"q  0 CdrInlineImage  Q (BI) Tj");
    }

    #[test]
    fn unfiltered_whitespace_samples_and_strings() {
        // 공백 값으로 시작하는 표본, 표본 안의 "EI" 와 문자열 안의 BI
        let mut c = b"(BI ID EI) Tj BI /W 4 /H 1 /CS /G /BPC 8 ID ".to_vec();
        c.extend(b" EI ");
        c.extend(b"\nEI");
        let (_, res) = run(&c);
        assert_eq!(res.normalized, 1, "{:?}", res.dropped);
        assert_eq!(res.images[0].content, b" EI ");
    }

    #[test]
    fn truncated_tokens_do_not_overrun() {
        for c in [
            &b"BI /W 1 (abc\\"[..],
            b"BI <41",
            b"(x\\",
            b"BI /W 1 /H 1 ID",
        ] {
            let mut budget = usize::MAX;
            let _ = normalize(c, &mut device, &Policy::default(), &mut budget);
        }
    }

    #[test]
    fn ccitt_decoder_survives_garbage() {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for n in 0..3000usize {
            let len = n % 97;
            let data: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    x as u8
                })
                .collect();
            let w = 1 + n % 70;
            for k in [-1, 0] {
                let p = Ccitt {
                    k,
                    black_is_1: n % 2 == 0,
                };
                if let Some((bits, _)) = ccitt_decode(&data, &p, w, 5) {
                    assert_eq!(bits.len(), w.div_ceil(8) * 5);
                }
            }
        }
    }

    #[test]
    fn unsupported_filters_are_dropped() {
        let (out, res) = run(b"BI /W 1 /H 1 /IM true /F /JBIG2Decode ID \x00\x01 EI 0 0 m");
        assert_eq!(res.normalized, 0);
        assert_eq!(res.dropped, vec!["지원하지 않는 필터(JBIG2·JPX 등)"]);
        assert_eq!(out, b" 0 0 m");
    }
}
