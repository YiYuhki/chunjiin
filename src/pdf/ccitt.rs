//! CCITT 팩스(T.4 G3 1차원·2차원, T.6 G4) 디코더.
//!
//! 코드 표는 `fax` 크레이트의 것을 쓰고, 줄 해석은 PDF `CCITTFaxDecode` 매개변수
//! (K, EndOfLine, EncodedByteAlign, BlackIs1)를 모두 따르도록 직접 구현한다.
//! 입력이 끝나거나 형식이 깨지면 거기까지 디코딩한 줄만 쓰고 나머지는 흰색으로 채운다.

use fax::maps::{black, mode, white, Mode};
use fax::BitReader;

pub struct Params {
    /// <0: G4, 0: G3 1차원, >0: G3 2차원 혼합
    pub k: i64,
    pub black_is_1: bool,
    pub byte_align: bool,
}

/// 끝을 넘어서는 0 으로 채워 읽는 비트 읽개
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Bits<'_> {
    fn exhausted(&self) -> bool {
        self.pos >= self.data.len() * 8
    }

    fn align(&mut self) {
        self.pos = self.pos.div_ceil(8) * 8;
    }
}

impl BitReader for Bits<'_> {
    type Error = ();

    fn peek(&self, bits: u8) -> Option<u16> {
        if bits > 16 {
            return None;
        }
        let mut v: u32 = 0;
        for k in 0..bits as usize {
            let p = self.pos + k;
            let bit = self.data.get(p / 8).map_or(0, |b| (b >> (7 - p % 8)) & 1);
            v = (v << 1) | u32::from(bit);
        }
        Some(v as u16)
    }

    fn consume(&mut self, bits: u8) -> Result<(), ()> {
        self.pos += bits as usize;
        // 끝을 한참 넘어서면(0 채움만 읽는 중) 멈춘다
        if self.pos > self.data.len() * 8 + 32 {
            Err(())
        } else {
            Ok(())
        }
    }

    fn bits_to_byte_boundary(&self) -> u8 {
        ((8 - self.pos % 8) % 8) as u8
    }
}

/// 한 색의 달리기 길이 (메이크업 코드 포함)
fn run(r: &mut Bits, black_run: bool) -> Option<u32> {
    let mut total = 0u32;
    loop {
        let v = if black_run {
            black::decode(r)?
        } else {
            white::decode(r)?
        };
        total = total.checked_add(u32::from(v))?;
        if v < 64 {
            return Some(total);
        }
    }
}

/// 1차원(MH) 줄. `line` 에 색이 바뀌는 위치를 쌓는다 (흰색에서 시작)
fn line_1d(r: &mut Bits, w: u32, line: &mut Vec<u32>) -> Option<()> {
    let mut pos = 0u32;
    let mut black_run = false;
    while pos < w {
        let n = run(r, black_run)?;
        pos = pos.checked_add(n)?;
        if pos > w {
            return None;
        }
        if pos < w {
            line.push(pos);
        }
        black_run = !black_run;
    }
    Some(())
}

/// 2차원(MR·MMR) 줄
fn line_2d(r: &mut Bits, w: u32, reference: &[u32], line: &mut Vec<u32>) -> Option<()> {
    // a0 = -1 은 줄 시작 앞
    let mut a0: i64 = -1;
    let mut black = false;
    // 기준 줄의 색 변화 위치 t[i]: i 가 짝수면 검정이 시작, 홀수면 흰색이 시작
    let b1b2 = |a0: i64, black: bool| -> (u32, u32) {
        let start = reference.partition_point(|&p| i64::from(p) <= a0);
        let mut i = start;
        // b1 의 색은 현재 색의 반대: 현재 흰색이면 검정 시작(짝수 번째)
        while i < reference.len() && (i % 2 == 0) == black {
            i += 1;
        }
        let b1 = reference.get(i).copied().unwrap_or(w);
        let b2 = reference.get(i + 1).copied().unwrap_or(w);
        (b1, b2)
    };
    while a0 < i64::from(w) {
        let m = mode::decode(r)?;
        match m {
            Mode::Pass => {
                let (_, b2) = b1b2(a0, black);
                a0 = i64::from(b2);
            }
            Mode::Horizontal => {
                let start = a0.max(0) as u32;
                let r1 = run(r, black)?;
                let r2 = run(r, !black)?;
                let a1 = start.checked_add(r1)?;
                let a2 = a1.checked_add(r2)?;
                if a2 > w {
                    return None;
                }
                if a1 < w {
                    line.push(a1);
                }
                if a2 < w {
                    line.push(a2);
                }
                a0 = i64::from(a2);
            }
            Mode::Vertical(d) => {
                let (b1, _) = b1b2(a0, black);
                let a1 = i64::from(b1) + i64::from(d);
                if a1 < a0.max(0) || a1 > i64::from(w) {
                    return None;
                }
                if a1 < i64::from(w) {
                    line.push(a1 as u32);
                }
                black = !black;
                a0 = a1;
            }
            Mode::Extension | Mode::EOF => return None,
        }
    }
    Some(())
}

/// 줄 앞의 채움 비트와 EOL(000000000001)을 건너뛴다. 반환: 건너뛴 EOL 수
fn skip_eols(r: &mut Bits) -> usize {
    let mut eols = 0;
    loop {
        match r.peek(12) {
            Some(1) => {
                let _ = r.consume(12);
                eols += 1;
            }
            // 11개 넘는 0 은 채움
            Some(0) if !r.exhausted() => {
                let _ = r.consume(1);
            }
            _ => return eols,
        }
    }
}

/// 디코딩한 1비트 표본(행마다 바이트 정렬, PDF 규칙대로 BlackIs1 이 아니면 검정 = 0)과
/// 실제로 디코딩한 줄 수. 한 줄도 못 읽으면 None
pub fn decode(data: &[u8], p: &Params, w: usize, h: usize) -> Option<(Vec<u8>, usize)> {
    if w == 0 || w > u32::MAX as usize / 2 {
        return None;
    }
    let wu = w as u32;
    let stride = w.div_ceil(8);
    let white_bit = !p.black_is_1;
    let mut out = vec![if white_bit { 0xFF } else { 0 }; stride.checked_mul(h)?];
    let mut r = Bits { data, pos: 0 };
    let mut reference: Vec<u32> = Vec::new();
    let mut line: Vec<u32> = Vec::new();
    let mut lines = 0usize;
    while lines < h && !r.exhausted() {
        if p.byte_align {
            r.align();
        }
        let eols = skip_eols(&mut r);
        // G4 의 EOFB, G3 의 RTC
        if (p.k < 0 && eols >= 1) || eols >= 2 {
            break;
        }
        let two_d = match p.k {
            k if k < 0 => true,
            0 => false,
            _ => {
                let tag = r.peek(1)?;
                r.consume(1).ok()?;
                tag == 0
            }
        };
        line.clear();
        let ok = if two_d {
            line_2d(&mut r, wu, &reference, &mut line)
        } else {
            line_1d(&mut r, wu, &mut line)
        };
        if ok.is_none() {
            break;
        }
        // 색 변화 위치 → 비트
        let row = &mut out[lines * stride..(lines + 1) * stride];
        let mut black = false;
        let mut x = 0usize;
        for &t in line.iter().chain(std::iter::once(&wu)) {
            let t = (t as usize).min(w);
            if black {
                for px in x..t {
                    let bit = 0x80 >> (px % 8);
                    if white_bit {
                        row[px / 8] &= !bit;
                    } else {
                        row[px / 8] |= bit;
                    }
                }
            }
            x = t.max(x);
            black = !black;
        }
        std::mem::swap(&mut reference, &mut line);
        lines += 1;
    }
    (lines > 0).then_some((out, lines))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_g4(rows: &[Vec<bool>], w: u32) -> Vec<u8> {
        let mut enc = fax::encoder::Encoder::new(fax::VecWriter::new());
        for r in rows {
            let pels = r.iter().map(|&b| {
                if b {
                    fax::Color::Black
                } else {
                    fax::Color::White
                }
            });
            enc.encode_line(pels, w).unwrap();
        }
        enc.finish().unwrap().finish()
    }

    #[test]
    fn g4_roundtrip() {
        let w = 37usize;
        let mut x: u32 = 7;
        let rows: Vec<Vec<bool>> = (0..23)
            .map(|y| {
                (0..w)
                    .map(|i| {
                        x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
                        (i / 3 + y) % 5 == 0 || x >> 28 == 0
                    })
                    .collect()
            })
            .collect();
        let data = encode_g4(&rows, w as u32);
        let p = Params {
            k: -1,
            black_is_1: false,
            byte_align: false,
        };
        let (bits, lines) = decode(&data, &p, w, rows.len()).unwrap();
        assert_eq!(lines, rows.len());
        let stride = w.div_ceil(8);
        for (y, r) in rows.iter().enumerate() {
            for (i, &b) in r.iter().enumerate() {
                let bit = bits[y * stride + i / 8] >> (7 - i % 8) & 1;
                assert_eq!(bit == 0, b, "({i},{y})");
            }
        }
    }

    #[test]
    fn g3_1d_without_eol() {
        // 흰 3 (1000) 검정 2 (11) 흰 3 (1000), 8 픽셀 두 줄
        let mut bits = String::new();
        for _ in 0..2 {
            bits += "1000";
            bits += "11";
            bits += "1000";
        }
        while !bits.len().is_multiple_of(8) {
            bits.push('0');
        }
        let data: Vec<u8> = bits
            .as_bytes()
            .chunks(8)
            .map(|c| c.iter().fold(0u8, |a, &b| (a << 1) | (b - b'0')))
            .collect();
        let p = Params {
            k: 0,
            black_is_1: false,
            byte_align: false,
        };
        let (out, lines) = decode(&data, &p, 8, 2).unwrap();
        assert_eq!(lines, 2);
        assert_eq!(out, [0b1110_0111, 0b1110_0111]);
    }

    #[test]
    fn garbage_is_bounded() {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for n in 0..3000usize {
            let data: Vec<u8> = (0..n % 131)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    x as u8
                })
                .collect();
            for k in [-1, 0, 2] {
                let p = Params {
                    k,
                    black_is_1: n % 2 == 0,
                    byte_align: n % 3 == 0,
                };
                if let Some((out, _)) = decode(&data, &p, 1 + n % 90, 7) {
                    assert_eq!(out.len(), (1 + n % 90).div_ceil(8) * 7);
                }
            }
        }
    }
}
