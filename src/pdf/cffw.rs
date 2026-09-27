//! CFF(Type 1C / CID-keyed) 글꼴을 외곽선에서 새로 만든다.
//!
//! 원본 글꼴(CFF 또는 Type 1)을 독립 해석기로 실행해 얻은 외곽선만으로 글리프 프로그램
//! (Type 2 charstring)을 새로 쓰고, 머리글·이름·딕셔너리·문자열·charset·인코딩을 새로 조립한다.
//! 서브루틴·힌트·알 수 없는 딕셔너리 연산자·사용되지 않는 데이터는 결과에 들어가지 않는다.

/// 외곽선 조각 (글꼴 단위 절대 좌표)
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Seg {
    Move(f64, f64),
    Line(f64, f64),
    Curve(f64, f64, f64, f64, f64, f64),
}

pub struct Glyph {
    /// 글리프 이름 (단순 글꼴) — 0번은 .notdef
    pub name: String,
    /// CID (CID-keyed 글꼴)
    pub cid: u16,
    pub width: f64,
    pub path: Vec<Seg>,
}

pub struct Font {
    pub name: String,
    /// PostScript FontMatrix
    pub matrix: [f64; 6],
    pub bbox: [f64; 4],
    pub glyphs: Vec<Glyph>,
    /// 단순 글꼴의 내장 인코딩 (코드, 글리프 번호)
    pub encoding: Vec<(u8, u16)>,
    pub cid: bool,
}

/// 외곽선을 모으는 수집기
#[derive(Default)]
pub struct PathSink {
    pub path: Vec<Seg>,
    cur: (f64, f64),
}

impl PathSink {
    pub fn move_to(&mut self, x: f64, y: f64) {
        self.path.push(Seg::Move(x, y));
        self.cur = (x, y);
    }
    pub fn line_to(&mut self, x: f64, y: f64) {
        self.path.push(Seg::Line(x, y));
        self.cur = (x, y);
    }
    pub fn quad_to(&mut self, x1: f64, y1: f64, x: f64, y: f64) {
        let (x0, y0) = self.cur;
        let c1 = (x0 + 2.0 / 3.0 * (x1 - x0), y0 + 2.0 / 3.0 * (y1 - y0));
        let c2 = (x + 2.0 / 3.0 * (x1 - x), y + 2.0 / 3.0 * (y1 - y));
        self.curve_to(c1.0, c1.1, c2.0, c2.1, x, y);
    }
    pub fn curve_to(&mut self, x1: f64, y1: f64, x2: f64, y2: f64, x: f64, y: f64) {
        self.path.push(Seg::Curve(x1, y1, x2, y2, x, y));
        self.cur = (x, y);
    }
}

impl ttf_parser::OutlineBuilder for PathSink {
    fn move_to(&mut self, x: f32, y: f32) {
        PathSink::move_to(self, x.into(), y.into());
    }
    fn line_to(&mut self, x: f32, y: f32) {
        PathSink::line_to(self, x.into(), y.into());
    }
    fn quad_to(&mut self, x1: f32, y1: f32, x: f32, y: f32) {
        PathSink::quad_to(self, x1.into(), y1.into(), x.into(), y.into());
    }
    fn curve_to(&mut self, x1: f32, y1: f32, x2: f32, y2: f32, x: f32, y: f32) {
        PathSink::curve_to(
            self,
            x1.into(),
            y1.into(),
            x2.into(),
            y2.into(),
            x.into(),
            y.into(),
        );
    }
    fn close(&mut self) {}
}

// ---------------------------------------------------------------- 수 인코딩

/// charstring 피연산자
fn cs_num(v: f64, out: &mut Vec<u8>) {
    let r = v.round();
    if (v - r).abs() < 1e-6 && (-32768.0..=32767.0).contains(&r) {
        let i = r as i32;
        match i {
            -107..=107 => out.push((i + 139) as u8),
            108..=1131 => {
                let j = i - 108;
                out.push((j / 256 + 247) as u8);
                out.push((j % 256) as u8);
            }
            -1131..=-108 => {
                let j = -i - 108;
                out.push((j / 256 + 251) as u8);
                out.push((j % 256) as u8);
            }
            _ => {
                out.push(28);
                out.extend((i as i16).to_be_bytes());
            }
        }
    } else {
        // 16.16 고정 소수점
        let f = (v.clamp(-32768.0, 32767.99) * 65536.0).round() as i32;
        out.push(255);
        out.extend(f.to_be_bytes());
    }
}

/// DICT 정수 (항상 5바이트: 오프셋을 미리 자리 잡기 위함)
fn dict_int(v: i32, out: &mut Vec<u8>) {
    out.push(29);
    out.extend(v.to_be_bytes());
}

/// DICT 실수 (BCD)
fn dict_real(v: f64, out: &mut Vec<u8>) {
    let s = format!("{:.8e}", v);
    // 가수·지수를 나눠 불필요한 0 을 없앤다
    let (mant, exp) = s.split_once('e').unwrap_or((&s, "0"));
    let mant = if mant.contains('.') {
        mant.trim_end_matches('0').trim_end_matches('.')
    } else {
        mant
    };
    let exp: i32 = exp.parse().unwrap_or(0);
    let mut nibbles: Vec<u8> = Vec::new();
    for c in mant.chars() {
        nibbles.push(match c {
            '0'..='9' => c as u8 - b'0',
            '.' => 0xA,
            '-' => 0xE,
            _ => continue,
        });
    }
    if exp != 0 {
        nibbles.push(if exp < 0 { 0xC } else { 0xB });
        for c in exp.abs().to_string().chars() {
            nibbles.push(c as u8 - b'0');
        }
    }
    nibbles.push(0xF);
    if nibbles.len() % 2 == 1 {
        nibbles.push(0xF);
    }
    out.push(30);
    for p in nibbles.chunks(2) {
        out.push(p[0] << 4 | p[1]);
    }
}

fn op(code: u16, out: &mut Vec<u8>) {
    if code >= 1200 {
        out.push(12);
        out.push((code - 1200) as u8);
    } else {
        out.push(code as u8);
    }
}

/// INDEX 자료 구조
fn index(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend((items.len() as u16).to_be_bytes());
    if items.is_empty() {
        return out;
    }
    let total: usize = items.iter().map(Vec::len).sum();
    let off_size: u8 = match total + 1 {
        0..=0xFF => 1,
        0x100..=0xFFFF => 2,
        0x1_0000..=0xFF_FFFF => 3,
        _ => 4,
    };
    out.push(off_size);
    let mut off = 1usize;
    let put = |v: usize, out: &mut Vec<u8>| {
        let b = (v as u32).to_be_bytes();
        out.extend(&b[4 - off_size as usize..]);
    };
    put(off, &mut out);
    for it in items {
        off += it.len();
        put(off, &mut out);
    }
    for it in items {
        out.extend(it);
    }
    out
}

/// 외곽선 → Type 2 charstring (폭을 첫 피연산자로)
fn charstring(g: &Glyph) -> Vec<u8> {
    let mut out = Vec::new();
    let mut width = Some(g.width);
    let mut cur = (0.0f64, 0.0f64);
    let mut emit_width = |out: &mut Vec<u8>| {
        if let Some(w) = width.take() {
            if w != 0.0 {
                cs_num(w, out);
            }
        }
    };
    for s in &g.path {
        match *s {
            Seg::Move(x, y) => {
                emit_width(&mut out);
                cs_num(x - cur.0, &mut out);
                cs_num(y - cur.1, &mut out);
                out.push(21); // rmoveto
                cur = (x, y);
            }
            Seg::Line(x, y) => {
                cs_num(x - cur.0, &mut out);
                cs_num(y - cur.1, &mut out);
                out.push(5); // rlineto
                cur = (x, y);
            }
            Seg::Curve(x1, y1, x2, y2, x, y) => {
                cs_num(x1 - cur.0, &mut out);
                cs_num(y1 - cur.1, &mut out);
                cs_num(x2 - x1, &mut out);
                cs_num(y2 - y1, &mut out);
                cs_num(x - x2, &mut out);
                cs_num(y - y2, &mut out);
                out.push(8); // rrcurveto
                cur = (x, y);
            }
        }
    }
    emit_width(&mut out);
    out.push(14); // endchar
    out
}

/// PostScript 이름에 쓸 수 있는 문자만
fn ps_name(s: &str) -> String {
    let n: String = s
        .chars()
        .filter(|c| c.is_ascii_graphic() && !"[](){}<>/%".contains(*c))
        .take(63)
        .collect();
    if n.is_empty() {
        "CDRFont".into()
    } else {
        n
    }
}

/// CFF 를 만든다
pub fn write(font: &Font) -> Vec<u8> {
    let n = font.glyphs.len();
    // 문자열: 글리프 이름(단순 글꼴) 또는 ROS(CID)
    let mut strings: Vec<Vec<u8>> = Vec::new();
    let sid = |s: &str, strings: &mut Vec<Vec<u8>>| -> u16 {
        strings.push(ps_name(s).into_bytes());
        (390 + strings.len()) as u16
    };
    let mut charset = vec![0u8]; // 형식 0
    let (ros, glyph_sids) = if font.cid {
        let r = sid("Adobe", &mut strings);
        let o = sid("Identity", &mut strings);
        for g in &font.glyphs[1..] {
            charset.extend(g.cid.to_be_bytes());
        }
        (Some((r, o)), Vec::new())
    } else {
        let mut sids = vec![0u16];
        for g in &font.glyphs[1..] {
            let s = sid(&g.name, &mut strings);
            charset.extend(s.to_be_bytes());
            sids.push(s);
        }
        (None, sids)
    };
    let _ = glyph_sids;

    // 인코딩 (형식 0 + 보충): 글리프 순서와 무관하게 코드마다 이름으로 잇는다
    let encoding = if !font.cid && !font.encoding.is_empty() {
        let mut first: Vec<(u8, u16)> = Vec::new();
        let mut sups: Vec<(u8, u16)> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        // 형식 0 은 글리프 1..n 의 코드를 차례로 적으므로, 글리프 순서대로 첫 코드를 쓰고
        // 나머지(순서가 어긋나거나 중복)는 보충(코드 → 이름 SID)으로
        let mut by_gid: Vec<Option<u8>> = vec![None; n];
        for &(code, gid) in &font.encoding {
            if (gid as usize) < n && gid != 0 && by_gid[gid as usize].is_none() {
                by_gid[gid as usize] = Some(code);
            }
        }
        let mut k = 1;
        while k < n {
            match by_gid[k] {
                Some(code) => {
                    first.push((code, k as u16));
                    seen.insert((code, k as u16));
                    k += 1;
                }
                None => break,
            }
        }
        for &(code, gid) in &font.encoding {
            if gid != 0 && (gid as usize) < n && !seen.contains(&(code, gid)) {
                sups.push((code, (391 + gid as usize - 1) as u16));
            }
        }
        let mut e = vec![if sups.is_empty() { 0 } else { 0x80 }];
        e.push(first.len() as u8);
        e.extend(first.iter().map(|(c, _)| *c));
        if !sups.is_empty() {
            let sups = &sups[..sups.len().min(255)];
            e.push(sups.len() as u8);
            for (c, s) in sups {
                e.push(*c);
                e.extend(s.to_be_bytes());
            }
        }
        Some(e)
    } else {
        None
    };

    let charstrings = index(&font.glyphs.iter().map(charstring).collect::<Vec<_>>());
    let mut private = Vec::new();
    dict_int(0, &mut private);
    op(20, &mut private); // defaultWidthX
    dict_int(0, &mut private);
    op(21, &mut private); // nominalWidthX

    // FDSelect(형식 0, 모두 0번)과 FDArray (CID)
    let fdselect = font.cid.then(|| {
        let mut v = vec![0u8];
        v.extend(std::iter::repeat_n(0u8, n));
        v
    });

    // 머리 딕셔너리는 오프셋 자리를 5바이트로 고정해 두 번 만든다
    let build_top = |offs: &[i32; 6]| {
        let mut t = Vec::new();
        if let Some((r, o)) = ros {
            dict_int(r as i32, &mut t);
            dict_int(o as i32, &mut t);
            dict_int(0, &mut t);
            op(1230, &mut t); // ROS
        }
        for v in font.matrix {
            dict_real(v, &mut t);
        }
        op(1207, &mut t); // FontMatrix
        for v in font.bbox {
            dict_int(v.round() as i32, &mut t);
        }
        op(5, &mut t); // FontBBox
        dict_int(offs[0], &mut t);
        op(15, &mut t); // charset
        if encoding.is_some() {
            dict_int(offs[1], &mut t);
            op(16, &mut t); // Encoding
        }
        dict_int(offs[2], &mut t);
        op(17, &mut t); // CharStrings
        if font.cid {
            dict_int(n as i32, &mut t);
            op(1234, &mut t); // CIDCount
            dict_int(offs[4], &mut t);
            op(1236, &mut t); // FDArray
            dict_int(offs[5], &mut t);
            op(1237, &mut t); // FDSelect
        } else {
            dict_int(private.len() as i32, &mut t);
            dict_int(offs[3], &mut t);
            op(18, &mut t); // Private
        }
        t
    };
    let name = index(&[ps_name(&font.name).into_bytes()]);
    let string_index = index(&strings);
    let gsubrs = index(&[]);
    let top_len = index(&[build_top(&[0; 6])]).len();
    let start = 4 + name.len() + top_len + string_index.len() + gsubrs.len();
    let at_charset = start;
    let at_encoding = at_charset + charset.len();
    let at_charstrings = at_encoding + encoding.as_ref().map_or(0, Vec::len);
    let at_private = at_charstrings + charstrings.len();
    // FD 딕셔너리: Private 만
    let at_fdselect = at_private + private.len();
    let at_fdarray = at_fdselect + fdselect.as_ref().map_or(0, Vec::len);
    let fd = {
        let mut f = Vec::new();
        dict_int(private.len() as i32, &mut f);
        dict_int(at_private as i32, &mut f);
        op(18, &mut f);
        f
    };
    let offs = [
        at_charset as i32,
        at_encoding as i32,
        at_charstrings as i32,
        at_private as i32,
        at_fdarray as i32,
        at_fdselect as i32,
    ];
    let top = index(&[build_top(&offs)]);
    debug_assert_eq!(top.len(), top_len);

    let mut out = vec![1, 0, 4, 4];
    out.extend(name);
    out.extend(top);
    out.extend(string_index);
    out.extend(gsubrs);
    out.extend(charset);
    if let Some(e) = encoding {
        out.extend(e);
    }
    out.extend(charstrings);
    out.extend(&private);
    if let Some(fs) = fdselect {
        out.extend(fs);
        out.extend(index(&[fd]));
    }
    out
}

// ---------------------------------------------------------------- 원본 CFF 행렬 읽기

fn read_index(d: &[u8], at: usize) -> Option<(Vec<&[u8]>, usize)> {
    let count = u16::from_be_bytes([*d.get(at)?, *d.get(at + 1)?]) as usize;
    if count == 0 {
        return Some((Vec::new(), at + 2));
    }
    let os = *d.get(at + 2)? as usize;
    if !(1..=4).contains(&os) {
        return None;
    }
    let off = |i: usize| -> Option<usize> {
        let p = at + 3 + i * os;
        let b = d.get(p..p + os)?;
        Some(b.iter().fold(0usize, |a, &x| a << 8 | x as usize))
    };
    let base = at + 3 + (count + 1) * os - 1;
    let mut items = Vec::with_capacity(count);
    for i in 0..count {
        let (s, e) = (off(i)?, off(i + 1)?);
        items.push(d.get(base + s..base + e)?);
    }
    Some((items, base + off(count)?))
}

/// DICT → (연산자, 피연산자들)
fn read_dict(d: &[u8]) -> Vec<(u16, Vec<f64>)> {
    let mut out = Vec::new();
    let mut ops: Vec<f64> = Vec::new();
    let mut i = 0;
    while i < d.len() {
        let b = d[i];
        match b {
            0..=21 => {
                let code = if b == 12 {
                    i += 1;
                    1200 + u16::from(*d.get(i).unwrap_or(&0))
                } else {
                    u16::from(b)
                };
                out.push((code, std::mem::take(&mut ops)));
                i += 1;
            }
            28 => {
                let v = d
                    .get(i + 1..i + 3)
                    .map_or(0, |x| i16::from_be_bytes([x[0], x[1]]));
                ops.push(f64::from(v));
                i += 3;
            }
            29 => {
                let v = d
                    .get(i + 1..i + 5)
                    .map_or(0, |x| i32::from_be_bytes([x[0], x[1], x[2], x[3]]));
                ops.push(f64::from(v));
                i += 5;
            }
            30 => {
                let mut s = String::new();
                i += 1;
                'real: while i < d.len() {
                    for nib in [d[i] >> 4, d[i] & 0xF] {
                        match nib {
                            0..=9 => s.push((b'0' + nib) as char),
                            0xA => s.push('.'),
                            0xB => s.push('E'),
                            0xC => s.push_str("E-"),
                            0xE => s.push('-'),
                            0xF => {
                                i += 1;
                                break 'real;
                            }
                            _ => {}
                        }
                    }
                    i += 1;
                }
                ops.push(s.parse().unwrap_or(0.0));
            }
            32..=246 => {
                ops.push(f64::from(i32::from(b) - 139));
                i += 1;
            }
            247..=250 => {
                let w = *d.get(i + 1).unwrap_or(&0);
                ops.push(f64::from((i32::from(b) - 247) * 256 + i32::from(w) + 108));
                i += 2;
            }
            251..=254 => {
                let w = *d.get(i + 1).unwrap_or(&0);
                ops.push(f64::from(-(i32::from(b) - 251) * 256 - i32::from(w) - 108));
                i += 2;
            }
            _ => i += 1,
        }
    }
    out
}

pub type Matrix = [f64; 6];
pub const DEFAULT_MATRIX: Matrix = [0.001, 0.0, 0.0, 0.001, 0.0, 0.0];

fn matrix_of(dict: &[(u16, Vec<f64>)]) -> Option<Matrix> {
    let (_, v) = dict.iter().find(|(o, _)| *o == 1207)?;
    let m: Matrix = v.as_slice().try_into().ok()?;
    m.iter().all(|x| x.is_finite()).then_some(m)
}

/// a 다음 b 를 적용하는 행렬 (점 × a × b)
pub fn mul(a: &Matrix, b: &Matrix) -> Matrix {
    [
        a[0] * b[0] + a[1] * b[2],
        a[0] * b[1] + a[1] * b[3],
        a[2] * b[0] + a[3] * b[2],
        a[2] * b[1] + a[3] * b[3],
        a[4] * b[0] + a[5] * b[2] + b[4],
        a[4] * b[1] + a[5] * b[3] + b[5],
    ]
}

pub fn invert(m: &Matrix) -> Option<Matrix> {
    let det = m[0] * m[3] - m[1] * m[2];
    if det.abs() < 1e-12 {
        return None;
    }
    let (a, b, c, d) = (m[3] / det, -m[1] / det, -m[2] / det, m[0] / det);
    Some([a, b, c, d, -(m[4] * a + m[5] * c), -(m[4] * b + m[5] * d)])
}

/// Name INDEX 의 글꼴 이름
pub fn font_name(cff: &[u8]) -> Option<String> {
    let hdr = *cff.get(2)? as usize;
    let (names, _) = read_index(cff, hdr)?;
    Some(String::from_utf8_lossy(names.first()?).into_owned())
}

/// 최상위 FontMatrix (없으면 기본값). ttf-parser 는 f32 로 돌려주므로 원본 값을 직접 읽는다
pub fn top_matrix(cff: &[u8]) -> Option<Matrix> {
    let hdr = *cff.get(2)? as usize;
    let (_, after_name) = read_index(cff, hdr)?;
    let (tops, _) = read_index(cff, after_name)?;
    Some(matrix_of(&read_dict(tops.first()?)).unwrap_or(DEFAULT_MATRIX))
}

/// CID 글꼴의 글리프별 유효 FontMatrix. 최상위 딕셔너리에 FontMatrix 가 명시돼 있으면 FD 행렬에
/// 이어 붙이고(Adobe TN5176), 없으면 FD 행렬만 쓴다
pub fn cid_matrices(cff: &[u8], n: usize) -> Option<Vec<Matrix>> {
    let hdr = *cff.get(2)? as usize;
    let (_, after_name) = read_index(cff, hdr)?;
    let (tops, _) = read_index(cff, after_name)?;
    let top = read_dict(tops.first()?);
    let off = |op: u16| {
        top.iter()
            .find(|(o, _)| *o == op)
            .and_then(|(_, v)| v.first().copied())
            .filter(|v| *v > 0.0)
            .map(|v| v as usize)
    };
    let top_m = matrix_of(&top);
    let (fds, _) = read_index(cff, off(1236)?)?;
    let fd_m: Vec<Matrix> = fds
        .iter()
        .map(|fd| {
            let m = matrix_of(&read_dict(fd));
            match (m, top_m) {
                (Some(m), Some(t)) => mul(&m, &t),
                (Some(m), None) => m,
                (None, t) => t.unwrap_or(DEFAULT_MATRIX),
            }
        })
        .collect();
    // FDSelect
    let at = off(1237)?;
    let sel: Vec<usize> = match *cff.get(at)? {
        0 => cff
            .get(at + 1..at + 1 + n)?
            .iter()
            .map(|&x| x as usize)
            .collect(),
        3 => {
            let nr = u16::from_be_bytes([*cff.get(at + 1)?, *cff.get(at + 2)?]) as usize;
            let mut v = vec![0usize; n];
            for r in 0..nr {
                let p = at + 3 + r * 3;
                let first = u16::from_be_bytes([*cff.get(p)?, *cff.get(p + 1)?]) as usize;
                let fd = *cff.get(p + 2)? as usize;
                let next = u16::from_be_bytes([*cff.get(p + 3)?, *cff.get(p + 4)?]) as usize;
                for g in v.iter_mut().take(next.min(n)).skip(first) {
                    *g = fd;
                }
            }
            v
        }
        _ => return None,
    };
    sel.iter().map(|&i| fd_m.get(i).copied()).collect()
}

/// 경로의 점에 행렬을 적용한다
pub fn transform(path: &mut [Seg], m: &Matrix) {
    let t = |x: f64, y: f64| (x * m[0] + y * m[2] + m[4], x * m[1] + y * m[3] + m[5]);
    for s in path {
        *s = match *s {
            Seg::Move(x, y) => {
                let (x, y) = t(x, y);
                Seg::Move(x, y)
            }
            Seg::Line(x, y) => {
                let (x, y) = t(x, y);
                Seg::Line(x, y)
            }
            Seg::Curve(a, b, c, d, x, y) => {
                let (a, b) = t(a, b);
                let (c, d) = t(c, d);
                let (x, y) = t(x, y);
                Seg::Curve(a, b, c, d, x, y)
            }
        };
    }
}

/// 경로의 외곽 경계 (점 기준)
pub fn bounds(path: &[Seg]) -> Option<[f64; 4]> {
    let mut b: Option<[f64; 4]> = None;
    let mut add = |x: f64, y: f64| {
        let v = b.get_or_insert([x, y, x, y]);
        v[0] = v[0].min(x);
        v[1] = v[1].min(y);
        v[2] = v[2].max(x);
        v[3] = v[3].max(y);
    };
    for s in path {
        match *s {
            Seg::Move(x, y) | Seg::Line(x, y) => add(x, y),
            Seg::Curve(a, b2, c, d, x, y) => {
                add(a, b2);
                add(c, d);
                add(x, y);
            }
        }
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn written_cff_parses_back() {
        let square = vec![
            Seg::Move(10.0, 0.0),
            Seg::Line(500.5, 0.0),
            Seg::Curve(600.0, 100.0, 600.0, 600.0, 500.5, 700.0),
            Seg::Line(10.0, 700.0),
        ];
        let font = Font {
            name: "Test Font".into(),
            matrix: [0.001, 0.0, 0.0, 0.001, 0.0, 0.0],
            bbox: [0.0, 0.0, 600.0, 700.0],
            glyphs: vec![
                Glyph {
                    name: ".notdef".into(),
                    cid: 0,
                    width: 500.0,
                    path: vec![],
                },
                Glyph {
                    name: "A".into(),
                    cid: 1,
                    width: 612.0,
                    path: square.clone(),
                },
                Glyph {
                    name: "uni00C5".into(),
                    cid: 2,
                    width: 0.0,
                    path: square.clone(),
                },
            ],
            encoding: vec![(65, 1), (197, 2), (97, 1)],
            cid: false,
        };
        let data = write(&font);
        let t = ttf_parser::cff::Table::parse(&data).expect("CFF 해석");
        assert_eq!(t.number_of_glyphs(), 3);
        assert_eq!(t.glyph_name(ttf_parser::GlyphId(2)), Some("uni00C5"));
        assert_eq!(t.glyph_width(ttf_parser::GlyphId(1)), Some(612));
        assert_eq!(t.glyph_index(65), Some(ttf_parser::GlyphId(1)));
        assert_eq!(t.glyph_index(197), Some(ttf_parser::GlyphId(2)));
        assert_eq!(t.glyph_index(97), Some(ttf_parser::GlyphId(1)));
        let mut sink = PathSink::default();
        t.outline(ttf_parser::GlyphId(1), &mut sink).unwrap();
        assert_eq!(bounds(&sink.path), bounds(&square));
        assert!((t.matrix().sx - 0.001).abs() < 1e-7);

        let cid = Font {
            cid: true,
            encoding: vec![],
            ..font
        };
        let data = write(&cid);
        let t = ttf_parser::cff::Table::parse(&data).expect("CID CFF 해석");
        assert_eq!(t.glyph_cid(ttf_parser::GlyphId(2)), Some(2));
        let mut sink = PathSink::default();
        t.outline(ttf_parser::GlyphId(2), &mut sink).unwrap();
        assert_eq!(bounds(&sink.path), bounds(&square));
    }
}
