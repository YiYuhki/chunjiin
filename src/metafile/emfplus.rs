//! EMF+ (GDI+) 레코드 재조합.
//!
//! EMF+ 레코드는 EMF 주석(EMR_COMMENT) 안에 들어 있다. 레코드를 하나씩 해석해 허용된 종류만
//! 크기·개체 번호·좌표 개수·경로·영역 구조를 검증한 정규형으로 다시 쓴다.
//! - 개체(브러시·펜·경로·영역·이미지·글꼴·문자열 형식·이미지 속성)는 정의된 필드만 옮기고,
//!   그리기 레코드가 가리키는 개체는 그 종류가 맞아야 한다
//! - 이미지 개체의 압축 비트맵(PNG/JPEG/GIF/BMP)은 재인코딩하고, 원시 화소는 크기를 검증한다.
//!   내장 메타파일·텍스처 브러시·경로 그라데이션·사용자 선 끝·여러 레코드로 나뉜 개체는 옮기지 않는다
//! - 주석·직렬화 개체(효과)·원격 데스크톱 상태·다중 형식 구획은 옮기지 않는다
//!
//! 그리기에 영향을 주는 레코드를 하나라도 옮길 수 없으면 그 메타파일의 EMF+ 는 모두 빼고
//! GDI 레코드로만 그리게 한다 (EMF+ 가 있으면 렌더러가 GDI 대체 레코드를 건너뛰므로, 일부만
//! 남기면 그림이 빠진다).

use crate::imaging::{self, ImageKind};
use crate::legacy::blip::PixelBudget;
use crate::policy::Policy;

const MAX_OBJECTS: usize = 64;
const MAX_REGION_DEPTH: usize = 64;

const OBJ_BRUSH: u8 = 1;
const OBJ_PEN: u8 = 2;
const OBJ_PATH: u8 = 3;
const OBJ_REGION: u8 = 4;
const OBJ_IMAGE: u8 = 5;
const OBJ_FONT: u8 = 6;
const OBJ_STRING_FORMAT: u8 = 7;
const OBJ_IMAGE_ATTRIBUTES: u8 = 8;

/// 순서대로 읽는 커서 (범위를 벗어나면 None)
struct Cur<'a> {
    d: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn new(d: &'a [u8]) -> Self {
        Cur { d, p: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.d.get(self.p..self.p.checked_add(n)?)?;
        self.p += n;
        Some(s)
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn f32(&mut self) -> Option<f32> {
        Some(f32::from_bits(self.u32()?)).filter(|v| v.is_finite())
    }
    /// 지금까지 읽은 부분
    fn done(&self) -> &'a [u8] {
        &self.d[..self.p]
    }
}

/// 개수 × 크기 만큼의 배열 (개수는 남은 데이터로 제한)
fn array<'a>(c: &mut Cur<'a>, count: u32, each: usize) -> Option<&'a [u8]> {
    c.take((count as usize).checked_mul(each)?)
}

/// 그래픽 버전 값 (상위 20비트가 0xDBC01)
fn version(c: &mut Cur) -> Option<u32> {
    c.u32().filter(|v| v >> 12 == 0xDBC01)
}

pub struct PlusCtx<'a> {
    pub policy: &'a Policy,
    pub budget: &'a mut PixelBudget,
    objects: [u8; MAX_OBJECTS],
    /// 그리기에 영향을 주는 레코드를 모두 옮겼는지
    pub faithful: bool,
    pub kept: u64,
    pub removed: u64,
    pub invalid: u64,
    pub images: u64,
}

impl<'a> PlusCtx<'a> {
    pub fn new(policy: &'a Policy, budget: &'a mut PixelBudget) -> Self {
        PlusCtx {
            policy,
            budget,
            objects: [0; MAX_OBJECTS],
            faithful: true,
            kept: 0,
            removed: 0,
            invalid: 0,
            images: 0,
        }
    }

    fn is(&self, id: u32, kind: u8) -> bool {
        (id as usize) < MAX_OBJECTS && self.objects[id as usize] == kind
    }

    /// 브러시 번호 또는 색 (S 플래그)
    fn brush(&self, flags: u16, v: u32) -> bool {
        flags & 0x8000 != 0 || self.is(v, OBJ_BRUSH)
    }

    /// EMF+ 주석 한 개의 레코드들(식별자 "EMF+" 뒤)을 재조합한다. 남길 것이 없으면 None
    pub fn comment(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut p = 0usize;
        while p + 12 <= data.len() {
            let t = u16::from_le_bytes([data[p], data[p + 1]]);
            let flags = u16::from_le_bytes([data[p + 2], data[p + 3]]);
            let size = u32::from_le_bytes(data[p + 4..p + 8].try_into().ok()?) as usize;
            let dsize = u32::from_le_bytes(data[p + 8..p + 12].try_into().ok()?) as usize;
            if size < 12 || !size.is_multiple_of(4) || size > data.len() - p || dsize > size - 12 {
                self.invalid += 1;
                self.faithful = false;
                break;
            }
            let body = &data[p + 12..p + 12 + dsize];
            p += size;
            match self.record(t, flags, body) {
                Rec::Keep(flags, b) => {
                    let mut b = b;
                    let dlen = b.len();
                    while !b.len().is_multiple_of(4) {
                        b.push(0);
                    }
                    out.extend(t.to_le_bytes());
                    out.extend(flags.to_le_bytes());
                    out.extend(((b.len() + 12) as u32).to_le_bytes());
                    out.extend((dlen as u32).to_le_bytes());
                    out.extend(b);
                    self.kept += 1;
                }
                Rec::Harmless => self.removed += 1,
                Rec::Invalid => {
                    self.invalid += 1;
                    self.faithful = false;
                }
            }
        }
        if p != data.len() {
            self.faithful = false;
        }
        (!out.is_empty()).then_some(out)
    }

    fn record(&mut self, t: u16, flags: u16, b: &[u8]) -> Rec {
        let keep = |v: Option<Vec<u8>>| match v {
            Some(v) => Rec::Keep(flags, v),
            None => Rec::Invalid,
        };
        let exact = |n: usize| (b.len() >= n).then(|| b[..n].to_vec());
        let id = u32::from(flags & 0xFF);
        let compressed = flags & 0x4000 != 0;
        // 상대 좌표(P 플래그)는 가변 길이라 옮기지 않는다
        if flags & 0x0800 != 0 && matches!(t, 0x400C | 0x400D | 0x4016..=0x4019 | 0x401B) {
            return Rec::Invalid;
        }
        let ps = if compressed { 4 } else { 8 };
        let rs = if compressed { 8 } else { 16 };
        match t {
            // 머리글: 버전·플래그·논리 DPI
            0x4001 => {
                let mut c = Cur::new(b);
                keep((|| {
                    version(&mut c)?;
                    c.take(12)?;
                    Some(c.done().to_vec())
                })())
            }
            0x4002 | 0x4004 | 0x401E..=0x4024 | 0x402B | 0x4031 | 0x4037 => {
                if t == 0x4037 && !self.is(id, OBJ_PATH) {
                    return Rec::Invalid;
                }
                Rec::Keep(flags, Vec::new())
            }
            // 주석, 다중 형식, 직렬화 개체(효과), 원격 데스크톱 상태
            0x4003 | 0x4005..=0x4007 | 0x4038..=0x403A => Rec::Harmless,
            0x4008 => {
                // 여러 레코드로 나뉜 개체(C 플래그)는 옮기지 않는다
                let obj = (flags >> 8 & 0x7F) as u8;
                if flags & 0x8000 != 0 || id as usize >= MAX_OBJECTS {
                    if (id as usize) < MAX_OBJECTS {
                        self.objects[id as usize] = 0;
                    }
                    return Rec::Invalid;
                }
                match self.object(obj, b) {
                    Some(v) => {
                        self.objects[id as usize] = obj;
                        Rec::Keep(flags, v)
                    }
                    None => {
                        self.objects[id as usize] = 0;
                        Rec::Invalid
                    }
                }
            }
            0x4009 => keep(exact(4)),
            // FillRects / DrawRects
            0x400A | 0x400B => {
                let mut c = Cur::new(b);
                keep((|| {
                    if t == 0x400A {
                        let br = c.u32()?;
                        self.brush(flags, br).then_some(())?;
                    } else {
                        self.is(id, OBJ_PEN).then_some(())?;
                    }
                    let n = c.u32()?;
                    array(&mut c, n, rs)?;
                    Some(c.done().to_vec())
                })())
            }
            // FillPolygon / DrawLines / DrawBeziers
            0x400C | 0x400D | 0x4019 => {
                let mut c = Cur::new(b);
                keep((|| {
                    if t == 0x400C {
                        let br = c.u32()?;
                        self.brush(flags, br).then_some(())?;
                    } else {
                        self.is(id, OBJ_PEN).then_some(())?;
                    }
                    let n = c.u32()?;
                    array(&mut c, n, ps)?;
                    Some(c.done().to_vec())
                })())
            }
            // FillEllipse / DrawEllipse / FillPie / DrawPie / DrawArc
            0x400E..=0x4012 => {
                let mut c = Cur::new(b);
                keep((|| {
                    if t == 0x400E || t == 0x4010 {
                        let br = c.u32()?;
                        self.brush(flags, br).then_some(())?;
                    } else {
                        self.is(id, OBJ_PEN).then_some(())?;
                    }
                    if t >= 0x4010 {
                        c.f32()?;
                        c.f32()?;
                    }
                    c.take(rs)?;
                    Some(c.done().to_vec())
                })())
            }
            // FillRegion / FillPath / DrawPath
            0x4013..=0x4015 => {
                let mut c = Cur::new(b);
                keep((|| {
                    let obj = if t == 0x4013 { OBJ_REGION } else { OBJ_PATH };
                    self.is(id, obj).then_some(())?;
                    let v = c.u32()?;
                    if t == 0x4015 {
                        self.is(v, OBJ_PEN).then_some(())?;
                    } else {
                        self.brush(flags, v).then_some(())?;
                    }
                    Some(c.done().to_vec())
                })())
            }
            // FillClosedCurve / DrawClosedCurve / DrawCurve
            0x4016..=0x4018 => {
                let mut c = Cur::new(b);
                keep((|| {
                    if t == 0x4016 {
                        let br = c.u32()?;
                        self.brush(flags, br).then_some(())?;
                    } else {
                        self.is(id, OBJ_PEN).then_some(())?;
                    }
                    c.f32()?; // Tension
                    let (off, seg) = if t == 0x4018 {
                        (c.u32()?, c.u32()?)
                    } else {
                        (0, 0)
                    };
                    let n = c.u32()?;
                    if t == 0x4018 && u64::from(off) + u64::from(seg) >= u64::from(n.max(1)) {
                        return None;
                    }
                    array(&mut c, n, ps)?;
                    Some(c.done().to_vec())
                })())
            }
            // DrawImage / DrawImagePoints
            0x401A | 0x401B => {
                let mut c = Cur::new(b);
                keep((|| {
                    self.is(id, OBJ_IMAGE).then_some(())?;
                    let attr = c.u32()?;
                    if attr != 0 && !self.is(attr, OBJ_IMAGE_ATTRIBUTES) {
                        return None;
                    }
                    c.u32()?; // SrcUnit
                    for _ in 0..4 {
                        c.f32()?;
                    }
                    if t == 0x401A {
                        c.take(rs)?;
                    } else {
                        (c.u32()? == 3).then_some(())?;
                        c.take(3 * ps)?;
                    }
                    Some(c.done().to_vec())
                })())
            }
            // DrawString
            0x401C => {
                let mut c = Cur::new(b);
                keep((|| {
                    self.is(id, OBJ_FONT).then_some(())?;
                    let br = c.u32()?;
                    self.brush(flags, br).then_some(())?;
                    let fmt = c.u32()?;
                    if fmt != u32::MAX && fmt != 0 && !self.is(fmt, OBJ_STRING_FORMAT) {
                        return None;
                    }
                    let len = c.u32()?;
                    for _ in 0..4 {
                        c.f32()?;
                    }
                    array(&mut c, len, 2)?;
                    Some(c.done().to_vec())
                })())
            }
            0x401D | 0x402D | 0x402E | 0x4035 => keep(exact(8)),
            0x4025 | 0x4026 | 0x4028 | 0x4029 | 0x402F | 0x4030 => keep(exact(4)),
            0x4027 => keep(exact(36)),
            0x402A | 0x402C => {
                let mut c = Cur::new(b);
                keep((|| {
                    for _ in 0..6 {
                        c.f32()?;
                    }
                    Some(c.done().to_vec())
                })())
            }
            0x4032 => keep(exact(16)),
            0x4033 => keep(self.is(id, OBJ_PATH).then(Vec::new)),
            0x4034 => keep(self.is(id, OBJ_REGION).then(Vec::new)),
            // DrawDriverString
            0x4036 => {
                let mut c = Cur::new(b);
                keep((|| {
                    self.is(id, OBJ_FONT).then_some(())?;
                    let br = c.u32()?;
                    self.brush(flags, br).then_some(())?;
                    c.u32()?; // 옵션
                    let matrix = c.u32()?;
                    let n = c.u32()?;
                    array(&mut c, n, 2)?;
                    array(&mut c, n, 8)?;
                    if matrix != 0 {
                        c.take(24)?;
                    }
                    Some(c.done().to_vec())
                })())
            }
            _ => Rec::Invalid,
        }
    }

    fn object(&mut self, kind: u8, b: &[u8]) -> Option<Vec<u8>> {
        let mut c = Cur::new(b);
        match kind {
            OBJ_BRUSH => {
                brush(&mut c)?;
                Some(c.done().to_vec())
            }
            OBJ_PEN => {
                version(&mut c)?;
                (c.u32()? == 0).then_some(())?;
                let fl = c.u32()?;
                // 사용자 선 끝(CustomStartCap/EndCap)은 옮기지 않는다
                if fl & !0x07FF != 0 {
                    return None;
                }
                c.u32()?; // 단위
                c.f32()?; // 굵기
                if fl & 0x01 != 0 {
                    c.take(24)?;
                }
                for bit in [0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80] {
                    if fl & bit != 0 {
                        c.u32()?;
                    }
                }
                if fl & 0x100 != 0 {
                    let n = c.u32()?;
                    array(&mut c, n, 4)?;
                }
                if fl & 0x200 != 0 {
                    c.u32()?;
                }
                if fl & 0x400 != 0 {
                    let n = c.u32()?;
                    array(&mut c, n, 4)?;
                }
                brush(&mut c)?;
                Some(c.done().to_vec())
            }
            OBJ_PATH => {
                path(&mut c)?;
                Some(c.done().to_vec())
            }
            OBJ_REGION => {
                version(&mut c)?;
                let n = c.u32()?;
                let mut left = n as usize + 1;
                region_node(&mut c, 0, &mut left)?;
                Some(c.done().to_vec())
            }
            OBJ_IMAGE => self.image(&mut c),
            OBJ_FONT => {
                version(&mut c)?;
                c.f32()?; // EmSize
                c.u32()?; // 단위
                c.u32()?; // 스타일
                c.u32()?; // 예약
                let len = c.u32()?;
                if len > 256 {
                    return None;
                }
                array(&mut c, len, 2)?;
                Some(c.done().to_vec())
            }
            OBJ_STRING_FORMAT => {
                version(&mut c)?;
                c.take(48)?;
                let tabs = c.u32()?;
                let ranges = c.u32()?;
                array(&mut c, tabs, 4)?;
                array(&mut c, ranges, 8)?;
                Some(c.done().to_vec())
            }
            OBJ_IMAGE_ATTRIBUTES => {
                version(&mut c)?;
                c.take(20)?;
                Some(c.done().to_vec())
            }
            _ => None,
        }
    }

    /// 이미지 개체: 압축 비트맵은 재인코딩, 원시 화소는 크기 검증. 메타파일은 옮기지 않는다
    fn image(&mut self, c: &mut Cur) -> Option<Vec<u8>> {
        let ver = version(c)?;
        (c.u32()? == 1).then_some(())?; // 비트맵만
        let w = c.u32()?;
        let h = c.u32()?;
        let stride = c.u32()?;
        let format = c.u32()?;
        let kind = c.u32()?;
        let px = u64::from(w).checked_mul(u64::from(h))?;
        if w == 0 || h == 0 || px > self.policy.max_image_pixels {
            return None;
        }
        let rest = &c.d[c.p..];
        let mut out = Vec::new();
        for v in [ver, 1, w, h] {
            out.extend(v.to_le_bytes());
        }
        match kind {
            // 압축 비트맵
            1 => {
                let k = ImageKind::sniff(rest)?;
                self.budget.charge(rest, k).ok()?;
                let (bytes, _) = imaging::reencode(rest, k, self.policy).ok()?;
                out.extend(0u32.to_le_bytes()); // Stride
                out.extend(0u32.to_le_bytes()); // PixelFormat
                out.extend(1u32.to_le_bytes());
                out.extend(bytes);
            }
            // 원시 화소
            0 => {
                let bpp = format >> 8 & 0xFF;
                if !matches!(bpp, 1 | 4 | 8 | 16 | 24 | 32 | 48 | 64) || format >> 24 != 0 {
                    return None;
                }
                let row = (u64::from(w) * u64::from(bpp)).div_ceil(8);
                if u64::from(stride) < row || stride % 4 != 0 {
                    return None;
                }
                self.budget.charge_pixels(px).ok()?;
                let mut d = Cur::new(rest);
                // 색인 형식이면 앞에 색상표
                if format & 0x0001_0000 != 0 {
                    d.u32()?;
                    let n = d.u32()?;
                    if n > 256 {
                        return None;
                    }
                    array(&mut d, n, 4)?;
                }
                d.take(usize::try_from(u64::from(stride) * u64::from(h)).ok()?)?;
                for v in [stride, format, 0] {
                    out.extend(v.to_le_bytes());
                }
                out.extend(d.done());
            }
            _ => return None,
        }
        self.images += 1;
        Some(out)
    }
}

enum Rec {
    Keep(u16, Vec<u8>),
    /// 옮기지 않아도 그림이 달라지지 않는 레코드
    Harmless,
    Invalid,
}

/// 브러시: 단색·해치·선형 그라데이션만
fn brush(c: &mut Cur) -> Option<()> {
    version(c)?;
    match c.u32()? {
        0 => {
            c.u32()?;
        }
        1 => {
            c.take(12)?;
        }
        4 => {
            let fl = c.u32()?;
            // 변환·미리 정한 색·혼합 계수·감마 보정만
            if fl & !(0x02 | 0x04 | 0x08 | 0x10 | 0x40) != 0 {
                return None;
            }
            c.u32()?; // WrapMode
            for _ in 0..4 {
                c.f32()?;
            }
            c.take(16)?; // 시작·끝 색, 예약
            if fl & 0x02 != 0 {
                c.take(24)?;
            }
            if fl & 0x04 != 0 {
                let n = c.u32()?;
                array(c, n, 4)?;
                array(c, n, 4)?;
            }
            for bit in [0x08, 0x10] {
                if fl & bit != 0 {
                    let n = c.u32()?;
                    array(c, n, 4)?;
                    array(c, n, 4)?;
                }
            }
        }
        // 텍스처(이미지 포함)·경로 그라데이션은 옮기지 않는다
        _ => return None,
    }
    Some(())
}

/// 경로: 점과 점 종류
fn path(c: &mut Cur) -> Option<()> {
    version(c)?;
    let n = c.u32()?;
    let fl = c.u32()?;
    // 상대 좌표(R)는 옮기지 않는다
    if fl & 0x1000 != 0 {
        return None;
    }
    let ps = if fl & 0x4000 != 0 { 4 } else { 8 };
    array(c, n, ps)?;
    let types = array(c, n, 1)?;
    if types
        .iter()
        .any(|&t| !matches!(t & 0x0F, 0 | 1 | 3) || t & 0x40 != 0)
    {
        return None;
    }
    // 4바이트 정렬
    let pad = (4 - (n as usize % 4)) % 4;
    let _ = c.take(pad);
    Some(())
}

fn region_node(c: &mut Cur, depth: usize, left: &mut usize) -> Option<()> {
    if depth > MAX_REGION_DEPTH || *left == 0 {
        return None;
    }
    *left -= 1;
    match c.u32()? {
        1..=5 => {
            region_node(c, depth + 1, left)?;
            region_node(c, depth + 1, left)?;
        }
        0x1000_0000 => {
            for _ in 0..4 {
                c.f32()?;
            }
        }
        0x1000_0001 => {
            let len = c.u32()? as usize;
            let start = c.p;
            path(c)?;
            if c.p - start > len {
                return None;
            }
            c.p = start;
            c.take(len)?;
        }
        0x1000_0002 | 0x1000_0003 => {}
        _ => return None,
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(t: u16, flags: u16, data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(t.to_le_bytes());
        v.extend(flags.to_le_bytes());
        v.extend(((12 + data.len().div_ceil(4) * 4) as u32).to_le_bytes());
        v.extend((data.len() as u32).to_le_bytes());
        v.extend(data);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    fn ver() -> Vec<u8> {
        0xDBC0_1002u32.to_le_bytes().to_vec()
    }

    #[test]
    fn records_are_validated() {
        let policy = Policy::default();
        let mut budget = PixelBudget::new(&policy);
        let mut ctx = PlusCtx::new(&policy, &mut budget);
        let mut s = Vec::new();
        let mut header = ver();
        header.extend([1, 0, 0, 0, 96, 0, 0, 0, 96, 0, 0, 0]);
        s.extend(rec(0x4001, 1, &header));
        // 단색 브러시 0번
        let mut brush = ver();
        brush.extend(0u32.to_le_bytes());
        brush.extend(0xFF00_00FFu32.to_le_bytes());
        s.extend(rec(0x4008, 0x0100, &brush));
        // 사각형 칠하기 (압축 좌표)
        let mut fill = 0u32.to_le_bytes().to_vec();
        fill.extend(1u32.to_le_bytes());
        fill.extend([0, 0, 0, 0, 10, 0, 10, 0]);
        s.extend(rec(0x400A, 0x4000, &fill));
        s.extend(rec(0x4003, 0, b"secret comment"));
        let out = ctx.comment(&s).unwrap();
        assert!(ctx.faithful);
        assert_eq!(ctx.kept, 3);
        assert!(!out.windows(6).any(|w| w == b"secret"));
        // 없는 브러시를 가리키면 옮기지 않고, 그림이 달라지므로 EMF+ 전체를 뺀다
        let mut bad = 5u32.to_le_bytes().to_vec();
        bad.extend(1u32.to_le_bytes());
        bad.extend([0; 8]);
        ctx.comment(&rec(0x400A, 0x4000, &bad));
        assert!(!ctx.faithful);
    }

    #[test]
    fn counts_and_region_depth() {
        let policy = Policy::default();
        let mut budget = PixelBudget::new(&policy);
        let mut ctx = PlusCtx::new(&policy, &mut budget);
        // 경로: 점 개수가 데이터보다 많음
        let mut path = ver();
        path.extend(1000u32.to_le_bytes());
        path.extend(0x4000u32.to_le_bytes());
        path.extend([0; 8]);
        ctx.comment(&rec(0x4008, 0x0300, &path));
        assert_eq!(ctx.invalid, 1);
        // 영역: 끝없이 중첩된 노드
        let mut region = ver();
        region.extend(1000u32.to_le_bytes());
        for _ in 0..200 {
            region.extend(1u32.to_le_bytes());
        }
        ctx.comment(&rec(0x4008, 0x0401, &region));
        assert_eq!(ctx.invalid, 2);
    }
}
