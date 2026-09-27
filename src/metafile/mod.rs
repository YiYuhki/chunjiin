//! 메타파일(EMF/WMF) 재조합.
//!
//! 메타파일은 그리기 명령(GDI 레코드)을 나열한 벡터 그림이다. 이스케이프·주석 레코드와 형식 불일치
//! 레코드는 GDI·렌더러 취약점 악용 경로로 자주 쓰였다. 레코드를 하나씩 해석해 **허용 목록의 그리기
//! 레코드만** 검증된 정규형으로 새 메타파일에 다시 쓴다.
//!
//! - 머리글은 새로 만든다(설명 문자열·픽셀 형식·OpenGL 정보 없음, 크기·레코드 수 재계산)
//! - 좌표 배열 레코드는 개수와 레코드 크기가 맞는지 확인하고 선언된 만큼만 옮긴다
//! - 개체 번호(핸들)는 머리글의 개체 표 범위 안이어야 한다
//! - 비트맵은 헤더·색상표·화소 크기를 검증해 정규형 DIB 로 다시 쓰고, 압축(RLE/JPEG/PNG)은 풀어서 쓴다
//! - EMF+ 레코드는 개체·좌표·경로·영역·비트맵을 검증해 옮기고, 하나라도 옮길 수 없으면 EMF+ 전체를 뺀다
//! - 일반 주석·이스케이프·색 프로필·OpenGL·미지원 레코드는 옮기지 않는다

mod dib;
mod emf;
mod emfplus;
mod wmf;

use crate::error::Result;

/// 메타파일 안의 메타파일(EMF+ 메타파일 이미지, WMF 이스케이프의 EMF)을 푸는 깊이. 안쪽 데이터는
/// 바깥 데이터의 일부이므로 처리량은 깊이에 비례한다 (Office 는 로고 등을 3단계까지 겹쳐 쓰기도 한다)
pub(super) const MAX_NESTED: usize = 4;
use crate::legacy::blip::PixelBudget;
use crate::policy::Policy;
use crate::report::{Findings, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Emf,
    Wmf,
}

impl Kind {
    pub fn extension(self) -> &'static str {
        match self {
            Kind::Emf => "emf",
            Kind::Wmf => "wmf",
        }
    }

    pub fn mime(self) -> &'static str {
        match self {
            Kind::Emf => "image/x-emf",
            Kind::Wmf => "image/x-wmf",
        }
    }
}

pub fn sniff(data: &[u8]) -> Option<Kind> {
    if emf::is_emf(data) {
        Some(Kind::Emf)
    } else if wmf::is_wmf(data) {
        Some(Kind::Wmf)
    } else {
        None
    }
}

/// 재조합 통계
#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub metafiles: u64,
    pub records: u64,
    /// 옮기지 않은 레코드: 주석(EMF+ 포함)·이스케이프·미지원 레코드
    pub removed: u64,
    /// 형식이 맞지 않아 버린 레코드: 개체 번호 범위 밖, 개수·크기 불일치, 깨진 비트맵 등
    pub invalid: u64,
    pub bitmaps: u64,
    /// GDI 레코드 없이 EMF+ 로만 그려진 그림 (EMF+ 를 버리면 비어 보일 수 있음)
    pub emf_plus_only: u64,
    /// 검증해 옮긴 EMF+ 레코드
    pub emf_plus_records: u64,
    /// 다시 만든 안쪽 메타파일 (EMF+ 메타파일 이미지, WMF 내장 EMF)
    pub nested: u64,
}

impl Stats {
    pub fn add(&mut self, o: &Stats) {
        self.metafiles += o.metafiles;
        self.records += o.records;
        self.removed += o.removed;
        self.invalid += o.invalid;
        self.bitmaps += o.bitmaps;
        self.emf_plus_only += o.emf_plus_only;
        self.emf_plus_records += o.emf_plus_records;
        self.nested += o.nested;
    }

    pub fn report(&self, findings: &mut Findings, location: &str) {
        if self.metafiles == 0 {
            return;
        }
        findings.count("metafiles_rebuilt", self.metafiles);
        if self.emf_plus_records > 0 {
            findings.count("emf_plus_records", self.emf_plus_records);
        }
        if self.invalid > 0 {
            findings.add(
                "metafile",
                Severity::Medium,
                format!(
                    "형식이 맞지 않는 메타파일 레코드 {}개 제거 (개체 번호 범위·개수·크기 불일치 등)",
                    self.invalid
                ),
                location,
            );
        }
        if self.removed > 0 {
            findings.add(
                "metafile",
                Severity::Low,
                format!(
                    "메타파일의 주석·이스케이프·미지원 레코드 {}개를 옮기지 않음",
                    self.removed
                ),
                location,
            );
        }
        if self.emf_plus_only > 0 {
            findings.add(
                "metafile",
                Severity::Low,
                format!(
                    "EMF+ 전용 그림 {}개: 검증할 수 없는 EMF+ 레코드가 있어 EMF+ 를 옮기지 않았고 비어 보일 수 있음",
                    self.emf_plus_only
                ),
                location,
            );
        }
    }
}

/// 메타파일을 재조합한다. 형식을 알 수 없거나 구조가 깨졌으면 차단 오류.
/// `budget` 은 안에 든 비트맵의 화소 수를 문서 단위로 누적한다.
pub fn rebuild(
    data: &[u8],
    policy: &Policy,
    budget: &mut PixelBudget,
    stats: &mut Stats,
) -> Result<(Vec<u8>, Kind)> {
    let mut s = Stats::default();
    let out = match sniff(data) {
        Some(Kind::Emf) => (emf::rebuild(data, policy, budget, &mut s)?, Kind::Emf),
        Some(Kind::Wmf) => (wmf::rebuild(data, policy, budget, &mut s)?, Kind::Wmf),
        None => return crate::error::blocked("metafile", "메타파일 형식이 아님"),
    };
    s.metafiles = 1;
    stats.add(&s);
    Ok(out)
}

/// 작은 재조합 (제자리 처리에서 자리가 모자랄 때): EMF+ 를 빼고 GDI 로만 그리고, WMF 내장 EMF 는 뺀다
pub fn rebuild_shallow(
    data: &[u8],
    policy: &Policy,
    budget: &mut PixelBudget,
    stats: &mut Stats,
) -> Result<(Vec<u8>, Kind)> {
    let mut s = Stats::default();
    let out = match sniff(data) {
        Some(Kind::Emf) => (
            emf::rebuild_nested(data, policy, budget, &mut s, MAX_NESTED + 1)?,
            Kind::Emf,
        ),
        Some(Kind::Wmf) => (
            wmf::rebuild_nested(data, policy, budget, &mut s, MAX_NESTED + 1)?,
            Kind::Wmf,
        ),
        None => return crate::error::blocked("metafile", "메타파일 형식이 아님"),
    };
    s.metafiles = 1;
    stats.add(&s);
    Ok(out)
}

/// 단독 메타파일 재조합 (엔진 진입점)
pub fn reassemble(data: &[u8], policy: &Policy, findings: &mut Findings) -> Result<Vec<u8>> {
    let mut budget = PixelBudget::new(policy);
    let mut stats = Stats::default();
    let (out, _) = rebuild(data, policy, &mut budget, &mut stats)?;
    stats.report(findings, "/");
    Ok(out)
}

/// 아무것도 그리지 않는 메타파일 (자리에 맞게 줄일 수 없는 그림의 대체용)
pub fn empty(kind: Kind) -> Vec<u8> {
    let mut v = Vec::new();
    match kind {
        Kind::Emf => {
            v.extend(1u32.to_le_bytes());
            v.extend(108u32.to_le_bytes());
            v.extend([0; 32]); // Bounds, Frame
            v.extend(0x464D_4520u32.to_le_bytes());
            v.extend(0x0001_0000u32.to_le_bytes());
            v.extend(128u32.to_le_bytes()); // Bytes
            v.extend(2u32.to_le_bytes()); // Records
            v.extend(1u16.to_le_bytes()); // Handles
            v.extend([0; 2 + 12]);
            for d in [1i32, 1, 1, 1] {
                v.extend(d.to_le_bytes()); // Device, Millimeters
            }
            v.extend([0; 12]);
            v.extend([0xE8, 3, 0, 0, 0xE8, 3, 0, 0]); // Micrometers
            for d in [14u32, 20, 0, 16, 20] {
                v.extend(d.to_le_bytes());
            }
        }
        Kind::Wmf => {
            for w in [1u16, 9, 0x0300, 12, 0, 0, 3, 0, 0, 3, 0, 0] {
                v.extend(w.to_le_bytes());
            }
        }
    }
    v
}

/// 리틀 엔디언 읽기 도우미 (범위를 벗어나면 None)
mod rd {
    pub fn u16(d: &[u8], at: usize) -> Option<u16> {
        Some(u16::from_le_bytes(
            d.get(at..at.checked_add(2)?)?.try_into().ok()?,
        ))
    }
    pub fn u32(d: &[u8], at: usize) -> Option<u32> {
        Some(u32::from_le_bytes(
            d.get(at..at.checked_add(4)?)?.try_into().ok()?,
        ))
    }
    pub fn i32(d: &[u8], at: usize) -> Option<i32> {
        Some(i32::from_le_bytes(
            d.get(at..at.checked_add(4)?)?.try_into().ok()?,
        ))
    }
    pub fn slice(d: &[u8], at: usize, len: usize) -> Option<&[u8]> {
        d.get(at..at.checked_add(len)?)
    }
}

fn pad4(v: &mut Vec<u8>) {
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
}
