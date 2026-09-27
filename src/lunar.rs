//! 음력(한국·중국·일본)·히즈라력 ↔ 양력 변환.
//!
//! - 태음태양력(한국·중국·일본): 해마다 달의 길이(큰달·작은달)·윤달·설날 위치를 표로 둔다.
//!   한국 1900~2049년은 한국천문연구원 자료 기반 `korean-lunar-calendar`, 중국은 `lunardate` 에서
//!   만들었다. 한국 2050~2098년과 일본은 동경 135°(UTC+9) 천문 계산(합삭·중기, 동지가 든 달이
//!   11월, 중기 없는 첫 달이 윤달)으로 만들었고, 이 계산은 한국 자료 1912~2049년·중국 자료의 현대
//!   연도와 모두 일치한다. 한국과 중국은 기준 경도가 달라 같은 해에도 달의 길이가 다를 수 있다.
//! - 움 알쿠라 히즈라력(사우디): `hijri-converter` 자료 1365~1500 AH (1945~2077년).
//! - 계산식 히즈라력: Windows 가 쓰는 쿠웨이트 알고리즘(30년 주기 윤년, 기원 622-07-16 율리우스력).

/// 음력·히즈라력 날짜
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LunarDate {
    pub year: i64,
    pub month: u32,
    pub leap: bool,
    pub day: u32,
}

/// 달력
#[derive(Clone, Copy)]
pub enum Calendar {
    /// 태음태양력 표 (1900년부터)
    Lunisolar(&'static [u32]),
    UmmAlQura,
    TabularHijri,
}

pub const KOREAN_CAL: Calendar = Calendar::Lunisolar(&KOREAN);
pub const CHINESE_CAL: Calendar = Calendar::Lunisolar(&CHINESE);
pub const JAPANESE_CAL: Calendar = Calendar::Lunisolar(&JAPANESE);
pub const UMM_AL_QURA_CAL: Calendar = Calendar::UmmAlQura;
pub const HIJRI_CAL: Calendar = Calendar::TabularHijri;

const LUNISOLAR_FIRST: i64 = 1900;
const UMM_AL_QURA_FIRST: i64 = 1365;

/// 1970-01-01 부터의 일수
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

/// 1970-01-01 부터의 일수 → 양력 연도
fn civil_year(days: i64) -> i64 {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    yoe + era * 400 + i64::from(month <= 2)
}

/// 히즈라 기원 (율리우스력 622-07-16 = 그레고리력 622-07-19)
fn hijri_epoch() -> i64 {
    days_from_civil(622, 7, 19)
}

/// 계산식 히즈라력의 설날
fn tabular_new_year(y: i64) -> i64 {
    hijri_epoch() + 354 * (y - 1) + (3 + 11 * y).div_euclid(30)
}

/// 그해 설날(1970-01-01 부터 일수)과 달들 (월, 윤달, 일수)
type YearInfo = (i64, Vec<(u32, bool, u32)>);

impl Calendar {
    /// 요약에 쓰는 이름
    pub fn label(&self) -> &'static str {
        match self {
            Calendar::Lunisolar(_) => "음력",
            _ => "히즈라력",
        }
    }

    /// 그해 설날(1970-01-01 부터 일수)과 달들 (월, 윤달, 일수)
    fn year(&self, year: i64) -> Option<YearInfo> {
        let flag = |e: u32, i: usize| if e & (1 << i) != 0 { 30 } else { 29 };
        match self {
            Calendar::Lunisolar(t) => {
                let e = *t.get(usize::try_from(year - LUNISOLAR_FIRST).ok()?)?;
                let leap = (e >> 13) & 0xF;
                let mut months = Vec::with_capacity(13);
                for m in 1..=12 {
                    months.push((m, false));
                    if m == leap {
                        months.push((m, true));
                    }
                }
                let ny = days_from_civil(year, 1, 1) + i64::from(e >> 17);
                Some((
                    ny,
                    months
                        .into_iter()
                        .enumerate()
                        .map(|(i, (m, l))| (m, l, flag(e, i)))
                        .collect(),
                ))
            }
            Calendar::UmmAlQura => {
                let e = *UMM_AL_QURA.get(usize::try_from(year - UMM_AL_QURA_FIRST).ok()?)?;
                let ny = i64::from(e >> 12) - 20_000;
                Some((
                    ny,
                    (1..=12)
                        .map(|m| (m, false, flag(e, m as usize - 1)))
                        .collect(),
                ))
            }
            Calendar::TabularHijri => {
                if !(1..=9999).contains(&year) {
                    return None;
                }
                let leap = (14 + 11 * year).rem_euclid(30) < 11;
                let months = (1..=12u32)
                    .map(|m| {
                        (
                            m,
                            false,
                            if m % 2 == 1 || (m == 12 && leap) {
                                30
                            } else {
                                29
                            },
                        )
                    })
                    .collect();
                Some((tabular_new_year(year), months))
            }
        }
    }

    /// 그 날이 속한 해
    fn year_of(&self, days: i64) -> Option<i64> {
        let mut y = match self {
            Calendar::Lunisolar(_) => civil_year(days),
            _ => (days - hijri_epoch()) * 30 / 10_631 + 1,
        };
        for _ in 0..4 {
            if days < self.year(y)?.0 {
                y -= 1;
            } else if self.year(y + 1).is_some_and(|(ny, _)| days >= ny) {
                y += 1;
            } else {
                return Some(y);
            }
        }
        None
    }

    /// 양력(1970-01-01 부터의 일수) → 이 달력의 날짜
    pub fn to_lunar(&self, days: i64) -> Option<LunarDate> {
        let year = self.year_of(days)?;
        let (mut at, months) = self.year(year)?;
        for (month, leap, len) in months {
            if days < at + i64::from(len) {
                return Some(LunarDate {
                    year,
                    month,
                    leap,
                    day: (days - at) as u32 + 1,
                });
            }
            at += i64::from(len);
        }
        None
    }

    /// 달의 첫날(양력 일수)과 일수. 없는 달(윤달이 아닌 해의 윤달 등)이면 None
    pub fn month_start(&self, year: i64, month: u32, leap: bool) -> Option<(i64, u32)> {
        let (mut at, months) = self.year(year)?;
        for (m, l, len) in months {
            if m == month && l == leap {
                return Some((at, len));
            }
            at += i64::from(len);
        }
        None
    }

    /// 연·월 뒤로 `n` 달 (윤달도 한 달로 센다)
    pub fn add_months(
        &self,
        year: i64,
        month: u32,
        leap: bool,
        n: u32,
    ) -> Option<(i64, u32, bool)> {
        let mut y = year;
        let mut months = self.year(y)?.1;
        let mut idx = months
            .iter()
            .position(|&(m, l, _)| m == month && l == leap)?;
        for _ in 0..n {
            idx += 1;
            if idx >= months.len() {
                y += 1;
                months = self.year(y)?.1;
                idx = 0;
            }
        }
        let (m, l, _) = months[idx];
        Some((y, m, l))
    }
}

/// 해마다(1900년부터): 비트 0~12 달 순서대로 큰달(30일), 13~16 윤달(그 달 뒤), 17~ 설날의 그해 1월 1일부터 일수. 1900~2049년은 한국천문연구원 자료, 2050~2098년은 동경 135°(UTC+9) 천문 계산(1912~2049년 자료와 모두 일치)
const KOREAN: [u32; 199] = [
    0x03d16d2, 0x0620752, 0x04c0ea5, 0x038b64a, 0x05c064b, 0x0440a9b, 0x0309556, 0x056056a,
    0x0400b59, 0x02a5752, 0x0500752, 0x03adb25, 0x0600b25, 0x0480a4b, 0x032b29b, 0x0580aad,
    0x044056a, 0x02c4b69, 0x0520ba9, 0x03efb52, 0x0640d92, 0x04c0d25, 0x036ba4d, 0x05c0956,
    0x04602b5, 0x02e95ad, 0x05606d4, 0x0400da9, 0x02c5d92, 0x0500e92, 0x03acd26, 0x05e0527,
    0x0480a57, 0x032b2b6, 0x0580ada, 0x04406d4, 0x02e6ea9, 0x0520749, 0x03cf693, 0x0620a93,
    0x04c052b, 0x034ca5b, 0x05a096d, 0x0460b6a, 0x0329b54, 0x0560ba4, 0x0400b49, 0x02a5a93,
    0x0500a95, 0x038f52b, 0x05e052d, 0x0480aad, 0x034b56a, 0x0580db2, 0x0440da4, 0x02e7d49,
    0x0540d4a, 0x03d1a95, 0x0620a96, 0x04c0556, 0x036cab5, 0x05a0ad5, 0x04606d2, 0x0308ea5,
    0x0560ea5, 0x0400e4a, 0x02a6c96, 0x04e0a9b, 0x03af556, 0x05e056a, 0x0480b59, 0x034b752,
    0x05a0752, 0x0420725, 0x02c964b, 0x0520a4b, 0x03d12ab, 0x06002ad, 0x04a056b, 0x036cb69,
    0x05c0da9, 0x0460d92, 0x0309b25, 0x0560d25, 0x0415a4d, 0x0640a56, 0x04e02b6, 0x038d5ad,
    0x06006d4, 0x0480da9, 0x034bd92, 0x05a0e92, 0x0440d26, 0x02c6a56, 0x0500a57, 0x03d12b6,
    0x0620b5a, 0x04c06d4, 0x036aec9, 0x05c0749, 0x0460693, 0x02e9527, 0x054052b, 0x03e0a5b,
    0x02a555a, 0x04e036a, 0x038fb55, 0x0600ba4, 0x04a0b49, 0x032ba93, 0x0580a95, 0x042052d,
    0x02c6a5d, 0x0500aad, 0x03d35aa, 0x06205d2, 0x04c0da5, 0x036bd4a, 0x05c0d4a, 0x0460a95,
    0x030952d, 0x0540556, 0x03e0ab5, 0x02a55aa, 0x05006d2, 0x038cea5, 0x05e0ea5, 0x04a0e4a,
    0x034ac96, 0x0560c9b, 0x042055a, 0x02c6ad5, 0x0520b69, 0x03d7752, 0x0620752, 0x04c0b25,
    0x036d64b, 0x05a0a4b, 0x04404ab, 0x02ea55b, 0x054056d, 0x03e0b69, 0x02a5b52, 0x0500d92,
    0x03afd25, 0x05e0d25, 0x0480a4d, 0x032b4ad, 0x05802b6, 0x04005b5, 0x02c6da9, 0x0520ea9,
    0x03f1d92, 0x0620e92, 0x04c0d26, 0x036ca56, 0x05a0a57, 0x04404d6, 0x02e86b5, 0x05406d5,
    0x0400ec9, 0x02a6e92, 0x04e0693, 0x038f52b, 0x05e052b, 0x0460a5b, 0x032b55a, 0x058056a,
    0x0420b55, 0x02c9749, 0x0520b49, 0x03d1a93, 0x0620a95, 0x04a052d, 0x034caad, 0x05a0ab5,
    0x04605aa, 0x02e8ba5, 0x0540da5, 0x0400d4a, 0x02a7a95, 0x04e0c95, 0x038f52e, 0x05e0556,
    0x0480ab5, 0x032b5b2, 0x05806d2, 0x0420ea5, 0x02e9e4a, 0x052064a, 0x03b0c97, 0x0600cab,
    0x04c055a, 0x034cad5, 0x05a0b69, 0x0460752, 0x03096a5, 0x0540b25, 0x03e064b,
];

/// 해마다(1900년부터): 비트 0~12 달 순서대로 큰달(30일), 13~16 윤달(그 달 뒤), 17~ 설날의 그해 1월 1일부터 일수. lunardate(UTC+8)
const CHINESE: [u32; 199] = [
    0x03d16d2, 0x0620752, 0x04c0ea5, 0x038b64a, 0x05c064b, 0x0440a9b, 0x0309556, 0x056056a,
    0x0400b59, 0x02a5752, 0x0500752, 0x03adb25, 0x0600b25, 0x0480a4b, 0x032b4ab, 0x05802ad,
    0x042056b, 0x02c4b69, 0x0520da9, 0x03efd92, 0x0640e92, 0x04c0d25, 0x036ba4d, 0x05c0a56,
    0x04602b6, 0x02e95b5, 0x05606d4, 0x0400ea9, 0x02c5e92, 0x0500e92, 0x03acd26, 0x05e052b,
    0x0480a57, 0x032b2d6, 0x0580b5a, 0x04406d4, 0x02e6ec9, 0x0520749, 0x03cf693, 0x0620a93,
    0x04c052b, 0x034ca5b, 0x05a0aad, 0x046056a, 0x0309b55, 0x0560ba4, 0x0400b49, 0x02a5a93,
    0x0500a95, 0x038f52d, 0x05e0536, 0x0480aad, 0x034b5aa, 0x05805b2, 0x0420ba5, 0x02e7d4a,
    0x0540d4a, 0x03d0a95, 0x0600a97, 0x04c0556, 0x036cab5, 0x05a0ad5, 0x04606d2, 0x0308ea5,
    0x0560ea5, 0x040064a, 0x0286c97, 0x04e0a9b, 0x03af55a, 0x05e056a, 0x0480b69, 0x034b752,
    0x05a0b52, 0x0420b25, 0x02c964b, 0x0520a4b, 0x03d14ab, 0x06002ad, 0x04a05ad, 0x036cb69,
    0x05c0da9, 0x0460d92, 0x0309d25, 0x0560d25, 0x0415a4d, 0x0640a56, 0x04e02b6, 0x038c5b5,
    0x05e06d5, 0x0480ea9, 0x034be92, 0x05a0e92, 0x0440d26, 0x02c6a56, 0x0500a57, 0x03d14d6,
    0x062035a, 0x04a06d5, 0x036b6c9, 0x05c0749, 0x0460693, 0x02e952b, 0x054052b, 0x03e0a5b,
    0x02a555a, 0x04e056a, 0x038fb55, 0x0600ba4, 0x04a0b49, 0x032ba93, 0x0580a95, 0x042052d,
    0x02c8aad, 0x0500ab5, 0x03d35aa, 0x06205d2, 0x04c0da5, 0x036dd4a, 0x05c0d4a, 0x0460c95,
    0x030952e, 0x0540556, 0x03e0ab5, 0x02a55b2, 0x05006d2, 0x038cea5, 0x05e0725, 0x048064b,
    0x032ac97, 0x0560cab, 0x042055a, 0x02c6ad6, 0x0520b69, 0x03d7752, 0x0620b52, 0x04c0b25,
    0x036da4b, 0x05a0a4b, 0x04404ab, 0x02ea55b, 0x05405ad, 0x03e0b6a, 0x02a5b52, 0x0500d92,
    0x03afd25, 0x05e0d25, 0x0480a55, 0x032b4ad, 0x05804b6, 0x04005b5, 0x02c6daa, 0x0520ec9,
    0x03f1e92, 0x0620e92, 0x04c0d26, 0x036ca56, 0x05a0a57, 0x0440556, 0x02e86d5, 0x0540755,
    0x0400749, 0x0286e93, 0x04e0693, 0x038f52b, 0x05e052b, 0x0460a5b, 0x032b55a, 0x058056a,
    0x0420b65, 0x02c974a, 0x0520b4a, 0x03d1a95, 0x0620a95, 0x04a052d, 0x034caad, 0x05a0ab5,
    0x04605aa, 0x02e8ba5, 0x0540da5, 0x0400d4a, 0x02a7c95, 0x04e0c96, 0x038f94e, 0x05e0556,
    0x0480ab5, 0x032b5b2, 0x05806d2, 0x0420ea5, 0x02e8e4a, 0x050068b, 0x03b0c97, 0x06004ab,
    0x04a055b, 0x034cad6, 0x05a0b6a, 0x0460752, 0x0309725, 0x0540b45, 0x03e0a8b,
];

/// 해마다(1900년부터): 비트 0~12 달 순서대로 큰달(30일), 13~16 윤달(그 달 뒤), 17~ 설날의 그해 1월 1일부터 일수. 동경 135°(UTC+9, 1888년 이후 일본 표준시) 천문 계산. 2033년은 중국식 규칙(윤11월)
const JAPANESE: [u32; 199] = [
    0x03d16d2, 0x0620752, 0x04c0ea5, 0x038ad4a, 0x05c054b, 0x0440a97, 0x0309556, 0x056055a,
    0x0400b55, 0x02a56d2, 0x0500752, 0x03ad725, 0x0600b25, 0x0480a4b, 0x032b29b, 0x0580aad,
    0x044056a, 0x02c4b69, 0x0520ba9, 0x03efb52, 0x0640d92, 0x04c0d25, 0x036ba4d, 0x05c0956,
    0x04602b5, 0x02e95ad, 0x05606d4, 0x0400da9, 0x02c5d92, 0x0500e92, 0x03acd26, 0x05e0527,
    0x0480a57, 0x032b2b6, 0x0580ada, 0x04406d4, 0x02e6ea9, 0x0520749, 0x03cf693, 0x0620a93,
    0x04c052b, 0x034ca5b, 0x05a096d, 0x0460b6a, 0x0329b54, 0x0560ba4, 0x0400b49, 0x02a5a93,
    0x0500a95, 0x038f52b, 0x05e052d, 0x0480aad, 0x034b56a, 0x0580db2, 0x0440da4, 0x02e7d49,
    0x0540d4a, 0x03d1a95, 0x0620a96, 0x04c0556, 0x036cab5, 0x05a0ad5, 0x04606d2, 0x0308ea5,
    0x0560ea5, 0x0400e4a, 0x02a6c96, 0x04e0a9b, 0x03af556, 0x05e056a, 0x0480b59, 0x034b752,
    0x05a0752, 0x0420725, 0x02c964b, 0x0520a4b, 0x03d12ab, 0x06002ad, 0x04a056b, 0x036cb69,
    0x05c0da9, 0x0460d92, 0x0309b25, 0x0560d25, 0x0415a4d, 0x0640a56, 0x04e02b6, 0x038d5ad,
    0x06006d4, 0x0480da9, 0x034bd92, 0x05a0e92, 0x0440d26, 0x02c6a56, 0x0500a57, 0x03d12b6,
    0x0620b5a, 0x04c06d4, 0x036aec9, 0x05c0749, 0x0460693, 0x02e9527, 0x054052b, 0x03e0a5b,
    0x02a555a, 0x04e036a, 0x038fb55, 0x0600ba4, 0x04a0b49, 0x032ba93, 0x0580a95, 0x042052d,
    0x02c6a5d, 0x0500aad, 0x03d35aa, 0x06205d2, 0x04c0da5, 0x036bd4a, 0x05c0d4a, 0x0460a95,
    0x030952d, 0x0540556, 0x03e0ab5, 0x02a55aa, 0x05006d2, 0x038cea5, 0x05e0ea5, 0x04a0e4a,
    0x034ac96, 0x0560c9b, 0x042055a, 0x02c6ad5, 0x0520b69, 0x03d7752, 0x0620752, 0x04c0b25,
    0x036d64b, 0x05a0a4b, 0x04404ab, 0x02ea55b, 0x054056d, 0x03e0b69, 0x02a5b52, 0x0500d92,
    0x03afd25, 0x05e0d25, 0x0480a4d, 0x032b4ad, 0x05802b6, 0x04005b5, 0x02c6da9, 0x0520ea9,
    0x03f1d92, 0x0620e92, 0x04c0d26, 0x036ca56, 0x05a0a57, 0x04404d6, 0x02e86b5, 0x05406d5,
    0x0400ec9, 0x02a6e92, 0x04e0693, 0x038f52b, 0x05e052b, 0x0460a5b, 0x032b55a, 0x058056a,
    0x0420b55, 0x02c9749, 0x0520b49, 0x03d1a93, 0x0620a95, 0x04a052d, 0x034caad, 0x05a0ab5,
    0x04605aa, 0x02e8ba5, 0x0540da5, 0x0400d4a, 0x02a7a95, 0x04e0c95, 0x038f52e, 0x05e0556,
    0x0480ab5, 0x032b5b2, 0x05806d2, 0x0420ea5, 0x02e9e4a, 0x052064a, 0x03b0c97, 0x0600cab,
    0x04c055a, 0x034cad5, 0x05a0b69, 0x0460752, 0x03096a5, 0x0540b25, 0x03e064b,
];

/// 움 알쿠라 히즈라력 (1365년부터): 비트 0~11 달 순서대로 큰달(30일), 12~ 설날(1970-01-01 부터 일수 + 20000). hijri-converter 자료
const UMM_AL_QURA: [u32; 136] = [
    0x02bc7d55, 0x02d2a555, 0x02e8c555, 0x02feed55, 0x031516d5, 0x032b4555, 0x03416ea5, 0x03579d2a,
    0x036dbaaa, 0x0383dcd5, 0x039a0655, 0x03b02572, 0x03c64da9, 0x03dc7555, 0x03f29aaa, 0x0408b555,
    0x041ed52d, 0x0434fa6d, 0x044b255a, 0x04614555, 0x0477674d, 0x048d9d53, 0x04a3cd54, 0x04b9e556,
    0x04d00d55, 0x04e632d5, 0x04fc5d55, 0x05128d54, 0x0528ad45, 0x053ec655, 0x0554e52d, 0x056b0a5d,
    0x0581355a, 0x05975ad5, 0x05ad86aa, 0x05c3ad4b, 0x05d9d52a, 0x05efea57, 0x060614ae, 0x061c3976,
    0x0632656c, 0x06488b55, 0x065ebaaa, 0x0674da55, 0x068af4ad, 0x06a1195d, 0x06b742da, 0x06cd65d9,
    0x06e39db2, 0x06f9cba4, 0x070feb4a, 0x07260a55, 0x073c22b5, 0x07524575, 0x07687b6a, 0x077eabd2,
    0x0794dbc4, 0x07aafb89, 0x07c11a95, 0x07d7352d, 0x07ed55ad, 0x08038b6a, 0x0819b6d4, 0x082fddc9,
    0x08460d92, 0x085c2aa6, 0x08724956, 0x088862ae, 0x089e856d, 0x08b4b36a, 0x08cadb55, 0x08e10aaa,
    0x08f7294d, 0x090d449d, 0x0923695d, 0x093992ba, 0x094fb5b5, 0x0965e5aa, 0x097c0d55, 0x09923a9a,
    0x09a8592e, 0x09be726e, 0x09d4955d, 0x09eacada, 0x0a00f6d4, 0x0a1716a5, 0x0a2d354b, 0x0a435a97,
    0x0a59854e, 0x0a6faaae, 0x0a85d5ac, 0x0a9bfba9, 0x0ab22d92, 0x0ac84b25, 0x0ade664b, 0x0af48cab,
    0x0b0ab55a, 0x0b20db55, 0x0b3706d2, 0x0b4d2ea5, 0x0b635e4a, 0x0b797a95, 0x0b8f952d, 0x0ba5baad,
    0x0bbbe36c, 0x0bd20759, 0x0be836d2, 0x0bfe5695, 0x0c14752d, 0x0c2a9a5b, 0x0c40c4ba, 0x0c56e9ba,
    0x0c6d13b4, 0x0c833b69, 0x0c996b52, 0x0caf8aa6, 0x0cc5a4b6, 0x0cdbc96d, 0x0cf1f2ec, 0x0d0816d9,
    0x0d1e4eb2, 0x0d347d54, 0x0d4a9d2a, 0x0d60ba56, 0x0d76d4ae, 0x0d8cf96d, 0x0da32d6a, 0x0db95b54,
    0x0dcf7b29, 0x0de59a93, 0x0dfbb52b, 0x0e11da57, 0x0e280536, 0x0e3e2ab5, 0x0e5456aa, 0x0e6a7e93,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_dates() {
        let d = days_from_civil;
        // 2024년 추석(음 8.15) = 2024-09-17, 설날(음 1.1) = 2024-02-10
        let k = KOREAN_CAL.to_lunar(d(2024, 9, 17)).unwrap();
        assert_eq!((k.year, k.month, k.leap, k.day), (2024, 8, false, 15));
        assert_eq!(
            KOREAN_CAL.month_start(2024, 1, false).unwrap().0,
            d(2024, 2, 10)
        );
        // 2023년 윤2월 (한국) 시작 2023-03-22
        assert_eq!(
            KOREAN_CAL.month_start(2023, 2, true).unwrap().0,
            d(2023, 3, 22)
        );
        assert!(KOREAN_CAL.month_start(2024, 2, true).is_none());
        // 윤달을 한 달로 센다
        assert_eq!(
            KOREAN_CAL.add_months(2023, 2, false, 1),
            Some((2023, 2, true))
        );
        assert_eq!(
            KOREAN_CAL.add_months(2023, 12, false, 1),
            Some((2024, 1, false))
        );
        // 표를 넓힌 한국 음력: 2050년 설날 = 2050-01-23
        assert_eq!(
            KOREAN_CAL.month_start(2050, 1, false).unwrap().0,
            d(2050, 1, 23)
        );
        // 일본 음력(구력): 2024년 설날 = 2024-02-10
        assert_eq!(
            JAPANESE_CAL.month_start(2024, 1, false).unwrap().0,
            d(2024, 2, 10)
        );
        // 움 알쿠라: 1445-01-01 = 2023-07-19, 1444-09-01(라마단) = 2023-03-23
        assert_eq!(
            UMM_AL_QURA_CAL.month_start(1445, 1, false).unwrap().0,
            d(2023, 7, 19)
        );
        assert_eq!(
            UMM_AL_QURA_CAL.month_start(1444, 9, false).unwrap().0,
            d(2023, 3, 23)
        );
        // 계산식 히즈라력: 1 AH 1월 1일 = 622-07-19, 1400-01-01 = 1979-11-21
        assert_eq!(HIJRI_CAL.month_start(1, 1, false).unwrap().0, d(622, 7, 19));
        assert_eq!(
            HIJRI_CAL.month_start(1400, 1, false).unwrap().0,
            d(1979, 11, 21)
        );
        // 표 범위 밖
        assert!(KOREAN_CAL.to_lunar(d(1850, 1, 1)).is_none());
        assert!(KOREAN_CAL.month_start(2100, 1, false).is_none());
        assert!(UMM_AL_QURA_CAL.month_start(1600, 1, false).is_none());
        // 모든 날짜가 왕복된다
        for cal in [KOREAN_CAL, CHINESE_CAL, JAPANESE_CAL] {
            for day in (d(1900, 3, 1)..d(2098, 12, 1)).step_by(3) {
                let l = cal.to_lunar(day).unwrap();
                let back =
                    cal.month_start(l.year, l.month, l.leap).unwrap().0 + i64::from(l.day) - 1;
                assert_eq!(back, day);
            }
        }
        for (cal, from, to) in [
            (UMM_AL_QURA_CAL, d(1946, 1, 1), d(2077, 1, 1)),
            (HIJRI_CAL, d(1900, 1, 1), d(2100, 1, 1)),
        ] {
            for day in from..to {
                let l = cal.to_lunar(day).unwrap();
                let back =
                    cal.month_start(l.year, l.month, l.leap).unwrap().0 + i64::from(l.day) - 1;
                assert_eq!(back, day);
            }
        }
    }
}
