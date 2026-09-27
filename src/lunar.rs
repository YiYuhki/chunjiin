//! 음력(한국·중국) ↔ 양력 변환.
//!
//! 해마다 달의 길이(큰달·작은달)·윤달·설날 위치를 표로 둔다. 표는 한국천문연구원 자료를 따른
//! `korean-lunar-calendar`(한국)와 `lunardate`(중국)에서 만들었다. 한국과 중국은 기준 경도가 달라
//! 같은 해에도 달의 길이가 다를 수 있다.

/// 음력 날짜
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LunarDate {
    pub year: i64,
    pub month: u32,
    pub leap: bool,
    pub day: u32,
}

/// 음력 표 (1900년부터)
#[derive(Clone, Copy)]
pub struct Calendar(&'static [u32]);

pub const KOREAN_CAL: Calendar = Calendar(&KOREAN);
pub const CHINESE_CAL: Calendar = Calendar(&CHINESE);
const FIRST_YEAR: i64 = 1900;

/// 1970-01-01 부터의 일수
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

impl Calendar {
    fn entry(&self, year: i64) -> Option<u32> {
        let i = usize::try_from(year - FIRST_YEAR).ok()?;
        self.0.get(i).copied()
    }

    /// 설날 (1970-01-01 부터의 일수)
    fn new_year(&self, year: i64) -> Option<i64> {
        let e = self.entry(year)?;
        Some(days_from_civil(year, 1, 1) + i64::from(e >> 17))
    }

    /// 그해의 달들: (월, 윤달, 일수)
    fn months(&self, year: i64) -> Option<Vec<(u32, bool, u32)>> {
        let e = self.entry(year)?;
        let leap = (e >> 13) & 0xF;
        let mut out = Vec::with_capacity(13);
        for m in 1..=12 {
            out.push((m, false));
            if m == leap {
                out.push((m, true));
            }
        }
        Some(
            out.into_iter()
                .enumerate()
                .map(|(i, (m, l))| (m, l, if e & (1 << i) != 0 { 30 } else { 29 }))
                .collect(),
        )
    }

    /// 양력(1970-01-01 부터의 일수) → 음력
    pub fn to_lunar(&self, days: i64) -> Option<LunarDate> {
        let y = civil_year(days);
        let year = if days < self.new_year(y)? { y - 1 } else { y };
        let mut at = self.new_year(year)?;
        for (month, leap, len) in self.months(year)? {
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

    /// 음력 달의 첫날(양력 일수)과 일수. 없는 달(윤달이 아닌 해의 윤달 등)이면 None
    pub fn month_start(&self, year: i64, month: u32, leap: bool) -> Option<(i64, u32)> {
        let mut at = self.new_year(year)?;
        for (m, l, len) in self.months(year)? {
            if m == month && l == leap {
                return Some((at, len));
            }
            at += i64::from(len);
        }
        None
    }

    /// 음력 연·월 뒤로 `n` 달 (윤달도 한 달로 센다)
    pub fn add_months(
        &self,
        year: i64,
        month: u32,
        leap: bool,
        n: u32,
    ) -> Option<(i64, u32, bool)> {
        let (mut y, mut idx) = (
            year,
            self.months(year)?
                .iter()
                .position(|&(m, l, _)| m == month && l == leap)?,
        );
        for _ in 0..n {
            idx += 1;
            if idx >= self.months(y)?.len() {
                y += 1;
                idx = 0;
            }
        }
        let (m, l, _) = self.months(y)?[idx];
        Some((y, m, l))
    }
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

/// 1900년부터 해마다: 비트 0~12 달 순서대로 큰달(30일), 13~16 윤달(그 달 뒤), 17~ 설날의 그해 1월 1일부터 일수
const KOREAN: [u32; 150] = [
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
    0x03afd25, 0x05e0d25, 0x0480a4d, 0x032b4ad, 0x05802b6, 0x04005b5,
];

/// 1900년부터 해마다: 비트 0~12 달 순서대로 큰달(30일), 13~16 윤달(그 달 뒤), 17~ 설날의 그해 1월 1일부터 일수
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_dates() {
        let d = |y, m, dd| days_from_civil(y, m, dd);
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
        // 윤달을 한 달로 센다: 2023년 2월 + 1달 = 윤2월
        assert_eq!(
            KOREAN_CAL.add_months(2023, 2, false, 1),
            Some((2023, 2, true))
        );
        assert_eq!(
            KOREAN_CAL.add_months(2023, 12, false, 1),
            Some((2024, 1, false))
        );
        // 표 범위 밖
        assert!(KOREAN_CAL.to_lunar(d(1850, 1, 1)).is_none());
        assert!(KOREAN_CAL.month_start(2100, 1, false).is_none());
        // 모든 날짜가 왕복된다
        for day in d(1900, 3, 1)..d(2049, 12, 1) {
            for cal in [KOREAN_CAL, CHINESE_CAL] {
                let l = cal.to_lunar(day).unwrap();
                assert_eq!(
                    cal.month_start(l.year, l.month, l.leap).unwrap().0 + i64::from(l.day) - 1,
                    day
                );
            }
        }
    }
}
