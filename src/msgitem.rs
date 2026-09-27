//! Outlook 비메일 항목(일정·회의 요청·작업·연락처)의 정보를 표준 형식으로 옮긴다.
//!
//! 메일로 재조합하면 제목·본문·첨부만 남으므로, 항목 고유 정보(시간·장소·연락처 필드)를
//! 본문 앞 요약과 `.ics`(iCalendar) / `.vcf`(vCard) 첨부로 새로 만든다. 값은 모두
//! 이스케이프한 텍스트 필드로만 쓰고, 첨부·URL 같은 능동 요소는 만들지 않는다. 알림은
//! 화면 표시(DISPLAY)만 만든다.
//!
//! 일정은 시간대(TZDEFINITION·TimeZoneStruct → VTIMEZONE), 반복 규칙(AppointmentRecur →
//! RRULE·EXDATE, 바뀐 회차는 RECURRENCE-ID 가 붙은 VEVENT), 참석자(역할·응답), 알림,
//! 종일 여부를 옮긴다 (MS-OXOCAL).

/// 항목 종류
pub enum Item {
    Event(Event),
    Task(Task),
    Contact(Contact),
}

#[derive(Default)]
pub struct Event {
    pub summary: String,
    /// FILETIME (UTC)
    pub start: Option<u64>,
    pub end: Option<u64>,
    pub location: Option<String>,
    pub organizer: Option<String>,
    pub organizer_email: Option<String>,
    /// 표시용 참석자 문자열 (수신자 목록이 없을 때)
    pub attendees: Option<String>,
    pub attendee_list: Vec<Attendee>,
    pub description: String,
    pub tz: Option<Tz>,
    pub recur: Option<Recur>,
    pub all_day: bool,
    /// 시작 몇 분 전에 알릴지
    pub reminder: Option<u32>,
    /// 약속 있음 표시 (false 면 한가함)
    pub busy: Option<bool>,
}

#[derive(Default)]
pub struct Task {
    pub summary: String,
    pub start: Option<u64>,
    pub due: Option<u64>,
    pub percent: Option<f64>,
    pub description: String,
    /// 알림 시각 (FILETIME)
    pub reminder: Option<u64>,
    /// 반복 (날짜 단위)
    pub recur: Option<Recur>,
}

#[derive(Default)]
pub struct Contact {
    pub display: Option<String>,
    pub given: Option<String>,
    pub surname: Option<String>,
    pub company: Option<String>,
    pub department: Option<String>,
    pub title: Option<String>,
    pub emails: Vec<String>,
    /// (종류, 번호)
    pub phones: Vec<(&'static str, String)>,
    /// 거리, 시, 도, 우편번호, 국가
    pub address: [Option<String>; 5],
    /// 재인코딩한 사진 (내용, vCard TYPE)
    pub photo: Option<(Vec<u8>, &'static str)>,
    /// 집 주소 (거리, 시, 도, 우편번호, 국가)
    pub home_address: [Option<String>; 5],
    pub nickname: Option<String>,
    /// 생일·기념일 (FILETIME)
    pub birthday: Option<u64>,
    pub anniversary: Option<u64>,
    /// 메모(본문)
    pub note: String,
    /// 그 밖의 필드 (이름표, 값): 사용자 정의 필드, 메신저 주소, 배우자 등
    pub extra: Vec<(String, String)>,
}

/// 생일처럼 날짜만 뜻이 있는 FILETIME → 날짜 (현지 자정을 UTC 로 저장하므로 가장 가까운 자정으로)
fn nearest_date(ft: u64) -> Option<i64> {
    let m = ft_minutes(ft);
    Some((m + 720).div_euclid(1440) * 1440)
}

/// 참석자
pub struct Attendee {
    pub name: Option<String>,
    pub email: Option<String>,
    /// 1 필수, 2 선택, 3 자원(회의실·장비)
    pub kind: u32,
    /// PidTagRecipientTrackStatus: 2 미정, 3 수락, 4 거절
    pub status: u32,
}

/// 시간대 전환 규칙 (해당 월의 n번째 요일, 5 는 마지막)
#[derive(Clone, Copy)]
pub struct TzRule {
    month: u32,
    dow: u32,
    week: u32,
    hour: u32,
    minute: u32,
}

/// 시간대 (Windows TIME_ZONE_INFORMATION 과 같은 모양). 편차는 분 단위, UTC = 현지 + 편차
pub struct Tz {
    pub name: String,
    bias: i32,
    std_bias: i32,
    dst_bias: i32,
    /// 일광 절약 시간 (끝, 시작) 규칙. 없으면 표준시만
    rules: Option<(TzRule, TzRule)>,
}

/// 반복 종류
#[derive(Clone, Copy, PartialEq)]
enum Freq {
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

/// 반복 일정 (MS-OXOCAL AppointmentRecurrencePattern). 시각은 1601-01-01 부터의 현지 분
pub struct Recur {
    freq: Freq,
    interval: u32,
    /// 요일 비트 (bit0 일요일)
    days: u8,
    /// n번째 요일 (1~4, 5 마지막). 0 이면 날짜 기준
    nth: u32,
    /// 날짜 (1~31, -1 마지막 날). 0 이면 요일 기준
    month_day: i32,
    /// 매년 반복의 월
    month: u32,
    count: Option<u32>,
    /// 끝 날짜 (현지 분, 자정)
    until: Option<i64>,
    first_dow: u32,
    /// 시작 날짜 (현지 분, 자정)와 하루 안의 시작·끝 (분)
    start_date: i64,
    start_offset: i64,
    end_offset: i64,
    /// 지운 회차 날짜 (현지 분, 자정)
    deleted: Vec<i64>,
    exceptions: Vec<Exception>,
    /// 음력 반복이면 그 달력 (날짜·월은 음력 기준)
    lunar: Option<crate::lunar::Calendar>,
}

impl Exception {
    /// 이 회차의 알림 (분 전). `master` 는 전체 일정의 알림
    fn reminder(&self, master: Option<u32>) -> Option<u32> {
        match self.reminder_set {
            Some(false) => None,
            Some(true) => Some(self.reminder_delta.or(master).unwrap_or(15)),
            None => master.map(|m| self.reminder_delta.unwrap_or(m)),
        }
    }
}

/// 바뀐 회차
pub struct Exception {
    start: i64,
    end: i64,
    original: i64,
    /// 알림을 켜거나 끈 변경 (None 이면 전체 일정을 따름)
    reminder_set: Option<bool>,
    /// 알림 시간(분 전) 변경
    reminder_delta: Option<u32>,
    /// 약속 있음 표시 변경 (false 면 한가함)
    busy: Option<bool>,
    /// 종일 여부 변경
    all_day: Option<bool>,
    subject: Option<String>,
    location: Option<String>,
}

/// 생성된 첨부 (이름, MIME 형식, 내용)
pub struct Generated {
    pub name: String,
    pub content_type: &'static str,
    pub data: Vec<u8>,
}

// ── 시각 ──
//
// 모든 시각을 1601-01-01 00:00 부터의 분(i64)으로 다룬다. FILETIME 은 UTC 분,
// 반복 패턴의 값은 일정 시간대의 현지 분이다.

/// 1601-01-01 부터 1970-01-01 까지의 일수
const DAYS_1601_TO_1970: i64 = 134_774;
/// 옮기는 시각의 범위 (연도)
const YEARS: std::ops::RangeInclusive<i64> = 1601..=9999;

fn ft_minutes(ft: u64) -> i64 {
    (ft / 600_000_000) as i64
}

/// 1970-01-01 부터의 일수 (Howard Hinnant, days_from_civil)
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// 분 → (년, 월, 일, 시, 분)
fn civil(min: i64) -> Option<(i64, i64, i64, i64, i64)> {
    let days = min.div_euclid(1440) - DAYS_1601_TO_1970;
    let rem = min.rem_euclid(1440);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    YEARS
        .contains(&year)
        .then_some((year, month, day, rem / 60, rem % 60))
}

fn minutes_of(y: i64, mo: i64, d: i64, h: i64, mi: i64) -> i64 {
    (days_from_civil(y, mo, d) + DAYS_1601_TO_1970) * 1440 + h * 60 + mi
}

fn days_in_month(y: i64, m: i64) -> i64 {
    days_from_civil(if m == 12 { y + 1 } else { y }, m % 12 + 1, 1) - days_from_civil(y, m, 1)
}

/// `YYYYMMDDTHHMMSS` (+ `Z`)
fn ical_dt(min: i64, utc: bool) -> Option<String> {
    let (y, mo, d, h, mi) = civil(min)?;
    let z = if utc { "Z" } else { "" };
    Some(format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}00{z}"))
}

fn ical_date(min: i64) -> Option<String> {
    let (y, mo, d, _, _) = civil(min)?;
    Some(format!("{y:04}{mo:02}{d:02}"))
}

fn human(min: i64) -> Option<String> {
    let (y, mo, d, h, mi) = civil(min)?;
    Some(format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}"))
}

fn human_date(min: i64) -> Option<String> {
    let (y, mo, d, _, _) = civil(min)?;
    Some(format!("{y:04}-{mo:02}-{d:02}"))
}

/// `+0900`
fn offset_str(off: i32) -> String {
    let sign = if off < 0 { '-' } else { '+' };
    let a = off.unsigned_abs();
    format!("{sign}{:02}{:02}", a / 60, a % 60)
}

// ── 시간대 ──

fn le16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// SYSTEMTIME 16바이트 → 전환 규칙 (연도가 정해진 절대 날짜는 쓰지 않는다)
fn systemtime(b: &[u8]) -> Option<TzRule> {
    let f = |i: usize| le16(b, i * 2).map(u32::from);
    let r = TzRule {
        month: f(1)?,
        dow: f(2)?,
        week: f(3)?,
        hour: f(4)?,
        minute: f(5)?,
    };
    (f(0)? == 0
        && (1..=12).contains(&r.month)
        && r.dow <= 6
        && (1..=5).contains(&r.week)
        && r.hour < 24
        && r.minute < 60)
        .then_some(r)
}

/// 시간대 이름: 매개변수·텍스트 어디에 써도 같게 나오는 문자만
fn tz_name(s: &str) -> String {
    let v: String = s
        .chars()
        .filter_map(|c| match c {
            ':' => Some('.'),
            '"' | ';' | ',' | '\\' => None,
            c if c.is_control() || crate::text::is_bidi_control(c) => None,
            c => Some(c),
        })
        .take(64)
        .collect();
    let v = v.trim();
    if v.is_empty() {
        "Outlook".into()
    } else {
        v.to_string()
    }
}

impl Tz {
    fn new(
        name: &str,
        bias: i32,
        std_bias: i32,
        dst_bias: i32,
        std: &[u8],
        dst: &[u8],
    ) -> Option<Tz> {
        let ok = |b: i32| b.abs() <= 24 * 60;
        if !ok(bias) || !ok(std_bias) || !ok(dst_bias) {
            return None;
        }
        let rules = systemtime(std).zip(systemtime(dst));
        Some(Tz {
            name: tz_name(name),
            bias,
            std_bias,
            dst_bias: if rules.is_some() { dst_bias } else { std_bias },
            rules,
        })
    }

    /// PidLidTimeZoneStruct (48바이트)
    pub fn from_struct(b: &[u8], name: &str) -> Option<Tz> {
        if b.len() < 48 {
            return None;
        }
        let i = |at| le32(b, at).map(|v| v as i32);
        Tz::new(name, i(0)?, i(4)?, i(8)?, &b[14..30], &b[32..48])
    }

    /// TZDEFINITION (PidLidAppointmentTimeZoneDefinition*)
    pub fn from_definition(b: &[u8]) -> Option<Tz> {
        if b.first() != Some(&2) {
            return None;
        }
        let header = usize::from(le16(b, 2)?);
        let cch = usize::from(le16(b, 6)?);
        let units: Vec<u16> = b
            .get(8..8 + cch * 2)?
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_le_bytes(c))
            .collect();
        let name = String::from_utf16_lossy(&units);
        let count = usize::from(le16(b, 8 + cch * 2)?).min(1024);
        let start = 4 + header;
        let rules: Vec<&[u8]> = (0..count)
            .filter_map(|k| b.get(start + k * 66..start + (k + 1) * 66))
            .collect();
        // TZRULE_FLAG_EFFECTIVE_TZREG 가 붙은 규칙, 없으면 마지막 규칙
        let r = rules
            .iter()
            .find(|r| le16(r, 4).is_some_and(|f| f & 2 != 0))
            .or(rules.last())?;
        let i = |at| le32(r, at).map(|v| v as i32);
        Tz::new(&name, i(22)?, i(26)?, i(30)?, &r[34..50], &r[50..66])
    }

    fn std_offset(&self) -> i32 {
        -(self.bias + self.std_bias)
    }

    fn dst_offset(&self) -> i32 {
        -(self.bias + self.dst_bias)
    }

    /// 그 해의 전환 시각 (현지 분)
    fn transition(r: &TzRule, year: i64) -> i64 {
        let first = days_from_civil(year, i64::from(r.month), 1);
        // 1970-01-01 은 목요일(4)
        let dow_first = (first + 4).rem_euclid(7);
        let mut day =
            1 + (i64::from(r.dow) - dow_first).rem_euclid(7) + 7 * (i64::from(r.week) - 1);
        while day > days_in_month(year, i64::from(r.month)) {
            day -= 7;
        }
        minutes_of(
            year,
            i64::from(r.month),
            day,
            i64::from(r.hour),
            i64::from(r.minute),
        )
    }

    /// UTC 분에서의 현지 편차 (분, 동쪽이 양수)
    fn offset_at(&self, utc: i64) -> i32 {
        let Some((std, dst)) = &self.rules else {
            return self.std_offset();
        };
        let Some((year, ..)) = civil(utc + i64::from(self.std_offset())) else {
            return self.std_offset();
        };
        let start = Tz::transition(dst, year) - i64::from(self.std_offset());
        let end = Tz::transition(std, year) - i64::from(self.dst_offset());
        let in_dst = if start < end {
            utc >= start && utc < end
        } else {
            utc >= start || utc < end
        };
        if in_dst {
            self.dst_offset()
        } else {
            self.std_offset()
        }
    }

    fn to_local(&self, utc: i64) -> i64 {
        utc + i64::from(self.offset_at(utc))
    }

    fn to_utc(&self, local: i64) -> i64 {
        local - i64::from(self.offset_at(local - i64::from(self.std_offset())))
    }

    fn label(&self, utc: i64) -> String {
        let off = self.offset_at(utc);
        let s = offset_str(off);
        format!("UTC{}:{} {}", &s[..3], &s[3..], self.name)
    }

    fn vtimezone(&self, o: &mut String) {
        fold("BEGIN:VTIMEZONE", o);
        fold(&format!("TZID:{}", esc(&self.name)), o);
        let (so, dof) = (self.std_offset(), self.dst_offset());
        match &self.rules {
            None => {
                fold("BEGIN:STANDARD", o);
                fold("DTSTART:16010101T000000", o);
                fold(&format!("TZOFFSETFROM:{}", offset_str(so)), o);
                fold(&format!("TZOFFSETTO:{}", offset_str(so)), o);
                fold("END:STANDARD", o);
            }
            Some((std, dst)) => {
                for (comp, r, from, to) in [("STANDARD", std, dof, so), ("DAYLIGHT", dst, so, dof)]
                {
                    fold(&format!("BEGIN:{comp}"), o);
                    let onset = ical_dt(Tz::transition(r, 1601), false).unwrap_or_default();
                    fold(&format!("DTSTART:{onset}"), o);
                    fold(&format!("TZOFFSETFROM:{}", offset_str(from)), o);
                    fold(&format!("TZOFFSETTO:{}", offset_str(to)), o);
                    let week = if r.week == 5 { -1 } else { r.week as i32 };
                    fold(
                        &format!(
                            "RRULE:FREQ=YEARLY;BYMONTH={};BYDAY={week}{}",
                            r.month, DAY_CODES[r.dow as usize]
                        ),
                        o,
                    );
                    fold(&format!("END:{comp}"), o);
                }
            }
        }
        fold("END:VTIMEZONE", o);
    }
}

const DAY_CODES: [&str; 7] = ["SU", "MO", "TU", "WE", "TH", "FR", "SA"];
const DAY_NAMES: [&str; 7] = ["일", "월", "화", "수", "목", "금", "토"];

// ── 반복 ──

/// 읽기 위치를 가진 바이트 읽개
struct Cur<'a> {
    b: &'a [u8],
    at: usize,
}

impl Cur<'_> {
    fn u16(&mut self) -> Option<u16> {
        let v = le16(self.b, self.at)?;
        self.at += 2;
        Some(v)
    }
    fn u32(&mut self) -> Option<u32> {
        let v = le32(self.b, self.at)?;
        self.at += 4;
        Some(v)
    }
    fn bytes(&mut self, n: usize) -> Option<&[u8]> {
        let v = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(v)
    }
    fn skip_block(&mut self) -> Option<()> {
        let n = self.u32()? as usize;
        self.bytes(n).map(|_| ())
    }
}

/// 한 목록에 허용하는 회차·예외 수
const MAX_INSTANCES: usize = 4096;

impl Recur {
    /// PidLidAppointmentRecur. `ansi` 는 8비트 문자열 디코더
    /// 작업의 반복 (PidLidTaskRecurrence: 일정 전용 부분이 없는 RecurrencePattern)
    pub fn parse_task(b: &[u8]) -> Option<Recur> {
        Recur::parse_inner(b, &|_| String::new(), false)
    }

    pub fn parse(b: &[u8], ansi: &dyn Fn(&[u8]) -> String) -> Option<Recur> {
        Recur::parse_inner(b, ansi, true)
    }

    fn parse_inner(b: &[u8], ansi: &dyn Fn(&[u8]) -> String, appointment: bool) -> Option<Recur> {
        let mut c = Cur { b, at: 0 };
        let (_reader, _writer) = (c.u16()?, c.u16()?);
        let recur_freq = c.u16()?;
        let pattern = c.u16()?;
        let calendar = c.u16()?;
        let _first = c.u32()?;
        let period = c.u32()?;
        let _sliding = c.u32()?;
        // 그레고리력과 음력(한국·중국)
        let lunar = match calendar {
            0 | 1 => None,
            0x12 | 0x14 => Some(crate::lunar::KOREAN_CAL),
            0x0F | 0x11 => Some(crate::lunar::CHINESE_CAL),
            _ => return None,
        };
        // 음력 패턴(0xA~0xC)은 음력 달력에서만, 뜻은 날짜·n번째 요일·말일 패턴과 같다
        let pattern = match pattern {
            0xA..=0xC if lunar.is_some() => pattern - 8,
            0xA..=0xC => return None,
            p => p,
        };
        let (mut days, mut nth, mut month_day) = (0u8, 0u32, 0i32);
        match pattern {
            0 => {}
            1 => days = (c.u32()? & 0x7F) as u8,
            2 | 4 => {
                let d = c.u32()?;
                month_day = if pattern == 4 || d >= 31 {
                    -1
                } else {
                    d as i32
                };
                if month_day == 0 {
                    return None;
                }
            }
            3 => {
                days = (c.u32()? & 0x7F) as u8;
                nth = c.u32()?;
                if !(1..=5).contains(&nth) || days == 0 {
                    return None;
                }
            }
            _ => return None,
        }
        let end_type = c.u32()?;
        let occurrences = c.u32()?;
        let first_dow = c.u32()?.min(6);
        let n_del = c.u32()? as usize;
        if n_del > MAX_INSTANCES {
            return None;
        }
        let mut deleted = Vec::with_capacity(n_del);
        for _ in 0..n_del {
            deleted.push(i64::from(c.u32()?));
        }
        let n_mod = c.u32()? as usize;
        if n_mod > MAX_INSTANCES {
            return None;
        }
        for _ in 0..n_mod {
            c.u32()?;
        }
        let start_date = i64::from(c.u32()?);
        let end_date = i64::from(c.u32()?);
        let (freq, interval) = match (recur_freq, pattern) {
            (0x200A, 0) => (Freq::Daily, period / 1440),
            // 평일마다
            (0x200A, 1) => (Freq::Weekly, 1),
            (0x200B, 1) => (Freq::Weekly, period),
            (0x200C, 2..=4) => (Freq::Monthly, period),
            (0x200D, 2..=4) => (Freq::Yearly, period / 12),
            _ => return None,
        };
        if !(1..=999).contains(&interval) || (freq == Freq::Weekly && days == 0) {
            return None;
        }
        let (count, until) = match end_type {
            0x2021 => (None, Some(end_date)),
            0x2022 => (Some(occurrences).filter(|&n| n > 0), None),
            _ => (None, None),
        };
        // 음력은 매월·매년 반복에만 뜻이 있다
        let lunar = lunar.filter(|_| matches!(freq, Freq::Monthly | Freq::Yearly));
        let start_day = start_date.div_euclid(1440) - DAYS_1601_TO_1970;
        let month = match lunar {
            Some(cal) => cal.to_lunar(start_day)?.month,
            None => civil(start_date).map_or(1, |(_, m, ..)| m as u32),
        };
        if !appointment {
            return Some(Recur {
                freq,
                interval,
                days,
                nth,
                month_day,
                month,
                count,
                until,
                first_dow,
                start_date,
                start_offset: 0,
                end_offset: 0,
                deleted,
                exceptions: Vec::new(),
                lunar,
            });
        }
        // AppointmentRecurrencePattern 나머지
        let _reader2 = c.u32()?;
        let writer2 = c.u32()?;
        let start_offset = i64::from(c.u32()?);
        let end_offset = i64::from(c.u32()?);
        if start_offset >= 1440 || end_offset < start_offset {
            return None;
        }
        let mut exceptions = Vec::new();
        let mut flags = Vec::new();
        let n_exc = usize::from(c.u16()?);
        for _ in 0..n_exc.min(MAX_INSTANCES) {
            let (start, end, original) = (c.u32()?, c.u32()?, c.u32()?);
            let f = c.u16()?;
            let mut e = Exception {
                start: i64::from(start),
                end: i64::from(end),
                original: i64::from(original),
                reminder_set: None,
                reminder_delta: None,
                busy: None,
                all_day: None,
                subject: None,
                location: None,
            };
            let text = |c: &mut Cur| -> Option<String> {
                let _len = c.u16()?;
                let len2 = usize::from(c.u16()?);
                Some(ansi(c.bytes(len2)?))
            };
            if f & 0x0001 != 0 {
                e.subject = Some(text(&mut c)?);
            }
            if f & 0x0002 != 0 {
                c.u32()?; // MeetingType
            }
            if f & 0x0004 != 0 {
                e.reminder_delta = Some(c.u32()?.min(60 * 24 * 365));
            }
            if f & 0x0008 != 0 {
                e.reminder_set = Some(c.u32()? != 0);
            }
            if f & 0x0010 != 0 {
                e.location = Some(text(&mut c)?);
            }
            if f & 0x0020 != 0 {
                e.busy = Some(c.u32()? != 0);
            }
            if f & 0x0040 != 0 {
                c.u32()?; // 첨부 여부 (예외 회차의 첨부는 옮기지 않음)
            }
            if f & 0x0080 != 0 {
                e.all_day = Some(c.u32()? != 0);
            }
            if f & 0x0100 != 0 {
                c.u32()?; // 색
            }
            flags.push(f);
            exceptions.push(e);
        }
        // 확장 예외: 유니코드 제목·장소 (없거나 깨져 있으면 8비트 값을 쓴다)
        let _ = (|| -> Option<()> {
            c.skip_block()?;
            for (e, &f) in exceptions.iter_mut().zip(&flags) {
                if writer2 >= 0x3009 {
                    c.skip_block()?;
                }
                c.skip_block()?;
                if f & 0x0011 != 0 {
                    c.bytes(12)?;
                    let wide = |c: &mut Cur| -> Option<String> {
                        let n = usize::from(c.u16()?);
                        let units: Vec<u16> = c
                            .bytes(n * 2)?
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .map(|&x| u16::from_le_bytes(x))
                            .collect();
                        Some(String::from_utf16_lossy(&units))
                    };
                    if f & 0x0001 != 0 {
                        e.subject = Some(wide(&mut c)?);
                    }
                    if f & 0x0010 != 0 {
                        e.location = Some(wide(&mut c)?);
                    }
                    c.skip_block()?;
                }
            }
            Some(())
        })();
        Some(Recur {
            freq,
            interval,
            days,
            nth,
            month_day,
            month,
            count,
            until,
            first_dow,
            start_date,
            start_offset,
            end_offset,
            deleted,
            exceptions,
            lunar,
        })
    }

    fn start(&self) -> i64 {
        self.start_date + self.start_offset
    }

    fn end(&self) -> i64 {
        self.start_date + self.end_offset
    }

    fn byday(&self) -> String {
        let d: Vec<&str> = (0..7)
            .filter(|i| self.days & (1 << i) != 0)
            .map(|i| DAY_CODES[i])
            .collect();
        d.join(",")
    }

    /// RRULE 값. `until` 은 끝 표기 (형식은 DTSTART 에 맞춤)
    fn rrule(&self, until: Option<String>) -> String {
        let freq = match self.freq {
            Freq::Daily => "DAILY",
            Freq::Weekly => "WEEKLY",
            Freq::Monthly => "MONTHLY",
            Freq::Yearly => "YEARLY",
        };
        let mut r = format!("FREQ={freq}");
        if self.interval > 1 {
            r += &format!(";INTERVAL={}", self.interval);
        }
        match self.freq {
            Freq::Weekly => r += &format!(";BYDAY={}", self.byday()),
            Freq::Monthly | Freq::Yearly => {
                if self.freq == Freq::Yearly {
                    r += &format!(";BYMONTH={}", self.month);
                }
                if self.nth > 0 {
                    let pos = if self.nth == 5 { -1 } else { self.nth as i32 };
                    r += &format!(";BYDAY={};BYSETPOS={pos}", self.byday());
                } else {
                    r += &format!(";BYMONTHDAY={}", self.month_day);
                }
            }
            Freq::Daily => {}
        }
        if let Some(n) = self.count {
            r += &format!(";COUNT={n}");
        } else if let Some(u) = until {
            r += &format!(";UNTIL={u}");
        }
        if self.freq == Freq::Weekly {
            r += &format!(";WKST={}", DAY_CODES[self.first_dow as usize]);
        }
        r
    }

    /// 사람이 읽는 설명
    fn describe(&self) -> String {
        let days: Vec<&str> = (0..7)
            .filter(|i| self.days & (1 << i) != 0)
            .map(|i| DAY_NAMES[i])
            .collect();
        let days = days.join("·");
        let every = |unit: &str, one: &str| {
            if self.interval > 1 {
                format!("{}{unit}마다", self.interval)
            } else {
                one.to_string()
            }
        };
        let nth = || match self.nth {
            5 => "마지막".to_string(),
            n => format!("{n}째"),
        };
        let day = || {
            if self.month_day < 0 {
                "마지막 날".to_string()
            } else {
                format!("{}일", self.month_day)
            }
        };
        let mut s = match self.freq {
            Freq::Daily => every("일", "매일"),
            Freq::Weekly => format!("{} {days}요일", every("주", "매주")),
            Freq::Monthly if self.nth > 0 => {
                format!("{} {} {days}요일", every("개월", "매월"), nth())
            }
            Freq::Monthly => format!("{} {}", every("개월", "매월"), day()),
            Freq::Yearly if self.nth > 0 => {
                format!(
                    "{} {}월 {} {days}요일",
                    every("년", "매년"),
                    self.month,
                    nth()
                )
            }
            Freq::Yearly => format!("{} {}월 {}", every("년", "매년"), self.month, day()),
        };
        if self.lunar.is_some() {
            s = format!("음력 {s}");
        }
        if let Some(n) = self.count {
            s += &format!(", {n}회");
        } else if let Some(d) = self.until.and_then(human_date) {
            s += &format!(", {d}까지");
        }
        s
    }

    /// 음력 반복의 회차 시작 (현지 분). 음력 표 범위(한국 2049년, 중국 2098년) 안에서 최대
    /// `MAX_LUNAR` 회까지 펼친다
    fn lunar_dates(&self) -> Vec<i64> {
        const MAX_LUNAR: usize = 500;
        let Some(cal) = self.lunar else {
            return Vec::new();
        };
        let start_day = self.start_date.div_euclid(1440) - DAYS_1601_TO_1970;
        let Some(first) = cal.to_lunar(start_day) else {
            return Vec::new();
        };
        let limit = self
            .count
            .map_or(MAX_LUNAR, |n| (n as usize).min(MAX_LUNAR));
        let mut out = Vec::new();
        for k in 0..(MAX_LUNAR * 2) as u32 {
            if out.len() >= limit {
                break;
            }
            let step = k.saturating_mul(self.interval);
            let month = match self.freq {
                Freq::Yearly => {
                    let y = first.year + i64::from(step);
                    // 윤달이 없는 해는 같은 달(평달)로
                    cal.month_start(y, first.month, first.leap)
                        .or_else(|| cal.month_start(y, first.month, false))
                }
                _ => cal
                    .add_months(first.year, first.month, first.leap, step)
                    .and_then(|(y, m, l)| cal.month_start(y, m, l)),
            };
            let Some((at, len)) = month else {
                break;
            };
            let day = if self.nth > 0 {
                // 그 달에서 n번째(5 는 마지막) 해당 요일
                let hits: Vec<i64> = (0..i64::from(len))
                    .filter(|d| self.days & (1 << (at + d + 4).rem_euclid(7)) != 0)
                    .collect();
                let pick = if self.nth == 5 {
                    hits.last()
                } else {
                    hits.get(self.nth as usize - 1)
                };
                match pick {
                    Some(&d) => at + d,
                    None => continue,
                }
            } else if self.month_day < 0 {
                at + i64::from(len) - 1
            } else {
                at + i64::from((self.month_day as u32).min(len)) - 1
            };
            let local = (day + DAYS_1601_TO_1970) * 1440;
            if local < self.start_date {
                continue;
            }
            if self.until.is_some_and(|u| local > u) {
                break;
            }
            out.push(local + self.start_offset);
        }
        out
    }

    /// 지운 회차(바뀐 회차 제외)
    fn exdates(&self) -> Vec<i64> {
        let mut v: Vec<i64> = self
            .deleted
            .iter()
            .filter(|&&d| {
                !self
                    .exceptions
                    .iter()
                    .any(|e| e.original.div_euclid(1440) * 1440 == d)
            })
            .map(|&d| d + self.start_offset)
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }
}

/// 제어 문자를 빼고 앞뒤 공백을 정리한 값 (빈 값은 None)
fn clean(s: &str) -> Option<String> {
    let v: String = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .filter(|c| !crate::text::is_bidi_control(*c))
        .collect();
    let v = v.trim().to_string();
    (!v.is_empty()).then_some(v)
}

use crate::ical::{escape as esc, fold};

fn prop(out: &mut String, name: &str, value: Option<&str>) {
    if let Some(v) = value.and_then(clean) {
        fold(&format!("{name}:{}", esc(&v)), out);
    }
}

fn utc_prop(out: &mut String, name: &str, ft: Option<u64>) {
    if let Some(t) = ft.and_then(|t| ical_dt(ft_minutes(t), true)) {
        fold(&format!("{name}:{t}"), out);
    }
}

/// 시간대 이름·참석자 이름을 매개변수 값(따옴표 안)에 쓸 수 있게
fn param_text(s: &str) -> Option<String> {
    let v: String = s
        .chars()
        .filter(|c| !c.is_control() && !crate::text::is_bidi_control(*c) && !"\";:\\".contains(*c))
        .take(128)
        .collect();
    let v = v.trim();
    (!v.is_empty()).then(|| v.to_string())
}

/// mailto: 로 쓸 수 있는 주소
fn mail_addr(s: &str) -> Option<&str> {
    let s = s.trim();
    (s.contains('@')
        && !s.is_empty()
        && !s
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "<>\"\\".contains(c)))
    .then_some(s)
}

fn uid(parts: &[&str]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update([0]);
    }
    let d = h.finalize();
    let hex: String = d[..16].iter().map(|b| format!("{b:02x}")).collect();
    format!("{hex}@cdr")
}

/// 화면 표시 알림 (설명이 있어야 한다)
fn display_alarm(o: &mut String, trigger: &str, summary: &str) {
    fold("BEGIN:VALARM", o);
    fold("ACTION:DISPLAY", o);
    fold(trigger, o);
    let text = clean(summary).unwrap_or_else(|| "Reminder".into());
    prop(o, "DESCRIPTION", Some(&text));
    fold("END:VALARM", o);
}

/// 본문 설명은 너무 길면 자른다
fn description(s: &str) -> String {
    s.chars().take(32 * 1024).collect()
}

/// 일정 시각을 쓰는 방식
enum Zone<'a> {
    /// UTC (`Z`)
    Utc,
    /// 시간대를 모르는 현지 시각
    Floating,
    Tz(&'a Tz),
}

impl Event {
    /// (시각 표기 방식, 시작, 끝): 시작·끝은 방식에 맞춘 분
    fn times(&self) -> Option<(Zone<'_>, i64, Option<i64>)> {
        if let Some(r) = &self.recur {
            let zone = self.tz.as_ref().map_or(Zone::Floating, Zone::Tz);
            return Some((zone, r.start(), Some(r.end())));
        }
        let start = ft_minutes(self.start?);
        let end = self.end.map(ft_minutes);
        Some(match &self.tz {
            Some(tz) => (
                Zone::Tz(tz),
                tz.to_local(start),
                end.map(|e| tz.to_local(e)),
            ),
            None => (Zone::Utc, start, end),
        })
    }

    fn all_day(&self, zone: &Zone) -> bool {
        self.all_day && !matches!(zone, Zone::Utc)
    }

    /// 속성 하나 (매개변수 포함)
    fn when(&self, zone: &Zone, name: &str, t: i64) -> Option<String> {
        self.when_as(zone, name, t, self.all_day(zone))
    }

    /// `date` 면 날짜로, 아니면 시각 표기 방식대로
    fn when_as(&self, zone: &Zone, name: &str, t: i64, date: bool) -> Option<String> {
        if date {
            return Some(format!("{name};VALUE=DATE:{}", ical_date(t)?));
        }
        Some(match zone {
            Zone::Utc => format!("{name}:{}", ical_dt(t, true)?),
            Zone::Floating => format!("{name}:{}", ical_dt(t, false)?),
            Zone::Tz(tz) => format!("{name};TZID=\"{}\":{}", tz.name, ical_dt(t, false)?),
        })
    }

    fn human(&self, zone: &Zone, t: i64) -> Option<String> {
        if self.all_day(zone) {
            return human_date(t);
        }
        Some(match zone {
            Zone::Utc => format!("{} (UTC)", human(t)?),
            Zone::Floating => human(t)?,
            Zone::Tz(tz) => format!("{} ({})", human(t)?, tz.label(tz.to_utc(t))),
        })
    }

    fn attendee_summary(&self) -> Option<String> {
        if self.attendee_list.is_empty() {
            return self.attendees.clone();
        }
        let v: Vec<String> = self
            .attendee_list
            .iter()
            .filter_map(|a| {
                let who = a
                    .name
                    .as_deref()
                    .and_then(clean)
                    .or_else(|| a.email.as_deref().and_then(clean))?;
                let mut notes = Vec::new();
                match a.kind {
                    2 => notes.push("선택"),
                    3 => notes.push("자원"),
                    _ => {}
                }
                match a.status {
                    2 => notes.push("미정"),
                    3 => notes.push("수락"),
                    4 => notes.push("거절"),
                    _ => {}
                }
                Some(if notes.is_empty() {
                    who
                } else {
                    format!("{who}({})", notes.join(", "))
                })
            })
            .collect();
        (!v.is_empty()).then(|| v.join(", "))
    }

    /// 주최자·참석자
    fn participants(&self, o: &mut String) {
        if let Some(addr) = self.organizer_email.as_deref().and_then(mail_addr) {
            let cn = self
                .organizer
                .as_deref()
                .and_then(param_text)
                .map(|n| format!(";CN=\"{n}\""))
                .unwrap_or_default();
            fold(&format!("ORGANIZER{cn}:mailto:{addr}"), o);
        }
        for a in &self.attendee_list {
            let Some(addr) = a.email.as_deref().and_then(mail_addr) else {
                continue;
            };
            let mut p = String::new();
            if let Some(n) = a.name.as_deref().and_then(param_text) {
                p += &format!(";CN=\"{n}\"");
            }
            p += match a.kind {
                2 => ";ROLE=OPT-PARTICIPANT",
                3 => ";CUTYPE=RESOURCE;ROLE=NON-PARTICIPANT",
                _ => ";ROLE=REQ-PARTICIPANT",
            };
            p += match a.status {
                2 => ";PARTSTAT=TENTATIVE",
                3 => ";PARTSTAT=ACCEPTED",
                4 => ";PARTSTAT=DECLINED",
                _ => ";PARTSTAT=NEEDS-ACTION",
            };
            fold(&format!("ATTENDEE{p}:mailto:{addr}"), o);
        }
    }

    fn ics(&self, stamp: Option<u64>) -> Option<String> {
        let (zone, start, end) = self.times()?;
        let mut o = String::new();
        fold("BEGIN:VCALENDAR", &mut o);
        fold("VERSION:2.0", &mut o);
        fold("PRODID:-//CDR//Outlook item//KO", &mut o);
        if let Zone::Tz(tz) = &zone {
            tz.vtimezone(&mut o);
        }
        let start_s = ical_dt(start, false).unwrap_or_default();
        let id = uid(&[&self.summary, &start_s]);
        let dtstamp = stamp
            .map(ft_minutes)
            .or(self.start.map(ft_minutes))
            .and_then(|t| ical_dt(t, true))
            .unwrap_or_else(|| "19700101T000000Z".into());
        let mut end = end.filter(|&e| e >= start);
        if self.all_day(&zone) {
            // 종일 일정의 끝 날짜는 다음 날 (포함하지 않음)
            let day = |t: i64| t.div_euclid(1440);
            end = Some(end.map_or(start + 1440, |e| {
                if day(e) > day(start) && e.rem_euclid(1440) == 0 {
                    e
                } else {
                    (day(e) + 1) * 1440
                }
            }));
        }

        fold("BEGIN:VEVENT", &mut o);
        fold(&format!("UID:{id}"), &mut o);
        fold(&format!("DTSTAMP:{dtstamp}"), &mut o);
        fold(&self.when(&zone, "DTSTART", start)?, &mut o);
        if let Some(e) = end.and_then(|e| self.when(&zone, "DTEND", e)) {
            fold(&e, &mut o);
        }
        if let Some(r) = &self.recur {
            let until = r.until.and_then(|u| {
                if self.all_day(&zone) {
                    ical_date(u)
                } else {
                    let local = u + r.start_offset;
                    match &zone {
                        Zone::Tz(tz) => ical_dt(tz.to_utc(local), true),
                        _ => ical_dt(local, false),
                    }
                }
            });
            if r.lunar.is_some() {
                // 음력 반복은 RRULE 로 나타낼 수 없어(RSCALE 은 지원이 드묾) 회차를 양력으로 펼친다
                let dates: Vec<String> = r
                    .lunar_dates()
                    .into_iter()
                    .filter(|&d| d != start)
                    .filter_map(|d| {
                        let line = self.when(&zone, "RDATE", d)?;
                        Some(line.rsplit(':').next()?.to_string())
                    })
                    .collect();
                if !dates.is_empty() {
                    let head = self.when(&zone, "RDATE", start)?;
                    let head = &head[..head.rfind(':')?];
                    fold(&format!("{head}:{}", dates.join(",")), &mut o);
                }
            } else {
                fold(&format!("RRULE:{}", r.rrule(until)), &mut o);
            }
            let ex: Vec<String> = r
                .exdates()
                .into_iter()
                .filter_map(|d| {
                    let line = self.when(&zone, "EXDATE", d)?;
                    Some(line.rsplit(':').next()?.to_string())
                })
                .collect();
            if !ex.is_empty() {
                let head = self.when(&zone, "EXDATE", start)?;
                let head = &head[..head.rfind(':')?];
                fold(&format!("{head}:{}", ex.join(",")), &mut o);
            }
        }
        prop(&mut o, "SUMMARY", Some(&self.summary));
        prop(&mut o, "LOCATION", self.location.as_deref());
        prop(&mut o, "DESCRIPTION", Some(&description(&self.description)));
        if let Some(b) = self.busy {
            fold(
                if b {
                    "TRANSP:OPAQUE"
                } else {
                    "TRANSP:TRANSPARENT"
                },
                &mut o,
            );
        }
        self.participants(&mut o);
        if let Some(m) = self.reminder {
            display_alarm(&mut o, &format!("TRIGGER:-PT{m}M"), &self.summary);
        }
        fold("END:VEVENT", &mut o);

        // 바뀐 회차
        if let Some(r) = &self.recur {
            for e in &r.exceptions {
                // 이 회차만 종일로(또는 종일에서 시각으로) 바꾼 경우 (UTC 로 쓰는 일정은 날짜를 알 수 없음)
                let all_day = match e.all_day {
                    Some(v) if !matches!(zone, Zone::Utc) => v,
                    _ => self.all_day(&zone),
                };
                let (Some(rid), Some(s)) = (
                    self.when(&zone, "RECURRENCE-ID", e.original),
                    self.when_as(&zone, "DTSTART", e.start, all_day),
                ) else {
                    continue;
                };
                fold("BEGIN:VEVENT", &mut o);
                fold(&format!("UID:{id}"), &mut o);
                fold(&format!("DTSTAMP:{dtstamp}"), &mut o);
                fold(&rid, &mut o);
                fold(&s, &mut o);
                if e.end >= e.start {
                    let day = |t: i64| t.div_euclid(1440);
                    let end =
                        if all_day && !(day(e.end) > day(e.start) && e.end.rem_euclid(1440) == 0) {
                            (day(e.end) + 1) * 1440
                        } else {
                            e.end
                        };
                    if let Some(l) = self.when_as(&zone, "DTEND", end, all_day) {
                        fold(&l, &mut o);
                    }
                }
                if let Some(b) = e.busy.or(self.busy) {
                    fold(
                        if b {
                            "TRANSP:OPAQUE"
                        } else {
                            "TRANSP:TRANSPARENT"
                        },
                        &mut o,
                    );
                }
                prop(
                    &mut o,
                    "SUMMARY",
                    Some(e.subject.as_deref().unwrap_or(&self.summary)),
                );
                prop(
                    &mut o,
                    "LOCATION",
                    e.location.as_deref().or(self.location.as_deref()),
                );
                prop(&mut o, "DESCRIPTION", Some(&description(&self.description)));
                self.participants(&mut o);
                if let Some(m) = e.reminder(self.reminder) {
                    let subject = e.subject.as_deref().unwrap_or(&self.summary);
                    display_alarm(&mut o, &format!("TRIGGER:-PT{m}M"), subject);
                }
                fold("END:VEVENT", &mut o);
            }
        }
        fold("END:VCALENDAR", &mut o);
        Some(o)
    }
}

impl Item {
    /// 본문 앞에 붙일 요약
    pub fn summary(&self) -> String {
        let mut lines: Vec<String> = Vec::new();
        let mut add = |label: &str, v: Option<String>| {
            if let Some(v) = v.as_deref().and_then(clean) {
                lines.push(format!("{label}: {}", v.replace('\n', " ")));
            }
        };
        match self {
            Item::Event(e) => {
                add("일정", clean(&e.summary));
                if let Some((zone, start, end)) = e.times() {
                    add("시작", e.human(&zone, start));
                    add("종료", end.and_then(|t| e.human(&zone, t)));
                    add("종일", e.all_day(&zone).then(|| "예".into()));
                }
                add("반복", e.recur.as_ref().map(Recur::describe));
                add("장소", e.location.clone());
                add("주최자", e.organizer.clone());
                add("참석자", e.attendee_summary());
                add("알림", e.reminder.map(|m| format!("{m}분 전")));
            }
            Item::Task(t) => {
                add("작업", clean(&t.summary));
                let utc = |ft: u64| human(ft_minutes(ft)).map(|h| format!("{h} (UTC)"));
                add("시작", t.start.and_then(utc));
                add("기한", t.due.and_then(utc));
                add("진행률", t.percent.map(|p| format!("{:.0}%", p * 100.0)));
                add("반복", t.recur.as_ref().map(Recur::describe));
                add("알림", t.reminder.and_then(utc));
            }
            Item::Contact(c) => {
                add("연락처", c.display.clone());
                add("회사", c.company.clone());
                add("부서", c.department.clone());
                add("직함", c.title.clone());
                for e in &c.emails {
                    add("메일", Some(e.clone()));
                }
                for (k, v) in &c.phones {
                    add(&format!("전화({k})"), Some(v.clone()));
                }
                let adr: Vec<&str> = c.address.iter().flatten().map(String::as_str).collect();
                add("주소", (!adr.is_empty()).then(|| adr.join(" ")));
                let home: Vec<&str> = c
                    .home_address
                    .iter()
                    .flatten()
                    .map(String::as_str)
                    .collect();
                add("집 주소", (!home.is_empty()).then(|| home.join(" ")));
                add("별명", c.nickname.clone());
                add(
                    "생일",
                    c.birthday.and_then(nearest_date).and_then(human_date),
                );
                add(
                    "기념일",
                    c.anniversary.and_then(nearest_date).and_then(human_date),
                );
                for (k, v) in &c.extra {
                    add(k, Some(v.clone()));
                }
            }
        }
        if lines.is_empty() {
            return String::new();
        }
        format!("[Outlook 항목 정보]\n{}\n\n", lines.join("\n"))
    }

    /// `.ics` / `.vcf` 첨부
    pub fn attachment(&self, stamp: Option<u64>) -> Option<Generated> {
        let mut o = String::new();
        let (name, content_type) = match self {
            Item::Event(e) => {
                o = e.ics(stamp)?;
                ("event.ics", "text/calendar; charset=utf-8")
            }
            Item::Task(t) => {
                fold("BEGIN:VCALENDAR", &mut o);
                fold("VERSION:2.0", &mut o);
                fold("PRODID:-//CDR//Outlook item//KO", &mut o);
                fold("BEGIN:VTODO", &mut o);
                let due = t
                    .due
                    .and_then(|d| ical_dt(ft_minutes(d), true))
                    .unwrap_or_default();
                fold(&format!("UID:{}", uid(&[&t.summary, &due])), &mut o);
                utc_prop(&mut o, "DTSTAMP", stamp.or(t.start).or(t.due));
                if stamp.or(t.start).or(t.due).is_none() {
                    fold("DTSTAMP:19700101T000000Z", &mut o);
                }
                match &t.recur {
                    // 반복 작업은 날짜로 (RRULE 에는 DTSTART 가 있어야 하고, DUE 도 같은 형식)
                    Some(r) => {
                        let date = |ft: u64| ical_date(ft_minutes(ft));
                        let start = t.start.and_then(date).or_else(|| ical_date(r.start_date));
                        if let Some(d) = &start {
                            fold(&format!("DTSTART;VALUE=DATE:{d}"), &mut o);
                        }
                        if let Some(d) = t
                            .due
                            .and_then(date)
                            .filter(|d| start.as_ref().is_none_or(|s| d >= s))
                        {
                            fold(&format!("DUE;VALUE=DATE:{d}"), &mut o);
                        }
                        if start.is_some() && r.lunar.is_some() {
                            let dates: Vec<String> = r
                                .lunar_dates()
                                .into_iter()
                                .filter_map(ical_date)
                                .filter(|d| Some(d) != start.as_ref())
                                .collect();
                            if !dates.is_empty() {
                                fold(&format!("RDATE;VALUE=DATE:{}", dates.join(",")), &mut o);
                            }
                        } else if start.is_some() {
                            fold(
                                &format!("RRULE:{}", r.rrule(r.until.and_then(ical_date))),
                                &mut o,
                            );
                        }
                    }
                    None => {
                        utc_prop(&mut o, "DTSTART", t.start);
                        utc_prop(&mut o, "DUE", t.due);
                    }
                }
                prop(&mut o, "SUMMARY", Some(&t.summary));
                if let Some(p) = t.percent.filter(|p| p.is_finite()) {
                    fold(
                        &format!("PERCENT-COMPLETE:{}", (p * 100.0).clamp(0.0, 100.0) as u32),
                        &mut o,
                    );
                }
                prop(&mut o, "DESCRIPTION", Some(&description(&t.description)));
                if let Some(at) = t.reminder.and_then(|r| ical_dt(ft_minutes(r), true)) {
                    display_alarm(&mut o, &format!("TRIGGER;VALUE=DATE-TIME:{at}"), &t.summary);
                }
                fold("END:VTODO", &mut o);
                fold("END:VCALENDAR", &mut o);
                ("task.ics", "text/calendar; charset=utf-8")
            }
            Item::Contact(c) => {
                let fname = c.display.as_deref().and_then(clean).or_else(|| {
                    let n = format!(
                        "{} {}",
                        c.given.as_deref().unwrap_or(""),
                        c.surname.as_deref().unwrap_or("")
                    );
                    clean(&n)
                })?;
                fold("BEGIN:VCARD", &mut o);
                fold("VERSION:3.0", &mut o);
                fold(&format!("FN:{}", esc(&fname)), &mut o);
                fold(
                    &format!(
                        "N:{};{};;;",
                        esc(c
                            .surname
                            .as_deref()
                            .and_then(clean)
                            .as_deref()
                            .unwrap_or("")),
                        esc(c.given.as_deref().and_then(clean).as_deref().unwrap_or(""))
                    ),
                    &mut o,
                );
                if c.company.is_some() || c.department.is_some() {
                    fold(
                        &format!(
                            "ORG:{};{}",
                            esc(c
                                .company
                                .as_deref()
                                .and_then(clean)
                                .as_deref()
                                .unwrap_or("")),
                            esc(c
                                .department
                                .as_deref()
                                .and_then(clean)
                                .as_deref()
                                .unwrap_or(""))
                        ),
                        &mut o,
                    );
                }
                prop(&mut o, "TITLE", c.title.as_deref());
                prop(&mut o, "NICKNAME", c.nickname.as_deref());
                if let Some(d) = c.birthday.and_then(nearest_date).and_then(civil) {
                    fold(&format!("BDAY:{:04}-{:02}-{:02}", d.0, d.1, d.2), &mut o);
                }
                // vCard 3.0 에 없는 필드와 메모는 NOTE 로
                let mut note: Vec<String> = Vec::new();
                if let Some(d) = c.anniversary.and_then(nearest_date).and_then(human_date) {
                    note.push(format!("기념일: {d}"));
                }
                for (k, v) in &c.extra {
                    note.push(format!("{k}: {v}"));
                }
                if let Some(n) = clean(&description(&c.note)) {
                    note.push(n);
                }
                if !note.is_empty() {
                    prop(&mut o, "NOTE", Some(&note.join("\n")));
                }
                if c.home_address.iter().any(Option::is_some) {
                    let f = |i: usize| {
                        esc(c.home_address[i]
                            .as_deref()
                            .and_then(clean)
                            .as_deref()
                            .unwrap_or(""))
                    };
                    fold(
                        &format!(
                            "ADR;TYPE=HOME:;;{};{};{};{};{}",
                            f(0),
                            f(1),
                            f(2),
                            f(3),
                            f(4)
                        ),
                        &mut o,
                    );
                }
                if let Some((img, t)) = &c.photo {
                    use base64::Engine as _;
                    let b64 = base64::engine::general_purpose::STANDARD.encode(img);
                    fold(&format!("PHOTO;ENCODING=b;TYPE={t}:{b64}"), &mut o);
                }
                for e in &c.emails {
                    prop(&mut o, "EMAIL;TYPE=INTERNET", Some(e));
                }
                for (k, v) in &c.phones {
                    let t = match *k {
                        "휴대" => "CELL",
                        "집" | "집2" => "HOME",
                        "팩스" => "WORK,FAX",
                        "집 팩스" => "HOME,FAX",
                        "호출기" => "PAGER",
                        "자동차" => "CAR",
                        "기타" => "VOICE",
                        _ => "WORK",
                    };
                    prop(&mut o, &format!("TEL;TYPE={t}"), Some(v));
                }
                if c.address.iter().any(Option::is_some) {
                    let f = |i: usize| {
                        esc(c.address[i]
                            .as_deref()
                            .and_then(clean)
                            .as_deref()
                            .unwrap_or(""))
                    };
                    fold(
                        &format!(
                            "ADR;TYPE=WORK:;;{};{};{};{};{}",
                            f(0),
                            f(1),
                            f(2),
                            f(3),
                            f(4)
                        ),
                        &mut o,
                    );
                }
                fold("END:VCARD", &mut o);
                ("contact.vcf", "text/vcard; charset=utf-8")
            }
        };
        Some(Generated {
            name: name.to_string(),
            content_type,
            data: o.into_bytes(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ft(unix: u64) -> u64 {
        (unix + 11_644_473_600) * 10_000_000
    }

    #[test]
    fn event_is_escaped_and_folded() {
        let e = Item::Event(Event {
            summary: "회의; 1차, 검토\r\nBEGIN:VALARM".into(),
            start: Some(ft(1_704_164_645)),
            end: Some(ft(1_704_168_245)),
            location: Some("3층 회의실".into()),
            description: "x".repeat(200),
            ..Default::default()
        });
        let g = e.attachment(None).unwrap();
        let s = String::from_utf8(g.data).unwrap();
        assert!(s.contains("DTSTART:20240102T030400Z"));
        assert!(s.contains("SUMMARY:회의\\; 1차\\, 검토\\nBEGIN:VALARM"));
        assert!(!s.contains("\r\nBEGIN:VALARM"));
        assert!(s.lines().all(|l| l.len() <= 76), "{s}");
        assert!(e.summary().contains("장소: 3층 회의실"));
    }

    fn tz_struct(bias: i32, dst_bias: i32, std: [u16; 4], dst: [u16; 4]) -> Vec<u8> {
        let mut b = Vec::new();
        for v in [bias, 0, dst_bias] {
            b.extend(v.to_le_bytes());
        }
        for r in [std, dst] {
            b.extend(0u16.to_le_bytes());
            // wYear, wMonth, wDayOfWeek, wDay, wHour, 나머지
            for v in [0, r[0], r[1], r[2], r[3], 0, 0, 0] {
                b.extend(v.to_le_bytes());
            }
        }
        b
    }

    #[test]
    fn timezone_rules() {
        let m = minutes_of;
        // 미국 동부: 3월 둘째 일요일 2시 ~ 11월 첫째 일요일 2시
        let us = Tz::from_struct(&tz_struct(300, -60, [11, 0, 1, 2], [3, 0, 2, 2]), "E").unwrap();
        assert_eq!(us.to_local(m(2024, 3, 10, 6, 59)), m(2024, 3, 10, 1, 59));
        assert_eq!(us.to_local(m(2024, 3, 10, 7, 0)), m(2024, 3, 10, 3, 0));
        assert_eq!(us.to_local(m(2024, 11, 3, 5, 59)), m(2024, 11, 3, 1, 59));
        assert_eq!(us.to_local(m(2024, 11, 3, 6, 0)), m(2024, 11, 3, 1, 0));
        assert_eq!(us.to_utc(m(2024, 7, 1, 8, 0)), m(2024, 7, 1, 12, 0));
        assert_eq!(us.to_utc(m(2024, 1, 15, 7, 0)), m(2024, 1, 15, 12, 0));
        // 남반구 (시드니): 10월 첫째 일요일 2시 시작, 4월 첫째 일요일 3시 끝
        let au = Tz::from_struct(&tz_struct(-600, -60, [4, 0, 1, 3], [10, 0, 1, 2]), "S").unwrap();
        assert_eq!(au.to_local(m(2024, 1, 15, 0, 0)), m(2024, 1, 15, 11, 0));
        assert_eq!(au.to_local(m(2024, 7, 15, 0, 0)), m(2024, 7, 15, 10, 0));
        // "마지막 일요일" (유럽)
        let eu = Tz::from_struct(&tz_struct(-60, -60, [10, 0, 5, 3], [3, 0, 5, 2]), "C").unwrap();
        assert_eq!(
            Tz::transition(&eu.rules.unwrap().1, 2024),
            m(2024, 3, 31, 2, 0)
        );
        // TZDEFINITION: 효력 있는 규칙 하나, 일광 절약 없음
        let key: Vec<u16> = "Korea Standard Time".encode_utf16().collect();
        let mut d = vec![2u8, 1];
        let header = 2 + 2 + key.len() * 2 + 2;
        d.extend((header as u16).to_le_bytes());
        d.extend(0u16.to_le_bytes());
        d.extend((key.len() as u16).to_le_bytes());
        for u in &key {
            d.extend(u.to_le_bytes());
        }
        d.extend(1u16.to_le_bytes());
        d.extend([2u8, 1, 0, 0]);
        d.extend(2u16.to_le_bytes());
        d.extend(0u16.to_le_bytes());
        d.extend([0u8; 14]);
        d.extend(tz_struct(-540, 0, [0, 0, 0, 0], [0, 0, 0, 0])[..12].iter());
        d.extend([0u8; 32]);
        let kr = Tz::from_definition(&d).unwrap();
        assert_eq!(kr.name, "Korea Standard Time");
        assert_eq!(kr.to_local(m(2024, 1, 1, 0, 0)), m(2024, 1, 1, 9, 0));
        assert!(kr.rules.is_none());
        // 깨진 입력
        for n in 0..d.len() {
            let _ = Tz::from_definition(&d[..n]);
        }
    }

    #[test]
    fn contact_vcard() {
        let c = Item::Contact(Contact {
            display: Some("김철수".into()),
            surname: Some("김".into()),
            given: Some("철수".into()),
            company: Some("예시, 주식회사".into()),
            emails: vec!["kim@example.com".into()],
            phones: vec![("휴대", "010-0000-0000".into())],
            ..Default::default()
        });
        let s = String::from_utf8(c.attachment(None).unwrap().data).unwrap();
        assert!(s.contains("FN:김철수") && s.contains("N:김;철수;;;"));
        assert!(s.contains("ORG:예시\\, 주식회사;") && s.contains("TEL;TYPE=CELL:010-0000-0000"));
    }
}
