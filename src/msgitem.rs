//! Outlook 비메일 항목(일정·회의 요청·작업·연락처)의 정보를 표준 형식으로 옮긴다.
//!
//! 메일로 재조합하면 제목·본문·첨부만 남으므로, 항목 고유 정보(시간·장소·연락처 필드)를
//! 본문 앞 요약과 `.ics`(iCalendar) / `.vcf`(vCard) 첨부로 새로 만든다. 값은 모두
//! 이스케이프한 텍스트 필드로만 쓰고, 첨부·알림 동작·URL 같은 능동 요소는 만들지 않는다.

/// 항목 종류
pub enum Item {
    Event(Event),
    Task(Task),
    Contact(Contact),
}

#[derive(Default)]
pub struct Event {
    pub summary: String,
    /// FILETIME
    pub start: Option<u64>,
    pub end: Option<u64>,
    pub location: Option<String>,
    pub organizer: Option<String>,
    pub attendees: Option<String>,
    pub description: String,
}

#[derive(Default)]
pub struct Task {
    pub summary: String,
    pub start: Option<u64>,
    pub due: Option<u64>,
    pub percent: Option<f64>,
    pub description: String,
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
}

/// 생성된 첨부 (이름, MIME 형식, 내용)
pub struct Generated {
    pub name: String,
    pub content_type: &'static str,
    pub data: Vec<u8>,
}

/// FILETIME → (년, 월, 일, 시, 분, 초) UTC
pub fn civil(ft: u64) -> Option<(i64, i64, i64, i64, i64, i64)> {
    let secs = (ft / 10_000_000).checked_sub(11_644_473_600)? as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // civil_from_days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    if !(1970..=9999).contains(&year) {
        return None;
    }
    Some((year, month, day, rem / 3600, rem / 60 % 60, rem % 60))
}

fn ical_time(ft: u64) -> Option<String> {
    let (y, mo, d, h, mi, s) = civil(ft)?;
    Some(format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z"))
}

fn human_time(ft: u64) -> Option<String> {
    let (y, mo, d, h, mi, _) = civil(ft)?;
    Some(format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02} (UTC)"))
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

fn time_prop(out: &mut String, name: &str, ft: Option<u64>) {
    if let Some(t) = ft.and_then(ical_time) {
        fold(&format!("{name}:{t}"), out);
    }
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

/// 본문 설명은 너무 길면 자른다
fn description(s: &str) -> String {
    s.chars().take(32 * 1024).collect()
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
                add("시작", e.start.and_then(human_time));
                add("종료", e.end.and_then(human_time));
                add("장소", e.location.clone());
                add("주최자", e.organizer.clone());
                add("참석자", e.attendees.clone());
            }
            Item::Task(t) => {
                add("작업", clean(&t.summary));
                add("시작", t.start.and_then(human_time));
                add("기한", t.due.and_then(human_time));
                add("진행률", t.percent.map(|p| format!("{:.0}%", p * 100.0)));
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
                e.start?;
                fold("BEGIN:VCALENDAR", &mut o);
                fold("VERSION:2.0", &mut o);
                fold("PRODID:-//CDR//Outlook item//KO", &mut o);
                fold("BEGIN:VEVENT", &mut o);
                let start = e.start.and_then(ical_time).unwrap_or_default();
                fold(&format!("UID:{}", uid(&[&e.summary, &start])), &mut o);
                time_prop(&mut o, "DTSTAMP", stamp.or(e.start));
                time_prop(&mut o, "DTSTART", e.start);
                time_prop(&mut o, "DTEND", e.end);
                prop(&mut o, "SUMMARY", Some(&e.summary));
                prop(&mut o, "LOCATION", e.location.as_deref());
                prop(&mut o, "DESCRIPTION", Some(&description(&e.description)));
                fold("END:VEVENT", &mut o);
                fold("END:VCALENDAR", &mut o);
                ("event.ics", "text/calendar; charset=utf-8")
            }
            Item::Task(t) => {
                fold("BEGIN:VCALENDAR", &mut o);
                fold("VERSION:2.0", &mut o);
                fold("PRODID:-//CDR//Outlook item//KO", &mut o);
                fold("BEGIN:VTODO", &mut o);
                let due = t.due.and_then(ical_time).unwrap_or_default();
                fold(&format!("UID:{}", uid(&[&t.summary, &due])), &mut o);
                time_prop(&mut o, "DTSTAMP", stamp.or(t.start).or(t.due));
                if stamp.or(t.start).or(t.due).is_none() {
                    fold("DTSTAMP:19700101T000000Z", &mut o);
                }
                time_prop(&mut o, "DTSTART", t.start);
                time_prop(&mut o, "DUE", t.due);
                prop(&mut o, "SUMMARY", Some(&t.summary));
                if let Some(p) = t.percent.filter(|p| p.is_finite()) {
                    fold(
                        &format!("PERCENT-COMPLETE:{}", (p * 100.0).clamp(0.0, 100.0) as u32),
                        &mut o,
                    );
                }
                prop(&mut o, "DESCRIPTION", Some(&description(&t.description)));
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
                for e in &c.emails {
                    prop(&mut o, "EMAIL;TYPE=INTERNET", Some(e));
                }
                for (k, v) in &c.phones {
                    let t = match *k {
                        "휴대" => "CELL",
                        "집" => "HOME",
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
        assert!(s.contains("DTSTART:20240102T030405Z"));
        assert!(s.contains("SUMMARY:회의\\; 1차\\, 검토\\nBEGIN:VALARM"));
        assert!(!s.contains("\r\nBEGIN:VALARM"));
        assert!(s.lines().all(|l| l.len() <= 76), "{s}");
        assert!(e.summary().contains("장소: 3층 회의실"));
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
