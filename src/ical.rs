//! iCalendar(.ics)·vCard(.vcf) 재조합.
//!
//! 줄을 해석해 허용된 구성 요소와 속성만 새로 쓴다. 알림(VALARM)은 화면 표시(DISPLAY)만
//! 옮기고 명령 실행·소리·메일 발송 동작은 뺀다. 첨부(ATTACH, 내장 바이너리 포함), URL·소리·키,
//! 확장 속성(X-*)은 옮기지 않는다. vCard 사진은 문서 안 그림(base64)만 화소를 재인코딩해 옮긴다.
//! 텍스트 값은 이스케이프를 풀었다가 다시 이스케이프하고, 날짜·반복 규칙은 문자 집합을
//! 검사한다. 줄은 75 옥텟으로 접어 CRLF 로 쓴다.

use base64::Engine as _;

use crate::error::{blocked, Result};
use crate::imaging::{self, ImageKind};
use crate::legacy::blip::PixelBudget;
use crate::policy::Policy;
use crate::report::{Findings, Severity};

/// 최대 줄(펼친 뒤) 수와 중첩 깊이
const MAX_LINES: usize = 200_000;
const MAX_DEPTH: usize = 8;

/// 구성 요소별 허용 속성
fn allowed(component: &str, name: &str) -> Option<Kind> {
    use Kind::*;
    Some(match (component, name) {
        ("VCALENDAR", "VERSION" | "PRODID" | "CALSCALE" | "METHOD") => Text,
        ("VEVENT" | "VTODO", n) => match n {
            "SUMMARY" | "LOCATION" | "DESCRIPTION" | "STATUS" | "CLASS" | "TRANSP" => Text,
            "UID" => Text,
            "CATEGORIES" => List,
            "DTSTAMP" | "DTSTART" | "DTEND" | "DUE" | "COMPLETED" | "CREATED" | "LAST-MODIFIED"
            | "RECURRENCE-ID" | "EXDATE" => Date,
            "DURATION" | "RRULE" | "PRIORITY" | "SEQUENCE" | "PERCENT-COMPLETE" => Token,
            "ORGANIZER" | "ATTENDEE" => Mailto,
            _ => return None,
        },
        ("VALARM", n) => match n {
            "ACTION" | "TRIGGER" | "REPEAT" | "DURATION" => Token,
            "DESCRIPTION" => Text,
            _ => return None,
        },
        ("VTIMEZONE", "TZID") => Text,
        ("STANDARD" | "DAYLIGHT", n) => match n {
            "DTSTART" => Date,
            "TZOFFSETFROM" | "TZOFFSETTO" | "RRULE" => Token,
            "TZNAME" => Text,
            _ => return None,
        },
        ("VCARD", n) => match n {
            "VERSION" | "FN" | "TITLE" | "NOTE" | "NICKNAME" | "ROLE" | "EMAIL" | "TEL" | "UID" => {
                Text
            }
            "N" | "ADR" | "ORG" => Structured,
            "BDAY" | "REV" => Date,
            "PHOTO" => Photo,
            _ => return None,
        },
        _ => return None,
    })
}

/// 허용 구성 요소 (부모, 자식)
fn allowed_child(parent: Option<&str>, child: &str) -> bool {
    matches!(
        (parent, child),
        (None, "VCALENDAR" | "VCARD")
            | (Some("VCALENDAR"), "VEVENT" | "VTODO" | "VTIMEZONE")
            | (Some("VEVENT" | "VTODO"), "VALARM")
            | (Some("VTIMEZONE"), "STANDARD" | "DAYLIGHT")
    )
}

#[derive(Clone, Copy)]
enum Kind {
    /// 자유 텍스트
    Text,
    /// 쉼표 목록 텍스트
    List,
    /// 세미콜론 구조 텍스트 (N, ADR, ORG)
    Structured,
    /// 날짜·시각 (쉼표 목록 허용)
    Date,
    /// 기간·반복 규칙·숫자
    Token,
    /// mailto: 주소
    Mailto,
    /// 문서 안 그림 (base64)
    Photo,
}

/// .ics / .vcf 로 보이는지
pub fn looks_like(data: &[u8]) -> bool {
    let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
    let head: Vec<u8> = data
        .iter()
        .skip_while(|c| c.is_ascii_whitespace())
        .take(16)
        .map(u8::to_ascii_uppercase)
        .collect();
    head.starts_with(b"BEGIN:VCALENDAR") || head.starts_with(b"BEGIN:VCARD")
}

/// 텍스트 값의 이스케이프를 푼다
fn unescape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut it = v.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('n' | 'N') => out.push('\n'),
            Some(c) => out.push(c),
            None => {}
        }
    }
    out
}

/// 텍스트 값 이스케이프 (제어·양방향 재정의 문자 제거)
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            '\n' => out.push_str("\\n"),
            c if c.is_control() || crate::text::is_bidi_control(c) => {}
            c => out.push(c),
        }
    }
    out
}

/// 이스케이프되지 않은 구분자로 나눈다
fn split_unescaped(v: &str, sep: char) -> Vec<String> {
    let mut parts = vec![String::new()];
    let mut esc = false;
    for c in v.chars() {
        if esc {
            parts.last_mut().unwrap().push('\\');
            parts.last_mut().unwrap().push(c);
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else if c == sep {
            parts.push(String::new());
        } else {
            parts.last_mut().unwrap().push(c);
        }
    }
    parts
}

/// 한 줄을 75 옥텟 이하로 접는다 (RFC 5545 3.1, RFC 6350 3.2)
pub fn fold(line: &str, out: &mut String) {
    let mut len = 0;
    for c in line.chars() {
        let n = c.len_utf8();
        if len + n > 75 {
            out.push_str("\r\n ");
            len = 1;
        }
        out.push(c);
        len += n;
    }
    out.push_str("\r\n");
}

/// 매개변수: TYPE·VALUE·TZID·CN·LANGUAGE 와 참석자·알림 매개변수(ROLE·PARTSTAT·CUTYPE·RELATED)만,
/// 값은 안전한 문자만
fn params(raw: &[&str]) -> String {
    let mut out = String::new();
    for p in raw {
        let Some((k, v)) = p.split_once('=') else {
            continue;
        };
        let k = k.trim().to_ascii_uppercase();
        let v = v.trim().trim_matches('"');
        let ok = match k.as_str() {
            "TYPE" | "VALUE" | "LANGUAGE" | "ROLE" | "PARTSTAT" | "CUTYPE" | "RELATED" => {
                !v.is_empty()
                    && v.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | ','))
            }
            "TZID" | "CN" => {
                !v.is_empty() && !v.chars().any(|c| c.is_control() || "\";:\\".contains(c))
            }
            _ => false,
        };
        if !ok {
            continue;
        }
        if k == "CN" || k == "TZID" {
            out.push_str(&format!(";{k}=\"{v}\""));
        } else {
            out.push_str(&format!(";{k}={v}"));
        }
    }
    out
}

fn value(kind: Kind, v: &str) -> Option<String> {
    let token_ok = |s: &str, extra: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
    };
    Some(match kind {
        Kind::Text => escape(&unescape(v)),
        Kind::List => split_unescaped(v, ',')
            .iter()
            .map(|p| escape(&unescape(p)))
            .collect::<Vec<_>>()
            .join(","),
        Kind::Structured => split_unescaped(v, ';')
            .iter()
            .map(|p| {
                split_unescaped(p, ',')
                    .iter()
                    .map(|q| escape(&unescape(q)))
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .collect::<Vec<_>>()
            .join(";"),
        Kind::Date if token_ok(v, "TZ,:-+") && v.len() <= 4096 => v.to_string(),
        Kind::Token if token_ok(v, "=;,:-+") && v.len() <= 1024 => v.to_string(),
        Kind::Mailto => {
            let addr = v
                .get(..7)
                .filter(|p| p.eq_ignore_ascii_case("mailto:"))
                .map(|_| &v[7..])?;
            if addr.is_empty()
                || addr
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control() || "<>\"\\".contains(c))
            {
                return None;
            }
            format!("mailto:{addr}")
        }
        _ => return None,
    })
}

/// 줄을 이름·매개변수·값으로 나눈다 (따옴표 안의 `;`·`:` 는 구분자가 아님)
fn split_line(line: &str) -> Option<(String, Vec<&str>, &str)> {
    let mut quote = false;
    let mut colon = None;
    let mut semis = Vec::new();
    for (i, c) in line.char_indices() {
        match c {
            '"' => quote = !quote,
            ';' if !quote => semis.push(i),
            ':' if !quote => {
                colon = Some(i);
                break;
            }
            _ => {}
        }
    }
    let colon = colon?;
    let name_end = semis.first().copied().unwrap_or(colon);
    let name = line[..name_end].trim();
    // 그룹 접두어(vCard `item1.EMAIL`)는 뺀다
    let name = name.rsplit('.').next().unwrap_or(name).to_ascii_uppercase();
    let mut params = Vec::new();
    for (k, &s) in semis.iter().enumerate() {
        let e = semis.get(k + 1).copied().unwrap_or(colon);
        params.push(&line[s + 1..e]);
    }
    Some((name, params, &line[colon + 1..]))
}

/// vCard 사진: `ENCODING=b` (3.0) 또는 `data:` URI (4.0) 의 그림을 재인코딩한다
fn photo(
    params_raw: &[&str],
    v: &str,
    v4: bool,
    policy: &Policy,
    budget: &mut PixelBudget,
) -> Result<Option<String>> {
    let b64 = if let Some(rest) = v.trim().strip_prefix("data:") {
        match rest.split_once(',') {
            Some((meta, d)) if meta.to_ascii_lowercase().ends_with(";base64") => d,
            _ => return Ok(None),
        }
    } else if params_raw.iter().any(|p| {
        p.split_once('=').is_some_and(|(k, v)| {
            k.trim().eq_ignore_ascii_case("ENCODING")
                && matches!(v.trim().to_ascii_lowercase().as_str(), "b" | "base64")
        })
    }) {
        v
    } else {
        // URL 을 가리키는 사진
        return Ok(None);
    };
    let clean: String = b64.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(clean.as_bytes()) else {
        return Ok(None);
    };
    let Some(kind) = ImageKind::sniff(&bytes) else {
        return Ok(None);
    };
    budget.charge(&bytes, kind)?;
    let Ok((img, out)) = imaging::reencode(&bytes, kind, policy) else {
        return Ok(None);
    };
    let enc = base64::engine::general_purpose::STANDARD.encode(img);
    Ok(Some(if v4 {
        format!("PHOTO:data:{};base64,{enc}", out.mime())
    } else {
        let t = match out {
            ImageKind::Jpeg => "JPEG",
            ImageKind::Gif => "GIF",
            _ => "PNG",
        };
        format!("PHOTO;ENCODING=b;TYPE={t}:{enc}")
    }))
}

/// .ics / .vcf 를 재조합한다
pub fn reassemble(data: &[u8], policy: &Policy, findings: &mut Findings) -> Result<Vec<u8>> {
    let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
    let Ok(text) = std::str::from_utf8(data) else {
        return blocked("structure", "UTF-8 이 아닌 iCalendar·vCard");
    };
    // 줄 펼치기
    let mut lines: Vec<String> = Vec::new();
    for raw in text.split('\n') {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some(cont) = raw.strip_prefix([' ', '\t']) {
            if let Some(last) = lines.last_mut() {
                last.push_str(cont);
                continue;
            }
        }
        if raw.trim().is_empty() {
            continue;
        }
        if lines.len() >= MAX_LINES {
            return blocked("resource", "iCalendar·vCard 줄 수 초과");
        }
        lines.push(raw.to_string());
    }

    let mut out = String::new();
    let mut stack: Vec<(String, bool)> = Vec::new();
    let (mut dropped_props, mut dropped_comps, mut alarms) = (0u64, 0u64, 0u64);
    let mut top = 0usize;
    let mut budget = PixelBudget::new(policy);
    let (mut photos, mut v4) = (0u64, false);
    // 알림: 시작 위치, 동작이 DISPLAY 인지, TRIGGER 가 있는지
    let mut alarm: Option<(usize, bool, bool)> = None;
    for line in &lines {
        let Some((name, params_raw, v)) = split_line(line) else {
            dropped_props += 1;
            continue;
        };
        let keep = stack.last().is_none_or(|(_, k)| *k);
        match name.as_str() {
            "BEGIN" => {
                let comp = v.trim().to_ascii_uppercase();
                if stack.len() >= MAX_DEPTH {
                    return blocked("resource", "iCalendar·vCard 중첩 깊이 초과");
                }
                let parent = stack.last().map(|(c, _)| c.as_str());
                let ok = keep && allowed_child(parent, &comp);
                if keep && !ok {
                    dropped_comps += 1;
                    if comp == "VALARM" {
                        alarms += 1;
                    }
                }
                if ok {
                    if stack.is_empty() {
                        top += 1;
                    }
                    if comp == "VALARM" {
                        alarm = Some((out.len(), false, false));
                    }
                    if comp == "VCARD" {
                        v4 = false;
                    }
                    fold(&format!("BEGIN:{comp}"), &mut out);
                }
                stack.push((comp, ok));
            }
            "END" => {
                let comp = v.trim().to_ascii_uppercase();
                match stack.pop() {
                    Some((c, ok)) if c == comp => {
                        if ok && comp == "VALARM" {
                            // 화면에 표시하는 알림만 남긴다
                            match alarm.take() {
                                Some((_, true, true)) => fold("END:VALARM", &mut out),
                                Some((start, _, _)) => {
                                    out.truncate(start);
                                    alarms += 1;
                                    dropped_comps += 1;
                                }
                                None => {}
                            }
                        } else if ok {
                            fold(&format!("END:{comp}"), &mut out);
                        }
                    }
                    _ => return blocked("structure", "iCalendar·vCard 구성 요소 짝이 맞지 않음"),
                }
            }
            _ => {
                let Some((comp, true)) = stack.last() else {
                    if stack.is_empty() {
                        dropped_props += 1;
                    }
                    continue;
                };
                let kind = allowed(comp, &name);
                if matches!(kind, Some(Kind::Photo)) {
                    match photo(&params_raw, v, v4, policy, &mut budget)? {
                        Some(line) => {
                            photos += 1;
                            fold(&line, &mut out);
                        }
                        None => dropped_props += 1,
                    }
                    continue;
                }
                match kind.and_then(|k| value(k, v)) {
                    Some(val) => {
                        if comp == "VCARD" && name == "VERSION" {
                            v4 = val.starts_with('4');
                        }
                        if let Some(a) = alarm.as_mut().filter(|_| comp == "VALARM") {
                            match name.as_str() {
                                "ACTION" => a.1 = val.eq_ignore_ascii_case("DISPLAY"),
                                "TRIGGER" => a.2 = true,
                                _ => {}
                            }
                        }
                        fold(&format!("{name}{}:{val}", params(&params_raw)), &mut out)
                    }
                    None => dropped_props += 1,
                }
            }
        }
    }
    if !stack.is_empty() {
        return blocked("structure", "닫히지 않은 iCalendar·vCard 구성 요소");
    }
    if top == 0 {
        return blocked("structure", "VCALENDAR·VCARD 구성 요소가 없음");
    }
    if alarms > 0 {
        findings.add(
            "active-content",
            Severity::Medium,
            format!("화면 표시가 아닌 일정 알림(VALARM) {alarms}개 제거 (명령 실행·소리·메일 발송 동작)"),
            "",
        );
    }
    if photos > 0 {
        findings.count("images_reencoded", photos);
    }
    if dropped_props + dropped_comps > alarms {
        findings.add(
            "calendar",
            Severity::Low,
            format!(
                "허용 목록 밖 속성 {dropped_props}개·구성 요소 {}개를 옮기지 않음 (첨부·URL·외부 사진·확장 속성 등)",
                dropped_comps - alarms
            ),
            "",
        );
    }
    Ok(out.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calendar_is_rebuilt() {
        let src = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//y\r\nX-WR-CALNAME:cal\r\nBEGIN:VEVENT\r\nUID:1@x\r\nDTSTART;TZID=\"Asia/Seoul\":20240102T030405\r\nSUMMARY:회의\\, 1차\r\n  이어짐\r\nATTACH;ENCODING=BASE64;VALUE=BINARY:TVqQAAMAAAAEAAAA\r\nURL:http://evil.example/\r\nORGANIZER;CN=\"Kim\";SENT-BY=\"mailto:x@y\":mailto:kim@example.com\r\nATTENDEE:http://evil.example\r\nBEGIN:VALARM\r\nACTION:PROCEDURE\r\nATTACH:file:///bin/sh\r\nEND:VALARM\r\nBEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER;RELATED=START:-PT15M\r\nDESCRIPTION:알림\r\nATTACH:http://evil.example/a\r\nEND:VALARM\r\nBEGIN:VALARM\r\nACTION:AUDIO\r\nTRIGGER:-PT5M\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let mut f = Findings::default();
        let out =
            String::from_utf8(reassemble(src.as_bytes(), &Policy::default(), &mut f).unwrap())
                .unwrap();
        for bad in [
            "X-WR",
            "ATTACH",
            "evil",
            "PROCEDURE",
            "AUDIO",
            "SENT-BY",
            "TVqQ",
        ] {
            assert!(!out.contains(bad), "{bad}:\n{out}");
        }
        assert!(out.contains("DTSTART;TZID=\"Asia/Seoul\":20240102T030405"));
        assert!(out.contains("SUMMARY:회의\\, 1차 이어짐"));
        assert!(out.contains("ORGANIZER;CN=\"Kim\":mailto:kim@example.com"));
        // 화면 표시 알림만 남는다
        assert_eq!(out.matches("BEGIN:VALARM").count(), 1, "{out}");
        assert!(out.contains(
            "BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER;RELATED=START:-PT15M\r\nDESCRIPTION:알림\r\nEND:VALARM"
        ));
        assert!(f.items.iter().any(|x| x.category == "active-content"));
        let mut g = Findings::default();
        assert_eq!(
            reassemble(out.as_bytes(), &Policy::default(), &mut g).unwrap(),
            out.as_bytes()
        );
        assert!(g.items.is_empty());
    }

    #[test]
    fn vcard_is_rebuilt() {
        let png = {
            let img = image::RgbImage::from_pixel(3, 2, image::Rgb([200, 10, 10]));
            let mut b = Vec::new();
            img.write_to(&mut std::io::Cursor::new(&mut b), image::ImageFormat::Png)
                .unwrap();
            b.extend(b"<?php evil(); ?>");
            base64::engine::general_purpose::STANDARD.encode(b)
        };
        let src = format!("BEGIN:VCARD\nVERSION:3.0\nFN:김철수\nN:김;철수;;;\nitem1.EMAIL;TYPE=INTERNET:kim@example.com\nPHOTO;ENCODING=b;TYPE=JPEG:/9j/4AAQ\nPHOTO;VALUE=URI:http://evil.example/p.jpg\nPHOTO;ENCODING=b;TYPE=PNG:{png}\nORG:예시\\, 주식회사;개발\nEND:VCARD\nBEGIN:VCARD\nVERSION:4.0\nFN:x\nPHOTO:data:image/png;base64,{png}\nEND:VCARD\n");
        let mut f = Findings::default();
        let out =
            String::from_utf8(reassemble(src.as_bytes(), &Policy::default(), &mut f).unwrap())
                .unwrap();
        // 깨진 사진·URL 사진은 빠지고, 문서 안 그림은 재인코딩되어 남는다
        assert_eq!(out.matches("PHOTO").count(), 2, "{out}");
        assert!(!out.contains("evil") && !out.contains("/9j/4AAQ"));
        assert!(out.contains("PHOTO;ENCODING=b;TYPE=PNG:iVBOR"));
        assert!(out.contains("PHOTO:data:image/png;base64,iVBOR"));
        let flat = out.replace("\r\n ", "");
        let b64 = flat
            .split("TYPE=PNG:")
            .nth(1)
            .unwrap()
            .split("\r\n")
            .next()
            .unwrap();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        assert!(!bytes.windows(5).any(|w| w == b"<?php"));
        let mut g = Findings::default();
        assert_eq!(
            reassemble(out.as_bytes(), &Policy::default(), &mut g).unwrap(),
            out.as_bytes()
        );
        assert!(out.contains("EMAIL;TYPE=INTERNET:kim@example.com"));
        assert!(out.contains("ORG:예시\\, 주식회사;개발"));
        assert!(out.contains("N:김;철수;;;"));
    }

    #[test]
    fn broken_structure_is_blocked() {
        let mut f = Findings::default();
        let p = Policy::default();
        assert!(reassemble(
            b"BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nEND:VCALENDAR\r\n",
            &p,
            &mut f
        )
        .is_err());
        assert!(reassemble(b"SUMMARY:x\r\n", &p, &mut f).is_err());
    }
}
