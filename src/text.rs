//! 텍스트·CSV 재조합.
//!
//! 스크립트(.bat/.vbs/.js/.hta 등)도 텍스트이므로 내용만으로는 판단하지 않는다.
//! 허용한 확장자(txt, csv, tsv, log)이면서 문자 인코딩으로 온전히 해석되는 경우에만 받는다.
//! - 문자열을 디코딩한 뒤 제어 문자(탭·줄바꿈 제외)와 양방향 텍스트 재정의 문자(표시 순서를
//!   뒤집어 내용·파일명을 위장하는 데 쓰임)를 제거하고, 원래 인코딩으로 다시 쓴다.
//! - CSV/TSV: 스프레드시트에서 수식으로 실행될 수 있는 셀(=, +, -, @ 로 시작하고 순수한 숫자가
//!   아닌 값, 탭·CR 로 시작하는 값)은 앞에 작은따옴표를 붙여 문자열로 만든다(수식·DDE 주입 방어).

use crate::error::{blocked, Result};
use crate::report::{Findings, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Text,
    /// 구분 문자
    Delimited(char),
}

/// 텍스트로 받는 확장자
pub fn kind_for_extension(ext: &str) -> Option<Kind> {
    match ext {
        "txt" | "log" => Some(Kind::Text),
        "csv" => Some(Kind::Delimited(',')),
        "tsv" | "tab" => Some(Kind::Delimited('\t')),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Utf8 {
        bom: bool,
    },
    Utf16Le,
    Utf16Be,
    /// 한국어 Windows 기본 인코딩(CP949/EUC-KR)
    Cp949,
}

/// 문자 인코딩을 판별해 디코딩한다. 어떤 인코딩으로도 온전히 해석되지 않으면(이진 데이터) None
fn decode(data: &[u8]) -> Option<(String, Encoding)> {
    if let Some(rest) = data.strip_prefix(b"\xEF\xBB\xBF") {
        return std::str::from_utf8(rest)
            .ok()
            .map(|s| (s.to_string(), Encoding::Utf8 { bom: true }));
    }
    for (bom, enc, codec) in [
        (&b"\xFF\xFE"[..], Encoding::Utf16Le, encoding_rs::UTF_16LE),
        (&b"\xFE\xFF"[..], Encoding::Utf16Be, encoding_rs::UTF_16BE),
    ] {
        if let Some(rest) = data.strip_prefix(bom) {
            let (s, had_errors) = codec.decode_without_bom_handling(rest);
            return (!had_errors).then(|| (s.into_owned(), enc));
        }
    }
    if data.contains(&0) {
        return None;
    }
    if let Ok(s) = std::str::from_utf8(data) {
        return Some((s.to_string(), Encoding::Utf8 { bom: false }));
    }
    let (s, had_errors) = encoding_rs::EUC_KR.decode_without_bom_handling(data);
    (!had_errors).then(|| (s.into_owned(), Encoding::Cp949))
}

fn encode(s: &str, enc: Encoding) -> Vec<u8> {
    match enc {
        Encoding::Utf8 { bom } => {
            let mut out = if bom {
                b"\xEF\xBB\xBF".to_vec()
            } else {
                Vec::new()
            };
            out.extend(s.as_bytes());
            out
        }
        Encoding::Utf16Le => {
            let mut out = b"\xFF\xFE".to_vec();
            out.extend(s.encode_utf16().flat_map(u16::to_le_bytes));
            out
        }
        Encoding::Utf16Be => {
            let mut out = b"\xFE\xFF".to_vec();
            out.extend(s.encode_utf16().flat_map(u16::to_be_bytes));
            out
        }
        // 디코딩에 성공한 문자열만 다시 쓰므로 CP949 로 모두 표현된다
        Encoding::Cp949 => encoding_rs::EUC_KR.encode(s).0.into_owned(),
    }
}

/// 양방향 텍스트 재정의·격리·방향 표시 문자 (RLO, LRM, RLM, ALM 등)
pub fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}'
    )
}

/// 파일 이름에서 표시 순서를 바꾸는 문자와 제어 문자를 뺀다 (`exe.pdf` 위장 방지)
pub fn strip_spoofing(name: &str) -> String {
    name.chars()
        .filter(|&c| !is_bidi_control(c) && !c.is_control())
        .collect()
}

fn clean(s: &str, findings: &mut Findings) -> String {
    let (mut controls, mut bidi) = (0u64, 0u64);
    let out: String = s
        .chars()
        .filter(|&c| {
            if is_bidi_control(c) {
                bidi += 1;
                false
            } else if c.is_control() && !matches!(c, '\t' | '\n' | '\r') {
                controls += 1;
                false
            } else {
                true
            }
        })
        .collect();
    if bidi > 0 {
        findings.add(
            "text-spoofing",
            Severity::Low,
            format!("양방향 텍스트 재정의 문자 {bidi}개 제거"),
            "",
        );
    }
    if controls > 0 {
        findings.add(
            "hidden-data",
            Severity::Low,
            format!("제어 문자 {controls}개 제거"),
            "",
        );
    }
    out
}

pub fn reassemble(data: &[u8], kind: Kind, findings: &mut Findings) -> Result<Vec<u8>> {
    let Some((text, enc)) = decode(data) else {
        return blocked(
            "unsupported",
            "텍스트 확장자이지만 문자 인코딩으로 해석되지 않음(이진 데이터)",
        );
    };
    let text = clean(&text, findings);
    let text = match kind {
        Kind::Text => text,
        Kind::Delimited(_) => {
            let (out, neutralized) = neutralize_csv(&text);
            if neutralized > 0 {
                findings.add(
                    "formula-injection",
                    Severity::High,
                    format!("수식으로 실행될 수 있는 셀 {neutralized}개를 문자열로 변환"),
                    "",
                );
            }
            out
        }
    };
    findings.count("text_chars", text.chars().count() as u64);
    Ok(encode(&text, enc))
}

fn is_plain_number(s: &str) -> bool {
    let t = s.strip_prefix(['+', '-']).unwrap_or(s);
    !t.is_empty()
        && t.chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '.' | ',' | 'e' | 'E' | '+' | '-'))
        && t.chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit() || c == '.')
        && t.chars().filter(|&c| matches!(c, '+' | '-')).count() <= 1
        && t.chars()
            .zip(t.chars().skip(1))
            .all(|(a, b)| !matches!(b, '+' | '-') || matches!(a, 'e' | 'E'))
}

/// 셀 경계로 보는 문자. 스프레드시트는 로케일·인코딩에 따라 쉼표, 세미콜론, 탭 중 무엇으로도
/// 나눌 수 있으므로(첫 줄로 구분자를 추정하면 공격자가 정할 수 있다) 모두 경계로 보고 검사한다.
const BOUNDARIES: [char; 3] = [',', ';', '\t'];

fn dangerous_cell(value: &str) -> bool {
    // 가져올 때 앞 공백을 지우는 프로그램이 있으므로 공백 뒤 첫 글자로 판정하고,
    // 전각 기호(＝＋－＠)는 반각으로 본다
    let value = value.trim_start_matches([' ', '\u{3000}', '\u{00A0}']);
    let first = value.chars().next().map(|c| match c {
        '\u{FF1D}' => '=',
        '\u{FF0B}' => '+',
        '\u{FF0D}' => '-',
        '\u{FF20}' => '@',
        c => c,
    });
    match first {
        Some('=') | Some('@') | Some('\t') | Some('\r') => true,
        // 부호만 있는 셀(보고서의 "-" 표시 등)은 수식이 될 수 없다
        Some('+') | Some('-') => {
            let t = value.trim();
            !t.chars().all(|c| matches!(c, '+' | '-')) && !is_plain_number(t)
        }
        _ => false,
    }
}

/// RFC 4180 방식으로 셀을 나눠 위험한 셀만 고친다. 따옴표·구분자·줄바꿈 구조는 그대로 둔다.
fn neutralize_csv(text: &str) -> (String, u64) {
    let mut out = String::with_capacity(text.len() + 16);
    let mut count = 0u64;
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    let mut at_cell_start = true;
    while i < chars.len() {
        if at_cell_start {
            at_cell_start = false;
            if chars[i] == '"' {
                // 따옴표 셀: 닫는 따옴표까지 값을 모은다
                let mut j = i + 1;
                let mut value = String::new();
                while j < chars.len() {
                    if chars[j] == '"' {
                        if chars.get(j + 1) == Some(&'"') {
                            value.push('"');
                            j += 2;
                            continue;
                        }
                        break;
                    }
                    value.push(chars[j]);
                    j += 1;
                }
                out.push('"');
                if dangerous_cell(&value) {
                    out.push('\'');
                    count += 1;
                }
                out.extend(&chars[i + 1..j.min(chars.len())]);
                if j < chars.len() {
                    out.push('"');
                }
                i = j + 1;
                continue;
            }
            // 따옴표 없는 셀
            let end = chars[i..]
                .iter()
                .position(|&c| BOUNDARIES.contains(&c) || c == '\n' || c == '\r')
                .map_or(chars.len(), |p| i + p);
            let value: String = chars[i..end].iter().collect();
            if dangerous_cell(&value) {
                out.push('\'');
                count += 1;
            }
            out.push_str(&value);
            i = end;
            continue;
        }
        let c = chars[i];
        out.push(c);
        // 구분자·줄바꿈(단독 CR 포함) 다음은 새 셀
        if BOUNDARIES.contains(&c) || c == '\n' || (c == '\r' && chars.get(i + 1) != Some(&'\n')) {
            at_cell_start = true;
        }
        i += 1;
    }
    (out, count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(data: &[u8], kind: Kind) -> (Vec<u8>, Findings) {
        let mut f = Findings::default();
        let out = reassemble(data, kind, &mut f).unwrap();
        (out, f)
    }

    #[test]
    fn csv_formulas_are_neutralized() {
        let src = "name,value,note\n\
                   a,=cmd|' /C calc'!A0,ok\n\
                   b,-2+3+cmd|' /C calc'!A0,\"=HYPERLINK(\"\"http://x\"\")\"\n\
                   c,-12.5,+1e10\n\
                   d,@SUM(1),\"plain, quoted\"\n";
        let (out, f) = run(src.as_bytes(), Kind::Delimited(','));
        let out = String::from_utf8(out).unwrap();
        assert_eq!(
            out,
            "name,value,note\n\
             a,'=cmd|' /C calc'!A0,ok\n\
             b,'-2+3+cmd|' /C calc'!A0,\"'=HYPERLINK(\"\"http://x\"\")\"\n\
             c,-12.5,+1e10\n\
             d,'@SUM(1),\"plain, quoted\"\n"
        );
        assert!(f
            .items
            .iter()
            .any(|x| x.category == "formula-injection" && x.description.contains("4개")));
        // 다시 처리하면 더 바뀌지 않는다
        let (again, f2) = run(out.as_bytes(), Kind::Delimited(','));
        assert_eq!(again, out.as_bytes());
        assert!(f2.items.is_empty());
    }

    #[test]
    fn encodings_are_preserved() {
        let korean = "이름,값\n홍길동,=1+1\n";
        let (cp949, _, _) = encoding_rs::EUC_KR.encode(korean);
        let (out, _) = run(&cp949, Kind::Delimited(','));
        let (decoded, _, err) = encoding_rs::EUC_KR.decode(&out);
        assert!(!err);
        assert_eq!(decoded, "이름,값\n홍길동,'=1+1\n");

        let mut utf8_bom = b"\xEF\xBB\xBF".to_vec();
        utf8_bom.extend("가;나\n=x;1\n".as_bytes());
        let (out, _) = run(&utf8_bom, Kind::Delimited(','));
        assert!(out.starts_with(b"\xEF\xBB\xBF"));
        assert_eq!(&out[3..], "가;나\n'=x;1\n".as_bytes());

        let mut utf16 = b"\xFF\xFE".to_vec();
        utf16.extend(
            "안녕\u{202E}txt.exe\u{0007}"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        let (out, f) = run(&utf16, Kind::Text);
        let text = String::from_utf16(
            &out[2..]
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert_eq!(text, "안녕txt.exe");
        assert!(f.items.iter().any(|x| x.category == "text-spoofing"));
    }

    #[test]
    fn binary_data_is_rejected() {
        let mut f = Findings::default();
        assert!(reassemble(b"MZ\x90\x00\x03\x00", Kind::Text, &mut f).is_err());
        assert!(reassemble(&[0xFF, 0x00, 0x81, 0x82], Kind::Text, &mut f).is_err());
    }
}
