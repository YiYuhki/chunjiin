//! Outlook 메시지(.msg, MS-OXMSG) 재조합.
//!
//! .msg 는 OLE 복합 파일에 MAPI 속성을 스트림으로 담은 형식이다. 필요한 속성(발신·수신·제목·
//! 날짜·본문·첨부)만 꺼내 표준 메일(.eml)로 새로 쓴다. 본문 정제와 첨부 재조합은 EML 과 같은
//! 경로([`crate::mail::rebuild`])를 탄다.
//! - 본문: HTML(0x1013) → RTF 에 감싼 HTML(0x1009, `\fromhtml1`) → 텍스트(0x1000) 순으로 쓴다
//! - 첨부: 값으로 담긴 파일과 내장 메시지(재귀)만 옮긴다. 참조(링크) 첨부와 OLE 개체는 뺀다
//! - 그 밖의 속성(명명 속성, 전송 경로 헤더 전체, 양식·서명 정보 등)은 옮기지 않는다

use std::collections::HashMap;
use std::io::{Cursor, Read};

use cfb::CompoundFile;

use crate::engine::Engine;
use crate::error::{blocked, Result};
use crate::mail::{clean_header, encoded_word, RawAttachment, RawMail};
use crate::report::{Findings, Severity};

/// 내장 메시지 중첩 한도
const MAX_EMBED: usize = 8;
/// 메시지 하나의 최대 첨부·수신자 수
const MAX_ATTACHMENTS: usize = 2_000;
const MAX_RECIPIENTS: usize = 10_000;
/// RTF 중첩 한도
const MAX_RTF_DEPTH: usize = 1_000;

const PROPS: &str = "__properties_version1.0";

/// .msg 인지 (OLE 복합 파일이고 최상위에 MAPI 속성 스트림이 있다)
pub fn is_msg<F: Read + std::io::Seek>(cf: &CompoundFile<F>) -> bool {
    cf.exists(format!("/{PROPS}"))
        && cf
            .read_root_storage()
            .any(|e| e.name().starts_with("__substg1.0_"))
}

struct Reader<'a> {
    cf: CompoundFile<Cursor<&'a [u8]>>,
    limit: usize,
    /// 읽고 푼 총량 예산. 조작된 복합 파일은 여러 스트림이 같은 섹터를 가리키게 해
    /// 파일 크기보다 훨씬 많이 읽히게 할 수 있다
    budget: usize,
    over_budget: bool,
}

/// 저장소 하나(메시지·첨부·수신자)의 속성
struct Props {
    base: String,
    fixed: HashMap<u16, [u8; 8]>,
    /// 8비트 문자열 속성의 코드 페이지 (PR_MESSAGE_CODEPAGE)
    codepage: Option<u32>,
    /// 인터넷 형식(HTML 본문)의 코드 페이지 (PR_INTERNET_CPID)
    internet_cp: Option<u32>,
}

impl Reader<'_> {
    fn stream(&mut self, path: &str) -> Option<Vec<u8>> {
        let e = self.cf.entry(path).ok()?;
        if !e.is_stream() {
            return None;
        }
        let mut s = self.cf.open_stream(path).ok()?;
        let mut out = Vec::new();
        (&mut s)
            .take(self.limit.min(self.budget) as u64 + 1)
            .read_to_end(&mut out)
            .ok()?;
        if out.len() > self.limit {
            self.over_budget = true;
            return None;
        }
        self.charge(out.len()).then_some(out)
    }

    fn charge(&mut self, n: usize) -> bool {
        match self.budget.checked_sub(n) {
            Some(rest) => {
                self.budget = rest;
                true
            }
            None => {
                self.over_budget = true;
                self.budget = 0;
                false
            }
        }
    }

    /// `header` 는 속성 스트림 머리글 크기 (최상위 메시지 32, 내장 메시지 24, 첨부·수신자 8)
    fn props(&mut self, base: &str, header: usize) -> Props {
        let mut fixed = HashMap::new();
        if let Some(data) = self.stream(&format!("{base}/{PROPS}")) {
            for e in data.get(header..).unwrap_or_default().as_chunks::<16>().0 {
                let tag = u32::from_le_bytes(e[0..4].try_into().unwrap());
                let mut v = [0u8; 8];
                v.copy_from_slice(&e[8..16]);
                fixed.entry((tag >> 16) as u16).or_insert(v);
            }
        }
        let mut p = Props {
            base: base.to_string(),
            fixed,
            codepage: None,
            internet_cp: None,
        };
        // PR_MESSAGE_CODEPAGE → 메시지 로캘(PR_MESSAGE_LOCALE_ID)의 ANSI 코드 페이지 →
        // 인터넷 코드 페이지(UTF-8 이 아닐 때) 순
        p.codepage = p
            .u32(0x3FFD)
            .or_else(|| p.u32(0x3FF1).map(ansi_codepage))
            .or_else(|| p.u32(0x3FDE).filter(|&c| c != 65001));
        p.internet_cp = p.u32(0x3FDE).or_else(|| p.u32(0x3FFD));
        p
    }

    fn string(&mut self, p: &Props, id: u16) -> Option<String> {
        if let Some(b) = self.stream(&format!("{}/__substg1.0_{id:04X}001F", p.base)) {
            let units: Vec<u16> = b
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&c| u16::from_le_bytes(c))
                .collect();
            let s = String::from_utf16_lossy(&units);
            return Some(s.trim_end_matches('\0').to_string());
        }
        let b = self.stream(&format!("{}/__substg1.0_{id:04X}001E", p.base))?;
        let (s, _, _) = encoding(p.codepage).decode(&b);
        Some(s.trim_end_matches('\0').to_string())
    }

    fn binary(&mut self, p: &Props, id: u16) -> Option<Vec<u8>> {
        self.stream(&format!("{}/__substg1.0_{id:04X}0102", p.base))
    }

    fn children(&self, base: &str, prefix: &str) -> Vec<String> {
        let mut names: Vec<String> =
            match self
                .cf
                .read_storage(if base.is_empty() { "/" } else { base })
            {
                Ok(entries) => entries
                    .filter(|e| e.is_storage() && e.name().starts_with(prefix))
                    .map(|e| format!("{base}/{}", e.name()))
                    .collect(),
                Err(_) => Vec::new(),
            };
        names.sort();
        names
    }
}

impl Props {
    fn u32(&self, id: u16) -> Option<u32> {
        self.fixed
            .get(&id)
            .map(|v| u32::from_le_bytes(v[..4].try_into().unwrap()))
    }

    fn u64(&self, id: u16) -> Option<u64> {
        self.fixed.get(&id).map(|v| u64::from_le_bytes(*v))
    }
}

/// Windows 로캘 ID → 그 언어의 ANSI 코드 페이지
fn ansi_codepage(lcid: u32) -> u32 {
    match lcid & 0x3FF {
        0x12 => 949,
        0x11 => 932,
        0x04 if matches!(lcid & 0xFFFF, 0x0404 | 0x0C04 | 0x1404) => 950,
        0x04 => 936,
        0x19 | 0x22 | 0x23 | 0x02 | 0x2F | 0x3F | 0x40 | 0x44 | 0x50 => 1251,
        0x1A if matches!(lcid & 0xFFFF, 0x0C1A | 0x1C1A | 0x201A) => 1251,
        0x05 | 0x0E | 0x15 | 0x18 | 0x1B | 0x24 | 0x1A | 0x1C => 1250,
        0x08 => 1253,
        0x1F | 0x2C | 0x43 => 1254,
        0x0D => 1255,
        0x01 | 0x29 | 0x20 => 1256,
        0x25..=0x27 => 1257,
        0x2A => 1258,
        0x1E => 874,
        _ => 1252,
    }
}

/// Windows 코드 페이지 → 인코딩 (모르는 값은 한국어 Windows 기본값)
fn encoding(cp: Option<u32>) -> &'static encoding_rs::Encoding {
    use encoding_rs::*;
    match cp.unwrap_or(949) {
        65001 => UTF_8,
        1200 => UTF_16LE,
        874 => WINDOWS_874,
        932 | 50220 | 50221 | 50222 => SHIFT_JIS,
        936 | 54936 => GB18030,
        950 => BIG5,
        1250 => WINDOWS_1250,
        1251 => WINDOWS_1251,
        1252 | 20127 | 28591 => WINDOWS_1252,
        1253 => WINDOWS_1253,
        1254 => WINDOWS_1254,
        1255 => WINDOWS_1255,
        1256 => WINDOWS_1256,
        1257 => WINDOWS_1257,
        1258 => WINDOWS_1258,
        20866 => KOI8_R,
        21866 => KOI8_U,
        28592 => ISO_8859_2,
        28595 => ISO_8859_5,
        28597 => ISO_8859_7,
        28605 => ISO_8859_15,
        51932 => EUC_JP,
        _ => EUC_KR,
    }
}

pub fn reassemble(
    engine: &Engine,
    depth: usize,
    data: &[u8],
    findings: &mut Findings,
) -> Result<Vec<u8>> {
    let Ok(cf) = CompoundFile::open(Cursor::new(data)) else {
        return blocked("structure", "OLE 복합 파일을 열 수 없음");
    };
    if !is_msg(&cf) {
        return blocked("structure", "Outlook 메시지 구조가 아님");
    }
    let mut r = Reader {
        cf,
        limit: engine.policy.max_stream_size,
        budget: data.len().saturating_mul(2).saturating_add(16 << 20),
        over_budget: false,
    };
    let raw = message(&mut r, "", 32, 0, findings)?;
    if r.over_budget {
        return blocked(
            "resource",
            "메시지 스트림을 읽은 총량이 파일 크기에 비해 지나치게 큼 (겹친 섹터·압축 폭탄 의심)",
        );
    }
    findings.add(
        "format-conversion",
        Severity::Low,
        "Outlook 메시지(.msg)를 표준 메일(.eml)로 재조합",
        "",
    );
    crate::mail::rebuild(engine, depth, raw, findings)
}

/// 메시지 저장소 하나를 꺼낸다
fn message<'a>(
    r: &mut Reader,
    base: &str,
    header: usize,
    level: usize,
    findings: &mut Findings,
) -> Result<RawMail<'a>> {
    let p = r.props(base, header);
    let mut raw = RawMail::default();

    // 헤더: 원래 인터넷 헤더(PR_TRANSPORT_MESSAGE_HEADERS)가 있으면 거기서, 없으면 속성에서
    let transport = r
        .string(&p, 0x007D)
        .map(|h| parse_headers(&h))
        .unwrap_or_default();
    let from_transport = |name: &str| {
        transport
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| clean_header(v))
            .filter(|v| !v.is_empty())
    };
    let push = |raw: &mut RawMail, name: &str, value: Option<String>| {
        if let Some(v) = value.map(|v| clean_header(&v)).filter(|v| !v.is_empty()) {
            raw.headers.push((name.to_string(), v));
        }
    };

    let sender_email = [0x5D01, 0x5D02, 0x0C1F, 0x0065]
        .into_iter()
        .find_map(|id| r.string(&p, id).filter(|e| e.contains('@')));
    let sender_name = r.string(&p, 0x0C1A).or_else(|| r.string(&p, 0x0042));
    let from = from_transport("From").or_else(|| match sender_email.as_deref() {
        Some(e) => Some(mailbox(sender_name.as_deref(), e)),
        None => sender_name.as_deref().and_then(name_only),
    });
    push(&mut raw, "From", from);

    let (mut to, mut cc) = (Vec::new(), Vec::new());
    for (i, rb) in r
        .children(base, "__recip_version1.0_#")
        .into_iter()
        .enumerate()
    {
        if i >= MAX_RECIPIENTS {
            return blocked("resource", format!("수신자 수 초과 ({MAX_RECIPIENTS})"));
        }
        let rp = r.props(&rb, 8);
        let email = [0x39FE, 0x3003]
            .into_iter()
            .find_map(|id| r.string(&rp, id).filter(|e| e.contains('@')));
        let name = r.string(&rp, 0x3001);
        let m = match email {
            Some(e) => mailbox(name.as_deref(), &e),
            None => match name.as_deref().and_then(name_only) {
                Some(m) => m,
                None => continue,
            },
        };
        match rp.u32(0x0C15).unwrap_or(1) {
            2 => cc.push(m),
            // 숨은 참조(3)는 옮기지 않는다
            3 => {}
            _ => to.push(m),
        }
    }
    let join = |v: Vec<String>| (!v.is_empty()).then(|| v.join(", "));
    push(&mut raw, "To", from_transport("To").or_else(|| join(to)));
    push(&mut raw, "Cc", from_transport("Cc").or_else(|| join(cc)));
    push(&mut raw, "Reply-To", from_transport("Reply-To"));
    let subject = r.string(&p, 0x0037).or_else(|| {
        from_transport("Subject").map(|s| {
            mail_parser::MessageParser::default()
                .parse(format!("Subject: {s}\r\n\r\n").as_bytes())
                .and_then(|m| m.subject().map(str::to_string))
                .unwrap_or(s)
        })
    });
    push(&mut raw, "Subject", subject);
    let date = from_transport("Date").or_else(|| {
        [0x0039, 0x0E06, 0x3007]
            .into_iter()
            .find_map(|id| p.u64(id).filter(|&t| t > 0))
            .and_then(rfc2822_date)
    });
    push(&mut raw, "Date", date);
    push(
        &mut raw,
        "Message-ID",
        from_transport("Message-ID").or_else(|| r.string(&p, 0x1035)),
    );
    push(
        &mut raw,
        "In-Reply-To",
        from_transport("In-Reply-To").or_else(|| r.string(&p, 0x1042)),
    );
    push(
        &mut raw,
        "References",
        from_transport("References").or_else(|| r.string(&p, 0x1039)),
    );

    // 본문
    let text = r.string(&p, 0x1000);
    let html = r
        .binary(&p, 0x1013)
        .map(|b| {
            let (s, _, _) = encoding(p.internet_cp.or(Some(65001))).decode(&b);
            s.into_owned()
        })
        .or_else(|| r.string(&p, 0x1013));
    let rtf = r
        .binary(&p, 0x1009)
        .and_then(|b| decompress_rtf(&b, r.limit.min(r.budget).saturating_add(1)));
    // 한도까지 풀고도 남으면 폭탄으로 본다
    let rtf = match rtf {
        Some(d) if d.len() > r.limit || !r.charge(d.len()) => {
            r.over_budget = true;
            None
        }
        d => d,
    };
    let html = html.or_else(|| rtf.as_deref().and_then(|rtf| rtf_body(rtf, true)));
    let text = text.or_else(|| {
        if html.is_some() {
            None
        } else {
            rtf.as_deref().and_then(|rtf| rtf_body(rtf, false))
        }
    });
    raw.texts
        .extend(text.map(|t| t.trim_end_matches('\0').to_string()));
    raw.htmls
        .extend(html.map(|h| h.trim_end_matches('\0').to_string()));

    // 첨부
    let html_body = raw.htmls.join("");
    for (i, ab) in r
        .children(base, "__attach_version1.0_#")
        .into_iter()
        .enumerate()
    {
        if i >= MAX_ATTACHMENTS {
            return blocked("resource", format!("첨부 수 초과 ({MAX_ATTACHMENTS})"));
        }
        let ap = r.props(&ab, 8);
        let name = [0x3707, 0x3704, 0x3001]
            .into_iter()
            .find_map(|id| r.string(&ap, id).filter(|n| !n.trim().is_empty()));
        let method = ap.u32(0x3705).unwrap_or(1);
        match method {
            // 값으로 담긴 파일
            0 | 1 => {
                let Some(data) = r.binary(&ap, 0x3701) else {
                    continue;
                };
                // 서명된 메시지(IPM.Note.SMIME.MultipartSigned): 원래 MIME 메일 전체가 첨부로 들어 있다
                let mime = r.string(&ap, 0x370E).unwrap_or_default();
                if mime.trim().eq_ignore_ascii_case("multipart/signed") {
                    let inner = crate::mail::parse(&data, findings)?;
                    if !inner.texts.is_empty() || !inner.htmls.is_empty() {
                        raw.texts = inner.texts;
                        raw.htmls = inner.htmls;
                    }
                    raw.attachments.extend(inner.attachments);
                    raw.removed.extend(inner.removed);
                    continue;
                }
                let name = name.unwrap_or_else(|| format!("attachment-{}", i + 1));
                let cid = r.string(&ap, 0x3712).filter(|c| !c.trim().is_empty());
                let hidden = ap.u32(0x7FFE).is_some_and(|v| v & 0xFF != 0);
                let referenced = cid.as_deref().is_some_and(|c| {
                    html_body.contains(&format!("cid:{}", c.trim_matches(['<', '>'])))
                });
                raw.attachments.push(RawAttachment {
                    name,
                    content_id: cid,
                    inline_hint: hidden || referenced,
                    signature: false,
                    data: data.into(),
                });
            }
            // 내장 메시지
            5 => {
                let inner_props = r.props(&format!("{ab}/__substg1.0_3701000D"), 24);
                let label = name
                    .or_else(|| r.string(&inner_props, 0x0037))
                    .unwrap_or_else(|| format!("message-{}", i + 1));
                if level + 1 >= MAX_EMBED {
                    raw.removed
                        .push((label, "내장 메시지 중첩 깊이 초과".into()));
                    continue;
                }
                let inner = format!("{ab}/__substg1.0_3701000D");
                if !r.cf.entry(&inner).is_ok_and(|e| e.is_storage()) {
                    continue;
                }
                let child = message(r, &inner, 24, level + 1, findings)?;
                let label = label.trim_end_matches(".msg").to_string();
                raw.attachments.push(RawAttachment {
                    name: format!("{label}.eml"),
                    content_id: None,
                    inline_hint: false,
                    signature: false,
                    data: serialize(child).into(),
                });
            }
            // 참조(파일 경로·URL) 첨부, OLE 개체
            m => {
                let label = name.unwrap_or_else(|| format!("attachment-{}", i + 1));
                let (category, reason) = if m == 6 {
                    ("ole", "OLE 개체 첨부")
                } else {
                    ("external-resource", "외부 파일·URL 을 가리키는 참조 첨부")
                };
                findings.add(
                    category,
                    Severity::Medium,
                    format!("{reason} 제외"),
                    label.as_str(),
                );
                raw.removed.push((label, reason.into()));
            }
        }
    }
    Ok(raw)
}

/// 헤더 블록을 (이름, 값) 목록으로 (접힌 줄을 잇는다)
fn parse_headers(block: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in block.lines() {
        if line.is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) {
            if let Some((_, v)) = out.last_mut() {
                v.push(' ');
                v.push_str(line.trim());
            }
            continue;
        }
        if let Some((n, v)) = line.split_once(':') {
            out.push((n.trim().to_string(), v.trim().to_string()));
        }
    }
    out
}

/// `표시 이름 <주소>` (이름은 필요하면 인코딩하거나 따옴표로 감싼다)
fn mailbox(name: Option<&str>, email: &str) -> String {
    let email = email.trim().trim_matches(['<', '>']);
    let name = name.map(str::trim).filter(|n| !n.is_empty() && *n != email);
    match name {
        None => format!("<{email}>"),
        Some(n) if !n.is_ascii() => format!("{} <{email}>", encoded_word(n)),
        Some(n) if n.contains(|c: char| "()<>[]:;@\\,.\"".contains(c)) => {
            format!(
                "\"{}\" <{email}>",
                n.replace('\\', "\\\\").replace('"', "\\\"")
            )
        }
        Some(n) => format!("{n} <{email}>"),
    }
}

/// 주소 없이 이름만 있는 발신·수신자 (Exchange 내부 주소 등): 빈 그룹 `이름:;` 으로 쓴다
fn name_only(name: &str) -> Option<String> {
    let n = name.trim();
    if n.is_empty() {
        return None;
    }
    Some(if !n.is_ascii() {
        format!("{}:;", encoded_word(n))
    } else if n.contains(|c: char| "()<>[]:;@\\,.\"".contains(c)) {
        format!("\"{}\":;", n.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        format!("{n}:;")
    })
}

/// FILETIME(1601년부터 100ns 단위) → RFC 5322 날짜
fn rfc2822_date(ft: u64) -> Option<String> {
    let secs = (ft / 10_000_000).checked_sub(11_644_473_600)? as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // 1970-01-01 이 목요일
    let weekday = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][days.rem_euclid(7) as usize];
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
    let mon = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][(month - 1) as usize];
    Some(format!(
        "{weekday}, {day} {mon} {year} {:02}:{:02}:{:02} +0000",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    ))
}

/// 내장 메시지를 첨부로 싣기 위한 정제 전 MIME 직렬화 (첨부로 다시 재조합된다)
fn serialize(raw: RawMail) -> Vec<u8> {
    crate::mail::serialize_raw(raw)
}

/// 압축 RTF(MS-OXRTFCP)를 푼다
pub(crate) fn decompress_rtf(data: &[u8], limit: usize) -> Option<Vec<u8>> {
    const PREBUF: &[u8] = b"{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil \\froman \\fswiss \\fmodern \\fscript \\fdecor MS Sans SerifSymbolArialTimes New RomanCourier{\\colortbl\\red0\\green0\\blue0\r\n\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx";
    if data.len() < 16 {
        return None;
    }
    let raw_size = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
    let kind = &data[8..12];
    let body = &data[16..];
    if kind == b"MELA" {
        return Some(body[..body.len().min(raw_size).min(limit)].to_vec());
    }
    if kind != b"LZFu" {
        return None;
    }
    let cap = raw_size.min(limit);
    let mut dict = [0u8; 4096];
    dict[..PREBUF.len()].copy_from_slice(PREBUF);
    let mut wpos = PREBUF.len();
    let mut out = Vec::with_capacity(cap.min(16 << 20));
    let mut i = 0;
    'outer: while i < body.len() {
        let control = body[i];
        i += 1;
        for bit in 0..8 {
            if out.len() >= cap {
                break 'outer;
            }
            if control & (1 << bit) == 0 {
                let Some(&b) = body.get(i) else { break 'outer };
                i += 1;
                out.push(b);
                dict[wpos] = b;
                wpos = (wpos + 1) % 4096;
            } else {
                let (Some(&hi), Some(&lo)) = (body.get(i), body.get(i + 1)) else {
                    break 'outer;
                };
                i += 2;
                let word = u16::from_be_bytes([hi, lo]) as usize;
                let offset = word >> 4;
                let len = (word & 0xF) + 2;
                if offset == wpos {
                    break 'outer;
                }
                for k in 0..len {
                    if out.len() >= cap {
                        break 'outer;
                    }
                    let b = dict[(offset + k) % 4096];
                    out.push(b);
                    dict[wpos] = b;
                    wpos = (wpos + 1) % 4096;
                }
            }
        }
    }
    Some(out)
}

/// RTF 에서 본문을 꺼낸다. `html` 이면 RTF 에 감싼 HTML(`\fromhtml1`)을 복원하고
/// (MS-OXRTFEX), 아니면 글자만 꺼낸다. 감싼 HTML 이 아니면 `html` 모드는 None.
pub(crate) fn rtf_body(rtf: &[u8], html: bool) -> Option<String> {
    let head = &rtf[..rtf.len().min(1024)];
    let is_html = crate::detect::find(head, b"\\fromhtml1").is_some();
    if html != is_html {
        return None;
    }
    const SKIP: &[&[u8]] = &[
        b"fonttbl",
        b"colortbl",
        b"stylesheet",
        b"info",
        b"pict",
        b"object",
        b"listtable",
        b"listoverridetable",
        b"rsidtbl",
        b"generator",
        b"xmlnstbl",
        b"themedata",
        b"colorschememapping",
        b"latentstyles",
        b"datastore",
        b"filetbl",
        b"revtbl",
        b"header",
        b"footer",
    ];
    #[derive(Clone, Copy)]
    struct State {
        skip: bool,
        htmlrtf: bool,
        uc: usize,
    }
    let mut cp: Option<u32> = None;
    let mut out = String::new();
    let mut bytes: Vec<u8> = Vec::new();
    let mut stack: Vec<State> = Vec::new();
    let mut st = State {
        skip: false,
        htmlrtf: false,
        uc: 1,
    };
    let mut pending_skip = 0usize;
    let flush = |bytes: &mut Vec<u8>, out: &mut String, cp: Option<u32>| {
        if !bytes.is_empty() {
            let (s, _, _) = encoding(cp.or(Some(1252))).decode(bytes);
            out.push_str(&s);
            bytes.clear();
        }
    };
    let emit = |st: &State| !st.skip && !(html && st.htmlrtf);
    let mut i = 0;
    let mut group_start = false;
    while i < rtf.len() {
        let c = rtf[i];
        match c {
            b'{' => {
                if stack.len() >= MAX_RTF_DEPTH {
                    return None;
                }
                stack.push(st);
                group_start = true;
                pending_skip = 0;
                i += 1;
                continue;
            }
            b'}' => {
                flush(&mut bytes, &mut out, cp);
                st = stack.pop()?;
                pending_skip = 0;
                i += 1;
            }
            b'\\' => {
                let Some(&n) = rtf.get(i + 1) else { break };
                if n.is_ascii_alphabetic() {
                    let s = i + 1;
                    let mut j = s;
                    while j < rtf.len() && rtf[j].is_ascii_alphabetic() {
                        j += 1;
                    }
                    let word = &rtf[s..j];
                    let ns = j;
                    if j < rtf.len() && (rtf[j] == b'-' || rtf[j].is_ascii_digit()) {
                        j += 1;
                        while j < rtf.len() && rtf[j].is_ascii_digit() && j - ns < 12 {
                            j += 1;
                        }
                    }
                    let param: Option<i64> = std::str::from_utf8(&rtf[ns..j])
                        .ok()
                        .and_then(|p| p.parse().ok());
                    if j < rtf.len() && rtf[j] == b' ' {
                        j += 1;
                    }
                    i = j;
                    let was_start = std::mem::take(&mut group_start);
                    if pending_skip > 0 && word != b"u" {
                        pending_skip = pending_skip.saturating_sub(1);
                        continue;
                    }
                    match word {
                        b"ansicpg" => cp = param.and_then(|p| u32::try_from(p).ok()),
                        b"htmlrtf" => {
                            flush(&mut bytes, &mut out, cp);
                            st.htmlrtf = param != Some(0);
                        }
                        b"uc" => st.uc = param.unwrap_or(1).clamp(0, 10) as usize,
                        b"u" => {
                            if emit(&st) {
                                flush(&mut bytes, &mut out, cp);
                                let v = param.unwrap_or(0);
                                let v = if v < 0 { v + 65536 } else { v } as u32;
                                out.push(char::from_u32(v).unwrap_or('\u{FFFD}'));
                            }
                            pending_skip = st.uc;
                        }
                        b"par" | b"line" if emit(&st) => {
                            flush(&mut bytes, &mut out, cp);
                            out.push_str("\r\n");
                        }
                        b"tab" if emit(&st) => bytes.push(b'\t'),
                        b"htmltag" | b"mhtmltag" => {}
                        w if was_start && SKIP.contains(&w) => st.skip = true,
                        _ => {}
                    }
                    continue;
                }
                group_start = false;
                match n {
                    b'*' => {
                        // `{\*\htmltag ...}` 만 읽고 나머지 확장 대상은 건너뛴다
                        let rest = &rtf[i + 2..];
                        let rest = rest.strip_prefix(b" ").unwrap_or(rest);
                        if rest.starts_with(b"\\htmltag") || rest.starts_with(b"\\mhtmltag") {
                            // HTML 태그 그룹은 둘레의 \htmlrtf 억제와 무관하게 옮긴다
                            st.htmlrtf = false;
                        } else {
                            st.skip = true;
                        }
                        i += 2;
                    }
                    b'\'' => {
                        let hex = rtf
                            .get(i + 2..i + 4)
                            .and_then(|h| std::str::from_utf8(h).ok());
                        let v = hex.and_then(|h| u8::from_str_radix(h, 16).ok());
                        i += 4;
                        if pending_skip > 0 {
                            pending_skip -= 1;
                        } else if let (Some(v), true) = (v, emit(&st)) {
                            bytes.push(v);
                        }
                    }
                    b'{' | b'}' | b'\\' => {
                        if pending_skip > 0 {
                            pending_skip -= 1;
                        } else if emit(&st) {
                            bytes.push(n);
                        }
                        i += 2;
                    }
                    b'~' => {
                        if emit(&st) {
                            flush(&mut bytes, &mut out, cp);
                            out.push('\u{A0}');
                        }
                        i += 2;
                    }
                    b'_' => {
                        if emit(&st) {
                            bytes.push(b'-');
                        }
                        i += 2;
                    }
                    b'\r' | b'\n' => {
                        if emit(&st) {
                            flush(&mut bytes, &mut out, cp);
                            out.push_str("\r\n");
                        }
                        i += 2;
                    }
                    _ => i += 2,
                }
            }
            b'\r' | b'\n' | 0 => i += 1,
            _ => {
                group_start = false;
                if pending_skip > 0 {
                    pending_skip -= 1;
                } else if emit(&st) {
                    bytes.push(c);
                }
                i += 1;
            }
        }
    }
    flush(&mut bytes, &mut out, cp);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn date_from_filetime() {
        // 2003-07-01 10:52:37 UTC
        let secs: u64 = 1_057_056_757 + 11_644_473_600;
        assert_eq!(
            rfc2822_date(secs * 10_000_000).as_deref(),
            Some("Tue, 1 Jul 2003 10:52:37 +0000")
        );
    }

    #[test]
    fn mailbox_quoting() {
        assert_eq!(mailbox(Some("Kim, A"), "a@b.c"), "\"Kim, A\" <a@b.c>");
        assert_eq!(mailbox(None, "a@b.c"), "<a@b.c>");
        assert!(mailbox(Some("김철수"), "a@b.c").starts_with("=?UTF-8?B?"));
        assert_eq!(
            name_only("Allison, Tim").as_deref(),
            Some("\"Allison, Tim\":;")
        );
        assert_eq!(name_only("Angela Deng").as_deref(), Some("Angela Deng:;"));
    }

    #[test]
    fn rtf_decompression_spec_example() {
        // MS-OXRTFCP 3.1.1 예제
        let comp: &[u8] = &[
            0x2d, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x00, 0x00, 0x4c, 0x5a, 0x46, 0x75, 0xf1, 0xc5,
            0xc7, 0xa7, 0x03, 0x00, 0x0a, 0x00, 0x72, 0x63, 0x70, 0x67, 0x31, 0x32, 0x35, 0x42,
            0x32, 0x0a, 0xf3, 0x20, 0x68, 0x65, 0x6c, 0x09, 0x00, 0x20, 0x62, 0x77, 0x05, 0xb0,
            0x6c, 0x64, 0x7d, 0x0a, 0x80, 0x0f, 0xa0,
        ];
        let out = decompress_rtf(comp, 1 << 20).unwrap();
        assert_eq!(out, b"{\\rtf1\\ansi\\ansicpg1252\\pard hello world}\r\n");
    }

    #[test]
    fn html_is_deencapsulated() {
        let rtf = br"{\rtf1\ansi\ansicpg949\fromhtml1 {\fonttbl{\f0 Arial;}}{\*\htmltag19 <html>}{\*\htmltag50 <body>}\htmlrtf {\htmlrtf0 \'c7\'d1\'b1\'db \u54620?x\par {\*\htmltag84 <script>}\htmlrtf ignored\htmlrtf0 }{\*\htmltag58 </body>}}";
        let h = rtf_body(rtf, true).unwrap();
        assert_eq!(h, "<html><body>한글 한x\r\n<script></body>");
        assert!(rtf_body(rtf, false).is_none());
    }
}
