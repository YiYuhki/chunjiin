//! 전자우편(EML, RFC 5322/MIME) 재조합.
//!
//! 메일을 해석해 필요한 헤더·본문·첨부만 꺼낸 뒤 MIME 구조를 새로 만든다.
//! - 헤더: 발신·수신·제목·날짜·메시지 ID 등 필요한 것만 옮긴다(X-*, 경로 정보 등은 버림)
//! - 텍스트 본문: 제어·양방향 재정의 문자를 제거한다
//! - HTML 본문: 허용 목록 기반 정제기(ammonia)로 스크립트·이벤트 처리기·폼·iframe·object 를
//!   제거하고, 링크는 허용 스킴만, 이미지는 메일 안 첨부(cid:)만 남긴다(외부 추적 픽셀 제거).
//!   인라인 스타일은 외부 자원(url(), @import)·스크립트 표현식이 없을 때만 남긴다
//! - 첨부: 같은 엔진으로 하나씩 재조합한다(ZIP 과 같은 중첩 제한·해제 예산). 차단된 첨부는
//!   빼고 본문 끝에 제거 안내를 덧붙인다
//! - 결과는 결정적인 경계 문자열과 base64 전송 인코딩으로 새로 쓴다

use std::borrow::Cow;
use std::collections::HashSet;

use base64::Engine as _;
use mail_parser::{MessageParser, MimeHeaders, PartType};

use crate::engine::Engine;
use crate::error::{blocked, Result};
use crate::policy::Policy;
use crate::report::{Findings, Severity, Status};

/// 메일 한 통의 최대 MIME 파트 수
const MAX_PARTS: usize = 2_000;
/// 옮기는 헤더
const KEEP_HEADERS: &[&str] = &[
    "From",
    "Sender",
    "To",
    "Cc",
    "Reply-To",
    "Subject",
    "Date",
    "Message-ID",
    "In-Reply-To",
    "References",
];

/// 메일처럼 보이는지: 첫 줄부터 헤더 형식이고 발신·날짜 등 메일 헤더가 있다
pub fn looks_like_mail(data: &[u8]) -> bool {
    let head = &data[..data.len().min(16 * 1024)];
    let text = String::from_utf8_lossy(head);
    let mut names = HashSet::new();
    for (i, line) in text.lines().enumerate() {
        if line.is_empty() {
            break;
        }
        // mbox 구분 줄("From 보낸이 날짜")
        if i == 0 && line.starts_with("From ") {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            continue;
        }
        let Some((name, _)) = line.split_once(':') else {
            return false;
        };
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_graphic() && b != b':') {
            return false;
        }
        names.insert(name.to_ascii_lowercase());
    }
    // .eml 확장자일 때만 호출되므로, 헤더 블록 형식이면서 메일 헤더가 하나라도 있으면 메일로 본다
    [
        "from",
        "received",
        "date",
        "subject",
        "mime-version",
        "message-id",
        "to",
        "content-type",
    ]
    .iter()
    .any(|h| names.contains(*h))
}

struct Attachment {
    name: String,
    content_type: String,
    content_id: Option<String>,
    inline: bool,
    data: Vec<u8>,
}

/// 형식(EML·MSG)에서 꺼낸 정제 전 메일 내용
#[derive(Default)]
pub(crate) struct RawMail<'a> {
    /// 옮길 헤더 (KEEP_HEADERS 이름, 전송용으로 인코딩된 값. 제목은 디코딩한 값)
    pub headers: Vec<(String, String)>,
    pub texts: Vec<String>,
    pub htmls: Vec<String>,
    pub attachments: Vec<RawAttachment<'a>>,
    /// 형식 단계에서 이미 뺀 첨부 (이름, 사유)
    pub removed: Vec<(String, String)>,
}

pub(crate) struct RawAttachment<'a> {
    pub name: String,
    pub content_id: Option<String>,
    /// 본문 안에 표시하는 첨부로 표시되었는지 (cid 이미지 판단에 씀)
    pub inline_hint: bool,
    /// S/MIME 분리 서명 (재조합하면 맞지 않으므로 뺀다)
    pub signature: bool,
    /// 엔진이 직접 만든 첨부의 MIME 형식 (재조합 없이 싣는다)
    pub generated: Option<&'static str>,
    pub data: Cow<'a, [u8]>,
}

pub fn reassemble(
    engine: &Engine,
    depth: usize,
    data: &[u8],
    findings: &mut Findings,
) -> Result<Vec<u8>> {
    let raw = parse(data, findings)?;
    rebuild(engine, depth, raw, findings)
}

/// MIME 메일을 해석해 정제 전 내용을 꺼낸다
pub(crate) fn parse(data: &[u8], findings: &mut Findings) -> Result<RawMail<'static>> {
    let Some(msg) = MessageParser::default().parse(data) else {
        return blocked("structure", "메일 형식을 해석할 수 없음");
    };
    if msg.parts.len() > MAX_PARTS {
        return blocked(
            "resource",
            format!("MIME 파트 수 초과 ({})", msg.parts.len()),
        );
    }

    let mut raw = RawMail::default();
    // 헤더
    let headers = &mut raw.headers;
    let mut dropped_headers = 0u64;
    for (name, value) in msg.headers_raw() {
        match KEEP_HEADERS.iter().find(|k| k.eq_ignore_ascii_case(name)) {
            Some(k) if !headers.iter().any(|(n, _): &(String, String)| n == k) => {
                // 제목은 디코딩한 값을 다시 인코딩한다 (원본 인코딩을 그대로 옮기지 않음)
                let v = if *k == "Subject" {
                    clean_header(msg.subject().unwrap_or(value))
                } else {
                    clean_header(value)
                };
                headers.push((k.to_string(), v));
            }
            Some(_) => {}
            None => dropped_headers += 1,
        }
    }
    if dropped_headers > 0 {
        findings.count("mail_headers_removed", dropped_headers);
    }

    // 본문
    for id in &msg.text_body {
        if let Some(PartType::Text(t)) = msg.parts.get(*id as usize).map(|p| &p.body) {
            raw.texts.push(t.to_string());
        }
    }
    for id in &msg.html_body {
        if let Some(PartType::Html(h)) = msg.parts.get(*id as usize).map(|p| &p.body) {
            raw.htmls.push(h.to_string());
        }
    }

    // 첨부
    let body_ids: HashSet<u32> = msg
        .text_body
        .iter()
        .chain(&msg.html_body)
        .copied()
        .collect();
    for (i, id) in msg.attachments.iter().enumerate() {
        if body_ids.contains(id) {
            continue;
        }
        let Some(part) = msg.parts.get(*id as usize) else {
            continue;
        };
        let (bytes, default_name): (Cow<[u8]>, String) = match &part.body {
            // 전송 인코딩을 푼 원문 메시지
            PartType::Message(_) => (
                Cow::Borrowed(part.contents()),
                format!("message-{}.eml", i + 1),
            ),
            PartType::Multipart(_) => continue,
            _ => (
                Cow::Borrowed(part.contents()),
                format!("attachment-{}", i + 1),
            ),
        };
        // 이름 없는 텍스트 파트(추가 본문 조각)는 첨부가 아니라 본문으로 잇는다
        if part.attachment_name().is_none() {
            match &part.body {
                PartType::Text(t) => {
                    raw.texts.push(t.to_string());
                    continue;
                }
                PartType::Html(h) => {
                    raw.htmls.push(h.to_string());
                    continue;
                }
                _ => {}
            }
        }
        let name = part
            .attachment_name()
            .map(crate::text::strip_spoofing)
            .filter(|n| !n.trim().is_empty())
            .unwrap_or(default_name);
        let signature = part.content_type().is_some_and(|ct| {
            ct.c_type.eq_ignore_ascii_case("application")
                && ct.subtype().is_some_and(|s| {
                    s.eq_ignore_ascii_case("pkcs7-signature")
                        || s.eq_ignore_ascii_case("x-pkcs7-signature")
                })
        });
        raw.attachments.push(RawAttachment {
            name,
            content_id: part.content_id().map(str::to_string),
            inline_hint: part.content_disposition().is_none_or(|d| d.is_inline()),
            signature,
            generated: None,
            data: Cow::Owned(bytes.into_owned()),
        });
    }
    Ok(raw)
}

/// 꺼낸 메일 내용을 정제하고 첨부를 하나씩 재조합해 새 MIME 메일로 쓴다
pub(crate) fn rebuild(
    engine: &Engine,
    depth: usize,
    raw: RawMail,
    findings: &mut Findings,
) -> Result<Vec<u8>> {
    let policy = &engine.policy;
    let headers = raw.headers;
    let mut texts: Vec<String> = raw
        .texts
        .iter()
        .map(|t| crate::text::strip_controls(t, findings))
        .collect();
    let mut htmls: Vec<String> = raw
        .htmls
        .iter()
        .map(|h| sanitize_html(h, policy, findings))
        .collect();
    let mut attachments = Vec::new();
    let mut removed = raw.removed;
    let mut expanded: u64 = 0;
    let mut signatures = 0u64;
    for a in raw.attachments {
        if a.signature {
            signatures += 1;
            continue;
        }
        if let Some(ct) = a.generated {
            attachments.push(Attachment {
                name: a.name,
                content_type: ct.to_string(),
                content_id: None,
                inline: false,
                data: a.data.into_owned(),
            });
            continue;
        }
        let bytes = a.data;
        let name = crate::text::strip_spoofing(&a.name);
        let name = name
            .rsplit(['/', '\\'])
            .next()
            .filter(|n| !n.is_empty())
            .unwrap_or("attachment")
            .to_string();

        if depth >= crate::archive::MAX_DEPTH && is_container(&bytes) {
            removed.push((name.clone(), "중첩 깊이 초과".to_string()));
            continue;
        }
        let child = Engine::nested(
            Policy {
                max_zip_total: policy.max_zip_total.saturating_sub(expanded),
                ..policy.clone()
            },
            depth + 1,
        );
        let r = child.process(&bytes, &name);
        expanded = expanded
            .saturating_add(bytes.len() as u64)
            .saturating_add(r.stats.get("unpacked_bytes").copied().unwrap_or(0));
        if expanded > policy.max_zip_total {
            return blocked("zip-bomb", "첨부 파일까지 합한 해제 총량 초과");
        }
        if r.status == Status::Blocked {
            if policy.strict_archives {
                return blocked(
                    "archive",
                    format!("차단된 첨부가 있어 전체 차단: {name} ({})", r.reason),
                );
            }
            findings.add(
                "archive-member",
                Severity::Medium,
                format!("차단된 첨부 제외 - {}", r.reason),
                name.as_str(),
            );
            removed.push((name, r.reason.clone()));
            continue;
        }
        for f in r.findings {
            let at = if f.location.is_empty() {
                format!("첨부:{name}")
            } else {
                format!("첨부:{name} > {}", f.location)
            };
            findings.add(&f.category, f.severity, f.description, at);
        }
        for (k, v) in r.stats {
            if k != "unpacked_bytes" {
                findings.count(&k, v);
            }
        }
        let (Some(output), Some(out_name)) = (r.output, r.output_filename) else {
            continue;
        };
        let content_type = mime_for(&out_name).to_string();
        let content_id = a
            .content_id
            .map(|c| clean_header(&c).trim_matches(['<', '>']).to_string())
            .filter(|c| !c.is_empty());
        attachments.push(Attachment {
            inline: content_id.is_some() && content_type.starts_with("image/") && a.inline_hint,
            name: out_name,
            content_type,
            content_id,
            data: output,
        });
    }
    if signatures > 0 {
        findings.add(
            "signature",
            Severity::Low,
            "전자서명(S/MIME) 제거 - 재조합한 메일에는 원래 서명이 맞지 않음",
            "",
        );
    }
    findings.count("mail_attachments", attachments.len() as u64);
    findings.count("unpacked_bytes", expanded);

    // 제거 안내
    if !removed.is_empty() {
        let list: Vec<String> = removed.iter().map(|(n, r)| format!("- {n}: {r}")).collect();
        let notice = format!(
            "\n\n[문서 보안] 보안 정책에 따라 다음 첨부 파일을 제거했습니다.\n{}\n",
            list.join("\n")
        );
        if texts.is_empty() && htmls.is_empty() {
            texts.push(String::new());
        }
        if let Some(t) = texts.last_mut() {
            t.push_str(&notice);
        }
        if let Some(h) = htmls.last_mut() {
            h.push_str(&format!(
                "<hr><p>[문서 보안] 보안 정책에 따라 다음 첨부 파일을 제거했습니다.</p><ul>{}</ul>",
                removed
                    .iter()
                    .map(|(n, r)| format!("<li>{}: {}</li>", html_escape(n), html_escape(r)))
                    .collect::<String>()
            ));
        }
    }

    Ok(build(&headers, &texts, &htmls, &attachments))
}

/// 정제하지 않은 메일 내용을 그대로 MIME 으로 쓴다 (.msg 의 내장 메시지를 첨부로 실을 때.
/// 첨부가 된 메일은 다시 [`rebuild`] 로 정제된다)
pub(crate) fn serialize_raw(raw: RawMail) -> Vec<u8> {
    let mut texts = raw.texts;
    if !raw.removed.is_empty() {
        let list: Vec<String> = raw
            .removed
            .iter()
            .map(|(n, r)| format!("- {n}: {r}"))
            .collect();
        texts.push(format!(
            "[문서 보안] 보안 정책에 따라 다음 첨부 파일을 제거했습니다.\n{}\n",
            list.join("\n")
        ));
    }
    let attachments: Vec<Attachment> = raw
        .attachments
        .into_iter()
        .filter(|a| !a.signature)
        .map(|a| {
            let content_type = a.generated.unwrap_or(mime_for(&a.name)).to_string();
            let content_id = a
                .content_id
                .map(|c| clean_header(&c).trim_matches(['<', '>']).to_string())
                .filter(|c| !c.is_empty());
            Attachment {
                inline: content_id.is_some() && a.inline_hint,
                name: crate::text::strip_spoofing(&a.name),
                content_type,
                content_id,
                data: a.data.into_owned(),
            }
        })
        .collect();
    build(&raw.headers, &texts, &raw.htmls, &attachments)
}

pub(crate) fn is_container(data: &[u8]) -> bool {
    matches!(crate::detect::detect(data), crate::detect::FileType::Zip) || looks_like_mail(data)
}

/// 헤더 값: 줄 접기를 풀고 제어 문자를 뺀다 (헤더 주입 방지)
pub(crate) fn clean_header(v: &str) -> String {
    let unfolded: String = v
        .chars()
        .map(|c| {
            if c == '\r' || c == '\n' || c == '\t' {
                ' '
            } else {
                c
            }
        })
        .filter(|c| !c.is_control() && !crate::text::is_bidi_control(*c))
        .collect();
    unfolded.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// HTML 본문을 허용 목록으로 정제한다
fn sanitize_html(html: &str, policy: &Policy, findings: &mut Findings) -> String {
    let lower = html.to_ascii_lowercase();
    let active = [
        "<script",
        "javascript:",
        "<iframe",
        "<object",
        "<embed",
        "<form",
        "<applet",
        "<base",
    ]
    .iter()
    .filter(|p| lower.contains(*p))
    .count()
        + event_handlers(&lower)
        + meta_refresh(&lower);
    let remote = lower.matches("src=\"http").count()
        + lower.matches("src='http").count()
        + lower.matches("src=http").count();

    let mut schemes: HashSet<&str> = policy
        .allowed_uri_schemes
        .iter()
        .map(String::as_str)
        .collect();
    schemes.insert("cid");
    if policy.remove_hyperlinks {
        schemes.retain(|s| *s == "cid");
    }
    let mut b = ammonia::Builder::default();
    b.url_schemes(schemes)
        .link_rel(Some("noopener noreferrer"))
        .url_relative(ammonia::UrlRelative::Deny)
        .add_tags(["font", "center"])
        .add_generic_attributes([
            "style",
            "align",
            "valign",
            "width",
            "height",
            "bgcolor",
            "color",
            "border",
            "cellpadding",
            "cellspacing",
            "face",
            "size",
        ])
        .attribute_filter(|element, attribute, value| match (element, attribute) {
            // 이미지는 메일 안 첨부(cid:)만 (외부 추적 이미지 제거)
            ("img", "src") => value
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("cid:")
                .then(|| value.into()),
            (_, "style") => {
                let l = value.to_ascii_lowercase();
                (![
                    "url(",
                    "@import",
                    "expression",
                    "javascript",
                    "behavior",
                    "-moz-binding",
                ]
                .iter()
                .any(|p| l.contains(p)))
                .then(|| value.into())
            }
            _ => Some(value.into()),
        });
    let clean = b.clean(html).to_string();
    if active > 0 {
        findings.add(
            "active-content",
            Severity::High,
            format!("HTML 본문의 스크립트·이벤트 처리기·폼·내장 개체 {active}종 제거"),
            "",
        );
    }
    if remote > 0 {
        findings.add(
            "external-resource",
            Severity::Low,
            format!("HTML 본문의 외부 이미지(추적 픽셀 등) {remote}개 제거"),
            "",
        );
    }
    clean
}

/// 문자 집합 선언(`http-equiv="Content-Type"`) 이 아닌 `<meta http-equiv>` (refresh 등)
fn meta_refresh(lower: &str) -> usize {
    lower
        .match_indices("<meta http-equiv")
        .any(|(i, m)| {
            let rest = lower[i + m.len()..].trim_start_matches([' ', '=', '"', '\'']);
            !rest.starts_with("content-type")
        })
        .into()
}

fn event_handlers(lower: &str) -> usize {
    let b = lower.as_bytes();
    (0..b.len().saturating_sub(3))
        .filter(|&i| {
            (b[i] == b' '
                || b[i] == b'\t'
                || b[i] == b'\n'
                || b[i] == b'/'
                || b[i] == b'"'
                || b[i] == b'\'')
                && b[i + 1] == b'o'
                && b[i + 2] == b'n'
                && b[i + 3..]
                    .iter()
                    .take_while(|c| c.is_ascii_alphabetic())
                    .count()
                    > 2
                && b[i + 3..]
                    .iter()
                    .skip_while(|c| c.is_ascii_alphabetic())
                    .find(|c| !c.is_ascii_whitespace())
                    == Some(&b'=')
        })
        .count()
        .min(1)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn mime_for(name: &str) -> &'static str {
    match crate::detect::extension_of(name).as_str() {
        "pdf" => "application/pdf",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "doc" => "application/msword",
        "xls" => "application/vnd.ms-excel",
        "ppt" => "application/vnd.ms-powerpoint",
        "hwp" => "application/x-hwp",
        "hwpx" => "application/hwp+zip",
        "rtf" => "application/rtf",
        "zip" => "application/zip",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ics" => "text/calendar; charset=utf-8",
        "vcf" | "vcard" => "text/vcard; charset=utf-8",
        "emf" => "image/x-emf",
        "wmf" => "image/x-wmf",
        "csv" => "text/csv",
        "txt" | "log" => "text/plain",
        "eml" => "message/rfc822",
        _ => "application/octet-stream",
    }
}

/// RFC 2047/2231: 비ASCII 이름은 UTF-8 로 인코딩한다
pub(crate) fn encoded_word(s: &str) -> String {
    if s.is_ascii() && !s.contains(['"', '\\']) {
        s.to_string()
    } else {
        format!(
            "=?UTF-8?B?{}?=",
            base64::engine::general_purpose::STANDARD.encode(s)
        )
    }
}

fn filename_param(name: &str) -> String {
    if name.is_ascii() && !name.contains(['"', '\\', ';']) {
        format!("filename=\"{name}\"")
    } else {
        let enc: String = name
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect();
        format!("filename*=UTF-8''{enc}")
    }
}

fn base64_lines(data: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(data);
    let mut out = String::with_capacity(b64.len() + b64.len() / 76 * 2 + 2);
    for chunk in b64.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push_str("\r\n");
    }
    out
}

/// 헤더 한 줄을 78자 안팎에서 공백 기준으로 접는다
fn header_line(name: &str, value: &str) -> String {
    let mut out = format!("{name}:");
    let mut line_len = out.len();
    for word in value.split(' ') {
        if line_len + 1 + word.len() > 76 && line_len > name.len() + 1 {
            out.push_str("\r\n");
            line_len = 0;
        }
        out.push(' ');
        out.push_str(word);
        line_len += 1 + word.len();
    }
    out.push_str("\r\n");
    out
}

struct Builder {
    boundary_seq: usize,
    /// 내용에서 얻은 값 - 첨부된 메일(8bit 로 그대로 싣는) 안의 경계와 겹치지 않게 한다
    salt: String,
}

impl Builder {
    fn boundary(&mut self) -> String {
        // base64 문자 집합에 '_' 가 없으므로 base64 본문과 겹치지 않는다
        self.boundary_seq += 1;
        format!("=_cdr_{}_{}", self.salt, self.boundary_seq)
    }

    fn leaf(content_type: &str, extra: &str, data: &[u8]) -> String {
        if content_type == "message/rfc822" {
            // 메시지는 규격상 base64 로 싣지 않는다 (재조합한 메일은 줄 길이·줄바꿈이 규격에 맞다)
            let mut body = String::from_utf8_lossy(data).into_owned();
            if !body.ends_with("\r\n") {
                body.push_str("\r\n");
            }
            return format!(
                "Content-Type: {content_type}\r\n{extra}Content-Transfer-Encoding: 8bit\r\n\r\n{body}"
            );
        }
        format!(
            "Content-Type: {content_type}\r\n{extra}Content-Transfer-Encoding: base64\r\n\r\n{}",
            base64_lines(data)
        )
    }

    fn multipart(&mut self, subtype: &str, parts: Vec<String>) -> String {
        if parts.len() == 1 {
            return parts.into_iter().next().unwrap();
        }
        let b = self.boundary();
        let mut out = format!("Content-Type: multipart/{subtype}; boundary=\"{b}\"\r\n\r\n");
        for p in parts {
            out.push_str(&format!("--{b}\r\n{p}"));
        }
        out.push_str(&format!("--{b}--\r\n"));
        out
    }
}

fn build(
    headers: &[(String, String)],
    texts: &[String],
    htmls: &[String],
    attachments: &[Attachment],
) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    texts
        .iter()
        .chain(htmls)
        .for_each(|t| h.update(t.as_bytes()));
    attachments.iter().for_each(|a| h.update(&a.data));
    let salt: String = h.finalize()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut b = Builder {
        boundary_seq: 0,
        salt,
    };
    let text = texts.join("\n\n");
    let html = htmls.join("\n<hr>\n");
    let mut alternatives = Vec::new();
    if !text.is_empty() || html.is_empty() {
        alternatives.push(Builder::leaf(
            "text/plain; charset=utf-8",
            "",
            text.as_bytes(),
        ));
    }
    if !html.is_empty() {
        alternatives.push(Builder::leaf(
            "text/html; charset=utf-8",
            "",
            html.as_bytes(),
        ));
    }
    let body = b.multipart("alternative", alternatives);

    let (inline, attached): (Vec<&Attachment>, Vec<&Attachment>) = attachments
        .iter()
        .partition(|a| a.inline && !html.is_empty());
    let related = if inline.is_empty() {
        body
    } else {
        let mut parts = vec![body];
        for a in inline {
            let extra = format!(
                "Content-ID: <{}>\r\nContent-Disposition: inline; {}\r\n",
                a.content_id.as_deref().unwrap_or(""),
                filename_param(&a.name)
            );
            parts.push(Builder::leaf(&a.content_type, &extra, &a.data));
        }
        b.multipart("related", parts)
    };
    let mixed = if attached.is_empty() {
        related
    } else {
        let mut parts = vec![related];
        for a in attached {
            let mut extra = format!(
                "Content-Disposition: attachment; {}\r\n",
                filename_param(&a.name)
            );
            if let Some(cid) = &a.content_id {
                extra.push_str(&format!("Content-ID: <{cid}>\r\n"));
            }
            parts.push(Builder::leaf(&a.content_type, &extra, &a.data));
        }
        b.multipart("mixed", parts)
    };

    let mut out = String::new();
    for (name, value) in headers {
        let value = if name == "Subject" {
            encoded_word(value)
        } else {
            value.clone()
        };
        out.push_str(&header_line(name, &value));
    }
    out.push_str("MIME-Version: 1.0\r\n");
    out.push_str(&mixed);
    out.into_bytes()
}
