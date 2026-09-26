//! Excel 97-2003(.xls) 재조합.
//!
//! - 새 OLE 복합 파일에 Workbook(또는 BIFF5 Book), 피벗 캐시(_SX_DB_CUR), CompObj 만 조립한다.
//!   VBA(_VBA_PROJECT_CUR), 사용자 정의 XML 등은 조립하지 않는다.
//! - BIFF 레코드를 순회해 다음을 판정한다.
//!   - 차단: 암호화(FILEPASS), Excel 4.0 매크로 시트/VB 모듈 시트(BOUNDSHEET dt=1/6),
//!     DDE/OLE 링크(SUPBOOK ctab=0), 임베디드 OLE 개체(MBD*), ActiveX(Ctls)
//!     — 시트/레코드 오프셋이 얽혀 있어 안전하게 떼어낼 수 없으므로 fail-closed 처리
//!   - 보고: 자동 실행 이름(Auto_Open), 외부 통합 문서 참조

use super::cfbx::{self, Node};
use crate::error::{blocked, Result};
use crate::policy::Policy;
use crate::report::{Findings, Severity};

const FILEPASS: u16 = 0x002F;
const BOUNDSHEET: u16 = 0x0085;
const NAME: u16 = 0x0018;
const SUPBOOK: u16 = 0x01AE;
const OBPROJ: u16 = 0x00D3;
const HLINK: u16 = 0x01B8;
/// 외부로 요청을 보내는 함수 (BIFF8 에는 "_xlfn." 이름으로 저장됨)
const REQUEST_FUNCTIONS: &[&str] = &["_xlfn.webservice", "_xlfn.filterxml", "_xlfn.image"];

pub fn reassemble(data: &[u8], policy: &Policy, findings: &mut Findings) -> Result<Vec<u8>> {
    let c = cfbx::read(data, policy)?;
    findings.count("input_parts", c.nodes.len() as u64);
    // 스트림 이름의 대소문자는 원본 그대로 유지한다 (예: "BOOK" 은 BIFF8 을 담는 변형)
    let find = |name: &str| {
        c.nodes
            .iter()
            .find(|n| !n.is_storage && n.path.eq_ignore_ascii_case(name))
    };
    let Some(node) = find("Workbook").or_else(|| find("Book")) else {
        return blocked("structure", "Workbook 스트림 없음");
    };
    let (stream_name, wb) = (node.path.as_str(), node.data.as_slice());

    // 임베디드 OLE 개체(MBD* 저장소): 내용이 있으면 차단하거나(기본) 빈 저장소로 대체
    let mut mbd: Vec<(String, [u8; 16])> = Vec::new();
    for n in c
        .nodes
        .iter()
        .filter(|n| n.is_storage && !n.path.contains('/') && n.path.starts_with("MBD"))
    {
        let has_children = c
            .nodes
            .iter()
            .any(|x| x.path.starts_with(&format!("{}/", n.path)));
        if has_children {
            if !policy.neutralize_embedded_ole {
                return blocked(
                    "embedded-object",
                    "임베디드 OLE 개체가 포함된 XLS 는 차단합니다 (--neutralize-ole 로 빈 개체 대체 가능)",
                );
            }
            findings.add(
                "embedded-object",
                Severity::High,
                "임베디드 OLE 개체를 빈 개체로 대체(미리보기 그림 유지)",
                n.path.as_str(),
            );
        }
        mbd.push((n.path.clone(), n.clsid));
    }
    if c.nodes
        .iter()
        .any(|n| n.path.split('/').next() == Some("Ctls"))
    {
        return blocked(
            "activex",
            "ActiveX 컨트롤이 포함된 XLS 는 안전하게 재조합할 수 없어 차단합니다",
        );
    }

    // BIFF 레코드 검사
    let mut pos = 0usize;
    let mut records = 0usize;
    let mut auto_names = 0u32;
    let mut external_books = 0u32;
    let mut hlink_bodies: Vec<(usize, usize)> = Vec::new();
    // 모든 BIFF 레코드 본문 구간 (그림 제자리 재인코딩이 레코드 경계를 넘지 않게)
    let mut bodies: Vec<(usize, usize)> = Vec::new();
    while pos + 4 <= wb.len() {
        let rt = u16::from_le_bytes([wb[pos], wb[pos + 1]]);
        let len = u16::from_le_bytes([wb[pos + 2], wb[pos + 3]]) as usize;
        let Some(body) = wb.get(pos + 4..pos + 4 + len) else {
            return blocked("structure", "BIFF 레코드 길이 오류");
        };
        let body_at = pos + 4;
        bodies.push((body_at, body_at + len));
        pos += 4 + len;
        records += 1;
        match rt {
            FILEPASS => {
                return blocked(
                    "encrypted",
                    "암호화된 Excel 문서는 검사할 수 없어 차단합니다",
                )
            }
            BOUNDSHEET if body.len() >= 6 => match body[5] {
                1 => {
                    return blocked(
                        "xlm-macro",
                        "Excel 4.0(XLM) 매크로 시트가 포함되어 차단합니다",
                    )
                }
                6 => return blocked("macro", "VB 모듈 시트가 포함되어 차단합니다"),
                _ => {}
            },
            NAME if body.len() >= 15 => {
                let builtin = u16::from_le_bytes([body[0], body[1]]) & 0x20 != 0;
                let cch = body[3] as usize;
                let high = body[14] & 1 != 0;
                let name: String = if high {
                    body.get(15..15 + cch * 2)
                        .map(super::cfbx::utf16le)
                        .unwrap_or_default()
                } else {
                    body.get(15..15 + cch)
                        .map(|b| b.iter().map(|&c| c as char).collect())
                        .unwrap_or_default()
                };
                let lower = name.to_ascii_lowercase();
                if REQUEST_FUNCTIONS.iter().any(|f| lower == *f) {
                    return blocked(
                        "external-resource",
                        format!("외부 요청 함수({})가 포함되어 차단합니다", &name[6..]),
                    );
                }
                if (builtin && matches!(name.chars().next(), Some('\u{1}') | Some('\u{2}')))
                    || lower.starts_with("auto_open")
                    || lower.starts_with("auto_close")
                {
                    auto_names += 1;
                }
            }
            SUPBOOK if body.len() >= 4 => {
                let ctab = u16::from_le_bytes([body[0], body[1]]);
                let cch = u16::from_le_bytes([body[2], body[3]]);
                if cch != 0x0401 && cch != 0x3A01 {
                    if ctab == 0 {
                        return blocked("dde", "DDE/OLE 외부 링크가 포함되어 차단합니다");
                    }
                    external_books += 1;
                }
            }
            HLINK => hlink_bodies.push((body_at, len)),
            OBPROJ => findings.add(
                "macro",
                Severity::Info,
                "VBA 프로젝트 표시 레코드(OBPROJ) - 프로젝트 본체는 조립하지 않음",
                stream_name,
            ),
            _ => {}
        }
    }
    if pos != wb.len() && wb.len() - pos > 16 {
        findings.add(
            "hidden-data",
            Severity::Low,
            "Workbook 스트림 끝의 해석되지 않는 데이터",
            stream_name,
        );
    }
    findings.count("biff_records", records as u64);
    if auto_names > 0 {
        findings.add(
            "auto-exec",
            Severity::Low,
            format!(
                "자동 실행 이름(Auto_Open/Close) {auto_names}개 - 연결된 매크로는 조립하지 않음"
            ),
            stream_name,
        );
    }
    if external_books > 0 {
        findings.add(
            "external-link",
            Severity::Low,
            format!("외부 통합 문서 참조 {external_books}개(자동 업데이트 시 경로 접근)"),
            stream_name,
        );
    }

    // 하이퍼링크(HLINK): 허용 URI 가 아닌 문자열(파일 모니커, 상대/UNC 경로 등)을 제자리에서 공백으로
    let mut wb_out = wb.to_vec();
    let mut neutralized = Vec::new();
    for (at, len) in hlink_bodies {
        let body = &wb_out[at..at + len];
        // 구조를 해석할 수 있으면 실제 대상(모니커)만 검사하고, 표시 문자열·문서 내 위치는 그대로 둔다.
        // 해석할 수 없는 형태(알 수 없는 모니커 등)는 안전하게 문자열 전체를 검사한다.
        let targets = hlink_targets(body).unwrap_or_else(|| text_runs(body));
        for (start, bytes, wide, text) in targets {
            let t = text.trim_matches(char::from(0));
            if t.starts_with('#') || (policy.uri_allowed(t) && !policy.remove_hyperlinks) {
                continue;
            }
            // 대상처럼 보이는 문자열(스킴·경로 구분자·확장자 포함)만 보고 대상으로 삼는다
            let looks_like_target = t.contains([':', '\\', '/', '.']);
            let region = &mut wb_out[at + start..at + start + bytes];
            if wide {
                for c in region.as_chunks_mut::<2>().0 {
                    *c = [0x20, 0];
                }
            } else {
                region.fill(0x20);
            }
            if looks_like_target {
                neutralized.push(t.to_string());
            }
        }
    }
    if !neutralized.is_empty() {
        findings.add(
            "dangerous-link",
            Severity::High,
            format!(
                "허용되지 않은 하이퍼링크 대상 제거: {}",
                crate::ooxml::content::truncate(&neutralized.join(", "), 160)
            ),
            stream_name,
        );
    }

    // 그리기 그룹의 그림(OfficeArt BLIP): 한 BIFF 레코드 안에 온전히 들어 있는 것만 제자리 재인코딩
    // (CONTINUE 레코드로 나뉜 큰 그림은 레코드 헤더가 중간에 끼어 있어 원본 유지)
    let within_record = |s: usize, e: usize| {
        let i = bodies.partition_point(|&(b, _)| b <= s);
        i > 0 && e <= bodies[i - 1].1
    };
    let stats = super::blip::reencode_in_place(&mut wb_out, policy, &within_record);
    super::blip::report(&stats, findings, stream_name);

    // 새 컨테이너 조립
    let mut out = vec![Node {
        path: stream_name.into(),
        is_storage: false,
        clsid: [0; 16],
        data: wb_out,
    }];
    for n in &c.nodes {
        if n.path == "_SX_DB_CUR" || n.path.starts_with("_SX_DB_CUR/") {
            out.push(Node {
                path: n.path.clone(),
                is_storage: n.is_storage,
                clsid: n.clsid,
                data: n.data.clone(),
            });
        }
    }
    for (path, clsid) in &mbd {
        out.push(Node {
            path: path.clone(),
            is_storage: true,
            clsid: *clsid,
            data: Vec::new(),
        });
    }
    if let Some(d) = c.stream("\u{1}CompObj") {
        out.push(Node {
            path: "\u{1}CompObj".into(),
            is_storage: false,
            clsid: [0; 16],
            data: d.to_vec(),
        });
    }
    let summaries = ["\u{5}SummaryInformation", "\u{5}DocumentSummaryInformation"];
    for s in summaries {
        if let Some(d) = c.stream(s) {
            if policy.strip_metadata {
                findings.add(
                    "metadata",
                    Severity::Info,
                    "문서 요약 정보(작성자 등) 제거",
                    s.trim_start_matches('\u{5}'),
                );
            } else {
                out.push(Node {
                    path: s.into(),
                    is_storage: false,
                    clsid: [0; 16],
                    data: d.to_vec(),
                });
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    for n in &c.nodes {
        let top = n.path.split('/').next().unwrap_or("").to_string();
        if out.iter().any(|o| o.path.eq_ignore_ascii_case(&top))
            || summaries.contains(&top.as_str())
            || !seen.insert(top.clone())
        {
            continue;
        }
        let (cat, sev, desc) = match top.as_str() {
            "_VBA_PROJECT_CUR" | "_VBA_PROJECT" | "Macros" => {
                ("macro", Severity::Critical, "VBA 매크로")
            }
            "MsoDataStore" => ("custom-xml", Severity::Info, "사용자 정의 XML 데이터"),
            "\u{1}Ole" => ("embedded-object", Severity::Info, "OLE 링크 정보"),
            "Book" | "BOOK" => (
                "hidden-data",
                Severity::Low,
                "사용하지 않는 이전 형식 통합 문서 스트림",
            ),
            "Revision Log" => ("hidden-data", Severity::Low, "변경 내용 추적 기록"),
            _ => ("orphan-part", Severity::Low, "허용 목록 외 항목"),
        };
        findings.add(
            cat,
            sev,
            format!("{desc} - 새 문서에 조립하지 않음"),
            top.replace(['\u{1}', '\u{5}'], "").as_str(),
        );
    }
    findings.count("output_parts", out.len() as u64);
    cfbx::write(c.version, c.root_clsid, &out)
}

const URL_MONIKER: [u8; 16] = [
    0xE0, 0xC9, 0xEA, 0x79, 0xF9, 0xBA, 0xCE, 0x11, 0x8C, 0x82, 0x00, 0xAA, 0x00, 0x4B, 0xA9, 0x0B,
];
const FILE_MONIKER: [u8; 16] = [
    0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// HLINK 레코드([MS-XLS] 2.4.140)의 하이퍼링크 개체([MS-OSHARED] 2.3.7.1)에서
/// 링크 대상 문자열(모니커)의 위치를 찾는다. (시작 위치, 바이트 길이, UTF-16 여부, 문자열)
fn hlink_targets(body: &[u8]) -> Option<Vec<(usize, usize, bool, String)>> {
    let u32_at = |at: usize| -> Option<u32> {
        Some(u32::from_le_bytes(body.get(at..at + 4)?.try_into().ok()?))
    };
    let u16_at = |at: usize| -> Option<u16> {
        Some(u16::from_le_bytes(body.get(at..at + 2)?.try_into().ok()?))
    };
    // UTF-16 문자열(문자 수 = 끝의 NUL 포함) 한 개: (다음 위치, 대상 정보)
    let wide = |at: usize, bytes: usize| -> Option<(usize, usize, bool, String)> {
        let raw = body.get(at..at.checked_add(bytes)?)?;
        let units: Vec<u16> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        let text = String::from_utf16_lossy(&units)
            .trim_end_matches('\0')
            .to_string();
        Some((at, bytes, true, text))
    };
    let hyperlink_string = |at: usize| -> Option<(usize, (usize, usize, bool, String))> {
        let chars = u32_at(at)? as usize;
        let bytes = chars.checked_mul(2)?;
        Some((at + 4 + bytes, wide(at + 4, bytes)?))
    };

    let mut p = 8 + 16;
    if u32_at(p)? != 2 {
        return None;
    }
    let flags = u32_at(p + 4)?;
    p += 8;
    let mut out = Vec::new();
    if flags & 0x10 != 0 {
        p = hyperlink_string(p)?.0; // 표시 이름
    }
    if flags & 0x80 != 0 {
        p = hyperlink_string(p)?.0; // 대상 프레임 이름
    }
    if flags & 0x01 != 0 {
        if flags & 0x100 != 0 {
            let (next, t) = hyperlink_string(p)?;
            out.push(t);
            p = next;
        } else {
            let clsid = body.get(p..p + 16)?;
            p += 16;
            if clsid == URL_MONIKER {
                let len = u32_at(p)? as usize;
                // 길이 안에 NUL 로 끝나는 URL 뒤로 선택적 GUID 등이 붙을 수 있다
                let raw = body.get(p + 4..p + 4 + len)?;
                let chars = raw
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .position(|c| *c == [0, 0])
                    .unwrap_or(len / 2);
                out.push(wide(p + 4, chars * 2)?);
                p += 4 + len;
            } else if clsid == FILE_MONIKER {
                let ansi_len = u32_at(p + 2)? as usize;
                let ansi_at = p + 6;
                let ansi = body.get(ansi_at..ansi_at.checked_add(ansi_len)?)?;
                let text: String = ansi
                    .iter()
                    .take_while(|&&b| b != 0)
                    .map(|&b| b as char)
                    .collect();
                out.push((ansi_at, ansi_len, false, text));
                p = ansi_at + ansi_len + 2 + 2 + 16 + 4;
                let cb = u32_at(p)? as usize;
                p += 4;
                if cb > 0 {
                    let bytes = u32_at(p)? as usize;
                    u16_at(p + 4)?;
                    out.push(wide(p + 6, bytes)?);
                    p += 6 + bytes;
                }
            } else {
                return None;
            }
        }
    }
    if flags & 0x08 != 0 {
        hyperlink_string(p)?; // 문서 내 위치: 검사 대상 아님
    }
    Some(out)
}

/// 레코드 본문에서 사람이 읽을 수 있는 문자열 구간(UTF-16LE 우선, 그다음 ANSI)을 찾는다.
/// (시작 위치, 바이트 길이, UTF-16 여부, 문자열)
fn text_runs(body: &[u8]) -> Vec<(usize, usize, bool, String)> {
    let printable = |b: u8| (0x20..0x7f).contains(&b);
    let mut covered = vec![false; body.len()];
    let mut out = Vec::new();
    for parity in 0..2 {
        let mut i = parity;
        while i + 1 < body.len() {
            let start = i;
            let mut units = Vec::new();
            while i + 1 < body.len() && !covered[i] {
                let u = u16::from_le_bytes([body[i], body[i + 1]]);
                let ok = (u < 0x80 && printable(u as u8))
                    || (0xac00..=0xd7a3).contains(&u)
                    || (0x3131..=0x318e).contains(&u);
                if !ok {
                    break;
                }
                units.push(u);
                i += 2;
            }
            if units.len() >= 3 {
                for c in covered.iter_mut().take(i).skip(start) {
                    *c = true;
                }
                out.push((start, i - start, true, String::from_utf16_lossy(&units)));
            } else {
                i = start + 2;
            }
        }
    }
    let mut i = 0;
    while i < body.len() {
        let start = i;
        while i < body.len() && !covered[i] && printable(body[i]) {
            i += 1;
        }
        if i - start >= 4 {
            out.push((
                start,
                i - start,
                false,
                body[start..i].iter().map(|&b| b as char).collect(),
            ));
        }
        i = i.max(start + 1);
    }
    out
}
