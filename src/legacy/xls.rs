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

    for n in &c.nodes {
        let top = n.path.split('/').next().unwrap_or("");
        if top.starts_with("MBD") {
            return blocked(
                "embedded-object",
                "임베디드 OLE 개체가 포함된 XLS 는 안전하게 재조합할 수 없어 차단합니다",
            );
        }
        if top == "Ctls" {
            return blocked(
                "activex",
                "ActiveX 컨트롤이 포함된 XLS 는 안전하게 재조합할 수 없어 차단합니다",
            );
        }
    }

    // BIFF 레코드 검사
    let mut pos = 0usize;
    let mut records = 0usize;
    let mut auto_names = 0u32;
    let mut external_books = 0u32;
    while pos + 4 <= wb.len() {
        let rt = u16::from_le_bytes([wb[pos], wb[pos + 1]]);
        let len = u16::from_le_bytes([wb[pos + 2], wb[pos + 3]]) as usize;
        let Some(body) = wb.get(pos + 4..pos + 4 + len) else {
            return blocked("structure", "BIFF 레코드 길이 오류");
        };
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

    // 새 컨테이너 조립
    let mut out = vec![Node {
        path: stream_name.into(),
        is_storage: false,
        clsid: [0; 16],
        data: wb.to_vec(),
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
