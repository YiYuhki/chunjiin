//! 일반 ZIP 압축 파일 재조합: 항목마다 같은 엔진으로 재조합·재검증하고, 결과물만으로
//! 새 압축 파일을 만든다. 차단된 항목은 빼고 보고한다(엄격 모드에서는 압축 파일 전체 차단).
//!
//! - 압축 안의 압축은 한 단계까지만 허용한다
//! - 압축 해제 총량 제한은 중첩된 압축까지 합산한 예산으로 적용한다(중첩 Zip bomb 방어)
//! - 항목 이름은 경로 조작을 거부한 상대 경로만 받고, 결과물 이름은 재조합된 형식에 맞춘다

use std::collections::HashSet;

use crate::detect::{self, FileType};
use crate::engine::Engine;
use crate::error::{blocked, Result};
use crate::policy::Policy;
use crate::report::{Findings, Severity, Status};
use crate::zipsafe::{self, Entry};

/// 압축 파일 안에 압축 파일이 들어 있을 수 있는 최대 깊이
pub const MAX_DEPTH: usize = 1;

pub fn reassemble(
    engine: &Engine,
    depth: usize,
    data: &[u8],
    findings: &mut Findings,
) -> Result<Vec<u8>> {
    let policy = &engine.policy;
    if !policy.allow_archives {
        return blocked("unsupported", "일반 압축 파일 처리가 비활성화되어 있음");
    }
    let entries = zipsafe::read_entries(data, policy, findings)?;
    let mut expanded: u64 = entries.iter().map(|e| e.data.len() as u64).sum();
    let mut out: Vec<Entry> = Vec::new();
    let mut names = HashSet::new();
    let mut blocked_members = 0u64;
    for e in entries {
        let is_archive = detect::detect(&e.data) == FileType::Zip;
        if is_archive && depth >= MAX_DEPTH {
            blocked_members += 1;
            if policy.strict_archives {
                return blocked("archive", format!("중첩 압축 깊이 초과: {}", e.name));
            }
            findings.add(
                "archive-member",
                Severity::Medium,
                "중첩 압축 깊이 초과 - 항목 제외",
                e.name.as_str(),
            );
            continue;
        }
        // 중첩 압축은 남은 해제 예산 안에서만 풀 수 있다
        let child = Engine::nested(
            Policy {
                max_zip_total: policy.max_zip_total.saturating_sub(expanded),
                ..policy.clone()
            },
            depth + 1,
        );
        let r = child.process(&e.data, &e.name);
        let nested = r.stats.get("archive_bytes").copied().unwrap_or(0);
        expanded = expanded.saturating_add(nested);
        if expanded > policy.max_zip_total {
            return blocked("zip-bomb", "중첩 압축까지 합한 해제 총량 초과");
        }

        if r.status == Status::Blocked {
            blocked_members += 1;
            if policy.strict_archives {
                return blocked(
                    "archive",
                    format!("차단된 항목이 있어 전체 차단: {} ({})", e.name, r.reason),
                );
            }
            findings.add(
                "archive-member",
                Severity::Medium,
                format!("차단된 항목 제외 - {}", r.reason),
                e.name.as_str(),
            );
            continue;
        }
        for f in r.findings {
            let at = if f.location.is_empty() {
                e.name.clone()
            } else {
                format!("{} > {}", e.name, f.location)
            };
            findings.add(&f.category, f.severity, f.description, at);
        }
        for (k, v) in r.stats {
            if k != "archive_bytes" {
                findings.count(&k, v);
            }
        }
        let (Some(output), Some(out_name)) = (r.output, r.output_filename) else {
            continue;
        };
        let dir = e
            .name
            .rsplit_once('/')
            .map(|(d, _)| format!("{d}/"))
            .unwrap_or_default();
        let name = unique_name(&mut names, &format!("{dir}{out_name}"));
        if name != e.name {
            findings.count("archive_members_renamed", 1);
        }
        out.push(Entry { name, data: output });
    }
    findings.count("archive_members", out.len() as u64);
    if blocked_members > 0 {
        findings.count("archive_members_blocked", blocked_members);
    }
    findings.count("archive_bytes", expanded);
    if out.is_empty() {
        return blocked("archive", "압축 파일 안에 재조합할 수 있는 항목이 없음");
    }
    zipsafe::write_entries(&out)
}

/// 같은 결과 이름(예: a.docm 과 a.docx → a.docx)이 겹치면 번호를 붙인다
fn unique_name(names: &mut HashSet<String>, name: &str) -> String {
    if names.insert(name.to_ascii_lowercase()) {
        return name.to_string();
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() && !s.ends_with('/') => (s.to_string(), format!(".{e}")),
        _ => (name.to_string(), String::new()),
    };
    (1..)
        .map(|n| format!("{stem}_{n}{ext}"))
        .find(|c| names.insert(c.to_ascii_lowercase()))
        .unwrap()
}
