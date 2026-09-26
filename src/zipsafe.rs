//! 안전한 압축 해제(Zip bomb·경로 조작·암호화 방어)와 결정적 재압축.

use std::io::{Cursor, Read, Write};

use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::error::{blocked, Result};
use crate::policy::Policy;
use crate::report::{Findings, Severity};

pub struct Entry {
    pub name: String,
    pub data: Vec<u8>,
}

pub fn read_entries(data: &[u8], policy: &Policy, findings: &mut Findings) -> Result<Vec<Entry>> {
    let mut archive = match ZipArchive::new(Cursor::new(data)) {
        Ok(a) => a,
        Err(e) => return blocked("structure", format!("손상된 압축 컨테이너: {e}")),
    };
    if archive.len() > policy.max_zip_entries {
        return blocked(
            "zip-bomb",
            format!("압축 엔트리 수 초과 ({})", archive.len()),
        );
    }

    let mut total: u64 = 0;
    let mut seen = std::collections::HashSet::new();
    let mut entries = Vec::new();
    for i in 0..archive.len() {
        let (name, size, csize, encrypted, is_dir) = match archive.by_index_raw(i) {
            Ok(f) => (
                f.name().to_string(),
                f.size(),
                f.compressed_size(),
                f.encrypted(),
                f.is_dir(),
            ),
            Err(e) => return blocked("structure", format!("엔트리 읽기 실패: {e}")),
        };
        if is_dir {
            continue;
        }
        if encrypted {
            return blocked("encrypted", format!("암호화된 엔트리: {name}"));
        }
        if !safe_name(&name) {
            return blocked("path-traversal", format!("비정상 엔트리 이름: {name}"));
        }
        if !seen.insert(name.to_ascii_lowercase()) {
            findings.add(
                "structure",
                Severity::Medium,
                "중복 엔트리 무시",
                name.as_str(),
            );
            continue;
        }
        total = total.saturating_add(size);
        if total > policy.max_zip_total {
            return blocked("zip-bomb", "압축 해제 총량 초과");
        }
        if size > 1024 * 1024 && csize > 0 && size / csize > policy.max_zip_ratio {
            return blocked("zip-bomb", format!("비정상 압축률 엔트리: {name}"));
        }

        let mut file = match archive.by_index(i) {
            Ok(f) => f,
            Err(e) => return blocked("structure", format!("엔트리 읽기 실패: {name} ({e})")),
        };
        // 헤더 크기 위조에 대비해 실제 해제량도 제한한다
        let mut buf = Vec::with_capacity(size.min(64 * 1024 * 1024) as usize);
        let limit = size.saturating_add(1);
        if let Err(e) = (&mut file).take(limit).read_to_end(&mut buf) {
            return blocked("structure", format!("엔트리 해제 실패: {name} ({e})"));
        }
        if buf.len() as u64 > size {
            return blocked("zip-bomb", format!("선언 크기와 실제 크기 불일치: {name}"));
        }
        entries.push(Entry { name, data: buf });
    }
    Ok(entries)
}

/// 파트 이름은 영숫자와 일부 기호로 된 상대 경로만 허용한다.
fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 512
        && !name.starts_with('/')
        && !name.contains('\\')
        && !name
            .split('/')
            .any(|seg| seg.is_empty() || seg == "." || seg == "..")
        && name.chars().all(|c| !c.is_control() && c != ':')
}

pub fn write_entries(entries: &[Entry]) -> Result<Vec<u8>> {
    write_entries_with(entries, &[])
}

/// `stored` 에 있는 엔트리는 압축하지 않고 저장한다 (예: OCF 의 mimetype).
pub fn write_entries_with(entries: &[Entry], stored: &[&str]) -> Result<Vec<u8>> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let opts = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .last_modified_time(zip::DateTime::default())
        .unix_permissions(0o644);
    let stored_opts = opts.compression_method(CompressionMethod::Stored);
    for e in entries {
        let opts = if stored.contains(&e.name.as_str()) {
            stored_opts
        } else {
            opts
        };
        let r = writer
            .start_file(e.name.as_str(), opts)
            .map_err(|e| e.to_string())
            .and_then(|_| writer.write_all(&e.data).map_err(|e| e.to_string()));
        if let Err(err) = r {
            return blocked("reconstruct", format!("압축 파일 작성 실패: {err}"));
        }
    }
    match writer.finish() {
        Ok(c) => Ok(c.into_inner()),
        Err(e) => blocked("reconstruct", format!("압축 파일 작성 실패: {e}")),
    }
}
