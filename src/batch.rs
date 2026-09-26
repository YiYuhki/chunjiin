//! 일괄 처리 유틸리티: 순서를 보존하는 병렬 처리와 원자적 결과물 쓰기.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// 임시 파일 접미사 - 쓰는 도중의 결과물을 다른 프로세스가 가져가지 않도록 숨김 파일로 쓴다.
pub const TEMP_SUFFIX: &str = ".cdr-partial";

/// `jobs` 개 스레드로 항목을 처리한다. 결과는 입력 순서대로 돌려준다.
pub fn par_map<T, R, F>(items: &[T], jobs: usize, f: F) -> Vec<R>
where
    T: Sync,
    R: Send,
    F: Fn(&T) -> R + Sync,
{
    let jobs = jobs.clamp(1, items.len().max(1));
    if jobs == 1 {
        return items.iter().map(&f).collect();
    }
    let next = AtomicUsize::new(0);
    let slots: Vec<Mutex<Option<R>>> = items.iter().map(|_| Mutex::new(None)).collect();
    std::thread::scope(|s| {
        for _ in 0..jobs {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(item) = items.get(i) else { break };
                let r = f(item);
                *slots[i].lock().unwrap_or_else(|e| e.into_inner()) = Some(r);
            });
        }
    });
    slots
        .into_iter()
        .map(|m| {
            m.into_inner()
                .unwrap_or_else(|e| e.into_inner())
                .expect("모든 항목 처리됨")
        })
        .collect()
}

pub fn default_jobs() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
}

/// 결과물을 원자적으로 쓴다: 숨김 임시 파일에 쓰고 동기화한 뒤 이름을 바꾼다.
/// 같은 이름이 있으면(덮어쓰기가 아니면) `이름_1.확장자` 식으로 피한다.
/// 이름 결정과 이동은 `lock` 으로 직렬화해 병렬 처리 중 충돌을 막는다.
pub fn write_atomic(
    dir: &Path,
    name: &str,
    data: &[u8],
    overwrite: bool,
    lock: &Mutex<()>,
) -> io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let file_name = sanitize_name(name);
    let tmp = dir.join(format!(".{file_name}.{}{TEMP_SUFFIX}", std::process::id()));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());
    let mut target = dir.join(&file_name);
    let (stem, ext) = match file_name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{e}")),
        _ => (file_name.clone(), String::new()),
    };
    let mut n = 1;
    while !overwrite && target.exists() {
        target = dir.join(format!("{stem}_{n}{ext}"));
        n += 1;
    }
    if let Err(e) = fs::rename(&tmp, &target) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(target)
}

/// 경로 구분자·제어 문자·숨김 파일 이름을 막는다.
pub fn sanitize_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = cleaned.trim().trim_start_matches('.');
    if trimmed.is_empty() {
        "unnamed".into()
    } else {
        trimmed.chars().take(200).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn par_map_keeps_order() {
        let items: Vec<u32> = (0..200).collect();
        let out = par_map(&items, 8, |x| x * 2);
        assert_eq!(out, items.iter().map(|x| x * 2).collect::<Vec<_>>());
    }

    #[test]
    fn names_are_sanitized() {
        assert_eq!(sanitize_name("../../etc/passwd"), "_.._etc_passwd");
        assert_eq!(sanitize_name(".hidden"), "hidden");
        assert_eq!(sanitize_name("a\u{0}b.docx"), "a_b.docx");
        assert_eq!(sanitize_name(""), "unnamed");
    }

    #[test]
    fn atomic_write_avoids_collisions() {
        let dir = std::env::temp_dir().join(format!("cdr-batch-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let lock = Mutex::new(());
        let a = write_atomic(&dir, "r.pdf", b"1", false, &lock).unwrap();
        let b = write_atomic(&dir, "r.pdf", b"2", false, &lock).unwrap();
        assert_eq!(a.file_name().unwrap(), "r.pdf");
        assert_eq!(b.file_name().unwrap(), "r_1.pdf");
        assert!(fs::read_dir(&dir).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(TEMP_SUFFIX)));
        let _ = fs::remove_dir_all(&dir);
    }
}
