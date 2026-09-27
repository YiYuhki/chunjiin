//! 감시 폴더 모드: 수신 폴더에 들어온 파일을 재조합해 송신 폴더로 넘긴다.
//!
//! 망연계·메일 게이트웨이처럼 "들어온 문서는 반드시 CDR 을 거쳐서만 나간다" 는 흐름을 위한 것이다.
//! - 크기와 수정 시각이 `settle` 동안 변하지 않은 파일만 처리한다(복사 중인 파일 보호)
//! - 결과물은 숨김 임시 파일에 쓴 뒤 이름을 바꾼다(송신 측이 쓰는 중인 파일을 가져가지 않음)
//! - 하위 폴더 구조를 송신 폴더에 그대로 유지한다
//! - 차단된 파일은 결과물 대신 보고서(JSON)만 `blocked` 폴더에 남긴다
//! - 감사 기록과 결과물 쓰기가 모두 성공해야 수신 폴더에서 원본을 지운다.
//!   실패한 파일은 내용이 바뀌기 전까지 다시 시도하지 않는다
//! - 숨김 파일과 쓰는 중임을 나타내는 확장자(.part, .tmp, .crdownload 등)는 건너뛴다

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use crate::audit::Auditor;
use crate::batch::{self, par_map, TEMP_SUFFIX};
use crate::report::{CdrResult, Status};
use crate::Engine;

pub struct WatchConfig {
    pub inbox: PathBuf,
    pub outbox: PathBuf,
    pub blocked: Option<PathBuf>,
    pub interval: Duration,
    pub settle: Duration,
    pub jobs: usize,
    /// 한 번 훑고 끝낸다(안정화 대기 없이 현재 파일을 모두 처리)
    pub once: bool,
}

/// 처리 결과 알림 (진행 상황 출력용)
pub enum Event<'a> {
    Processed {
        rel: &'a Path,
        result: &'a CdrResult,
        output: Option<&'a Path>,
    },
    Failed {
        rel: &'a Path,
        error: String,
    },
    Cycle {
        processed: usize,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    size: u64,
    modified: SystemTime,
}

const SKIP_SUFFIXES: &[&str] = &[
    ".part",
    ".partial",
    ".tmp",
    ".temp",
    ".crdownload",
    ".download",
    ".filepart",
    TEMP_SUFFIX,
];

fn skip(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    name.starts_with('.')
        || name.starts_with('~')
        || SKIP_SUFFIXES.iter().any(|s| lower.ends_with(s))
}

fn list_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if skip(&name) {
                continue;
            }
            // 심볼릭 링크는 따라가지 않는다 (수신 폴더 밖 파일 유출 방지)
            match e.file_type() {
                Ok(t) if t.is_dir() => stack.push(e.path()),
                Ok(t) if t.is_file() => out.push(e.path()),
                _ => {}
            }
        }
    }
    out.sort();
    out
}

/// 일반 파일만 읽는다. 목록 작성 이후 심볼릭 링크 등으로 바꿔치기된 경우
/// (열기 전 lstat 과 연 뒤 fstat 의 파일 식별자가 다르면) 거부한다.
fn read_regular(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "일반 파일이 아님",
        ));
    }
    let mut f = fs::File::open(path)?;
    let after = f.metadata()?;
    #[cfg(unix)]
    let same = {
        use std::os::unix::fs::MetadataExt;
        before.dev() == after.dev() && before.ino() == after.ino()
    };
    #[cfg(not(unix))]
    let same = after.is_file() && fs::symlink_metadata(path)?.is_file();
    if !same || !after.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "처리 중 파일이 바뀜",
        ));
    }
    // 크기 제한보다 1바이트만 더 읽으면 엔진이 크기 초과로 차단한다(거대 파일 전체를 메모리에 올리지 않음)
    let mut data = Vec::new();
    io::Read::read_to_end(&mut io::Read::take(&mut f, limit as u64 + 1), &mut data)?;
    Ok(data)
}

fn stamp(path: &Path) -> Option<Stamp> {
    let m = fs::symlink_metadata(path).ok()?;
    m.is_file().then(|| Stamp {
        size: m.len(),
        modified: m.modified().unwrap_or(SystemTime::UNIX_EPOCH),
    })
}

pub struct Watcher<'a> {
    cfg: WatchConfig,
    engine: &'a Engine,
    auditor: &'a Auditor,
    seen: HashMap<PathBuf, (Stamp, Instant)>,
    failed: HashMap<PathBuf, Stamp>,
    lock: Mutex<()>,
}

impl<'a> Watcher<'a> {
    pub fn new(cfg: WatchConfig, engine: &'a Engine, auditor: &'a Auditor) -> io::Result<Self> {
        fs::create_dir_all(&cfg.inbox)?;
        fs::create_dir_all(&cfg.outbox)?;
        if let Some(b) = &cfg.blocked {
            fs::create_dir_all(b)?;
        }
        let inbox = fs::canonicalize(&cfg.inbox)?;
        for other in [Some(&cfg.outbox), cfg.blocked.as_ref()]
            .into_iter()
            .flatten()
        {
            let o = fs::canonicalize(other)?;
            if o.starts_with(&inbox) || inbox.starts_with(&o) {
                return Err(io::Error::other(
                    "수신 폴더와 송신/차단 폴더는 서로 포함 관계일 수 없습니다",
                ));
            }
        }
        clean_partials(&cfg.outbox);
        Ok(Watcher {
            cfg,
            engine,
            auditor,
            seen: HashMap::new(),
            failed: HashMap::new(),
            lock: Mutex::new(()),
        })
    }

    /// 감시를 계속한다. `stop` 이 true 를 돌려주면 끝낸다.
    pub fn run(&mut self, on_event: &(dyn Fn(Event) + Sync), stop: &dyn Fn() -> bool) {
        loop {
            let n = self.cycle(on_event);
            on_event(Event::Cycle { processed: n });
            if self.cfg.once || stop() {
                break;
            }
            std::thread::sleep(self.cfg.interval);
            if stop() {
                break;
            }
        }
    }

    /// 한 주기: 준비된 파일을 골라 병렬로 처리한다. 처리한 파일 수를 돌려준다.
    pub fn cycle(&mut self, on_event: &(dyn Fn(Event) + Sync)) -> usize {
        let now = Instant::now();
        let files = list_files(&self.cfg.inbox);
        let present: HashSet<&PathBuf> = files.iter().collect();
        self.seen.retain(|p, _| present.contains(p));
        self.failed.retain(|p, _| present.contains(p));

        let mut ready = Vec::new();
        for path in &files {
            let Some(st) = stamp(path) else { continue };
            if self.failed.get(path) == Some(&st) {
                continue; // 이전에 실패했고 내용이 바뀌지 않음
            }
            let age = st.modified.elapsed().unwrap_or_default();
            let stable = match self.seen.get(path) {
                Some((prev, since)) if *prev == st => now.duration_since(*since) >= self.cfg.settle,
                _ => {
                    self.seen.insert(path.clone(), (st, now));
                    false
                }
            };
            if self.cfg.once || (stable && age >= self.cfg.settle) {
                ready.push((path.clone(), st));
            }
        }

        let outcomes = par_map(&ready, self.cfg.jobs, |(path, st)| {
            let rel = path
                .strip_prefix(&self.cfg.inbox)
                .unwrap_or(path)
                .to_path_buf();
            let r = self.process_one(path, &rel);
            match &r {
                Ok((result, out)) => on_event(Event::Processed {
                    rel: &rel,
                    result,
                    output: out.as_deref(),
                }),
                Err(e) => on_event(Event::Failed {
                    rel: &rel,
                    error: e.to_string(),
                }),
            }
            (path.clone(), *st, r.is_ok())
        });

        let mut done = 0;
        for (path, st, ok) in outcomes {
            self.seen.remove(&path);
            if ok {
                done += 1;
                remove_empty_parents(&path, &self.cfg.inbox);
            } else {
                self.failed.insert(path, st);
            }
        }
        done
    }

    fn process_one(&self, path: &Path, rel: &Path) -> io::Result<(CdrResult, Option<PathBuf>)> {
        let data = read_regular(path, self.engine.policy.max_file_size)?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let started = Instant::now();
        let result = self.engine.process(&data, &name);
        if self.auditor.is_enabled() {
            self.auditor.record(
                &result,
                &data,
                &path.display().to_string(),
                &self.engine.policy,
                started.elapsed(),
            )?;
        }
        let sub = rel.parent().unwrap_or(Path::new(""));
        let output = match (&result.output, &result.output_filename) {
            (Some(bytes), Some(out_name)) if result.status != Status::Blocked => {
                Some(batch::write_atomic(
                    &self.cfg.outbox.join(sub),
                    out_name,
                    bytes,
                    false,
                    &self.lock,
                )?)
            }
            _ => {
                if let Some(dir) = &self.cfg.blocked {
                    let report = serde_json::to_vec_pretty(&result).map_err(io::Error::other)?;
                    batch::write_atomic(
                        &dir.join(sub),
                        &format!("{name}.blocked.json"),
                        &report,
                        false,
                        &self.lock,
                    )?;
                }
                None
            }
        };
        // 여기까지 모두 성공했을 때만 원본을 수신 폴더에서 지운다
        fs::remove_file(path)?;
        Ok((result, output))
    }
}

fn remove_empty_parents(path: &Path, root: &Path) {
    let mut dir = path.parent();
    while let Some(d) = dir {
        if d == root || !d.starts_with(root) || fs::remove_dir(d).is_err() {
            break;
        }
        dir = d.parent();
    }
}

/// 이전 실행이 중단되며 남긴 임시 파일 정리
fn clean_partials(dir: &Path) {
    for p in list_all(dir) {
        if p.file_name()
            .is_some_and(|n| n.to_string_lossy().ends_with(TEMP_SUFFIX))
        {
            let _ = fs::remove_file(p);
        }
    }
}

fn list_all(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            match e.file_type() {
                Ok(t) if t.is_dir() => stack.push(e.path()),
                Ok(t) if t.is_file() => out.push(e.path()),
                _ => {}
            }
        }
    }
    out
}
