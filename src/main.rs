//! cdr 명령행 도구.
//!
//!   cdr sanitize 받은문서.docm -o clean/ --report report.json
//!   cdr scan 의심파일.pdf
//!   cdr watch --inbox 수신/ --outbox 송신/ --quarantine 격리/ --audit-log audit.jsonl
//!   cdr serve --bind 0.0.0.0:8080
//!   cdr policy > cdr.toml

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand};

use cdr::audit::{AuditConfig, Auditor};
use cdr::batch::{self, par_map};
use cdr::config::PolicyFile;
use cdr::watch::{Event, WatchConfig, Watcher};
use cdr::{CdrResult, Engine, Policy, Status};

#[derive(Parser)]
#[command(
    name = "cdr",
    version,
    about = "CDR(Content Disarm & Reconstruction) - 오피스/한글/PDF 문서 재조합 도구"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 문서를 재조합하여 안전한 파일로 저장
    Sanitize {
        /// 파일 또는 디렉터리
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
        /// 출력 디렉터리
        #[arg(short, long)]
        output: PathBuf,
        /// 같은 이름의 출력 파일 덮어쓰기
        #[arg(long)]
        overwrite: bool,
        #[command(flatten)]
        common: Common,
    },
    /// 저장 없이 분석 결과만 출력
    Scan {
        /// 파일 또는 디렉터리
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
        #[command(flatten)]
        common: Common,
    },
    /// 수신 폴더를 감시하며 들어온 문서를 재조합해 송신 폴더로 넘김
    Watch {
        /// 수신 폴더
        #[arg(long)]
        inbox: PathBuf,
        /// 송신 폴더 (재조합된 문서)
        #[arg(long)]
        outbox: PathBuf,
        /// 차단된 문서의 보고서(JSON)를 남길 폴더
        #[arg(long)]
        blocked: Option<PathBuf>,
        /// 폴더 확인 주기(초)
        #[arg(long, default_value_t = 2)]
        interval: u64,
        /// 파일이 이 시간(초) 동안 바뀌지 않아야 처리 (복사 중 파일 보호)
        #[arg(long, default_value_t = 3)]
        settle: u64,
        /// 현재 들어 있는 파일만 처리하고 종료
        #[arg(long)]
        once: bool,
        #[command(flatten)]
        common: Common,
    },
    /// REST API 서버 실행
    Serve {
        /// 바인드 주소
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: std::net::SocketAddr,
        /// 요청당 처리 제한 시간(초)
        #[arg(long, default_value_t = 120)]
        timeout: u64,
        /// 요청 파라미터로 정책을 완화하는 것을 허용 (기본: 강화하는 방향만 허용)
        #[arg(long)]
        allow_request_relax: bool,
        #[command(flatten)]
        common: Common,
    },
    /// 기본값과 설명이 들어간 정책 파일(TOML)을 출력
    Policy,
}

#[derive(Args)]
struct Common {
    /// 정책 파일(TOML). 명시한 명령행 옵션이 파일 값보다 우선한다
    #[arg(long)]
    config: Option<PathBuf>,
    /// 동시 처리 수 (기본: CPU 수)
    #[arg(short, long)]
    jobs: Option<usize>,
    /// JSON 보고서 저장 경로
    #[arg(long)]
    report: Option<PathBuf>,
    /// 허용 스킴의 하이퍼링크까지 모두 제외
    #[arg(long)]
    remove_links: bool,
    /// 작성자 등 메타데이터 유지
    #[arg(long)]
    keep_metadata: bool,
    /// PDF 주석/폼 외형을 평면화하지 않고 버림
    #[arg(long)]
    no_flatten: bool,
    /// 레거시 PPT/XLS 의 임베디드 OLE 개체를 차단하지 않고 빈 개체로 대체
    #[arg(long)]
    neutralize_ole: bool,
    /// 최고 보안 모드: PDF 페이지를 이미지로 렌더링하여 재구성
    #[arg(long)]
    rasterize: bool,
    /// 래스터화 해상도(DPI)
    #[arg(long)]
    dpi: Option<f32>,
    /// 최대 파일 크기(MB)
    #[arg(long)]
    max_size: Option<usize>,
    /// 탐지 항목 상세 출력
    #[arg(short, long)]
    verbose: bool,
    /// 감사 로그(JSONL) 파일 - 처리한 모든 파일을 한 줄씩 기록
    #[arg(long)]
    audit_log: Option<PathBuf>,
    /// 재조합/차단된 파일의 원본을 보관할 격리 폴더
    #[arg(long)]
    quarantine: Option<PathBuf>,
    /// 위협이 없던(정상) 파일의 원본도 격리 폴더에 보관
    #[arg(long)]
    quarantine_clean: bool,
}

impl Common {
    /// 기본값 → 정책 파일 → 명시한 명령행 옵션 순으로 정책을 만든다.
    fn policy(&self) -> Result<Policy, String> {
        let mut p = match &self.config {
            Some(path) => PolicyFile::load(path)?.into_policy()?,
            None => Policy::default(),
        };
        if self.remove_links {
            p.remove_hyperlinks = true;
        }
        if self.keep_metadata {
            p.strip_metadata = false;
        }
        if self.no_flatten {
            p.flatten_pdf_annotations = false;
        }
        if self.neutralize_ole {
            p.neutralize_embedded_ole = true;
        }
        if self.rasterize {
            p.pdf_rasterize = true;
        }
        if let Some(d) = self.dpi {
            p.raster_dpi = d.clamp(36.0, 600.0);
        }
        if let Some(mb) = self.max_size {
            p.max_file_size = mb.saturating_mul(1024 * 1024);
        }
        Ok(p)
    }

    fn auditor(&self) -> Result<Auditor, String> {
        Auditor::open(&AuditConfig {
            log_path: self.audit_log.clone(),
            quarantine_dir: self.quarantine.clone(),
            quarantine_clean: self.quarantine_clean,
        })
        .map_err(|e| format!("감사 로그/격리 폴더 준비 실패: {e}"))
    }

    fn jobs(&self) -> usize {
        self.jobs.unwrap_or_else(batch::default_jobs).max(1)
    }
}

fn collect(inputs: &[PathBuf]) -> Vec<PathBuf> {
    fn walk(p: &Path, out: &mut Vec<PathBuf>) {
        if p.is_dir() {
            if let Ok(rd) = fs::read_dir(p) {
                let mut entries: Vec<PathBuf> =
                    rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
                entries.sort();
                for e in entries {
                    walk(&e, out);
                }
            }
        } else if p.is_file() {
            out.push(p.to_path_buf());
        } else {
            eprintln!("경고: 파일을 찾을 수 없음 - {}", p.display());
        }
    }
    let mut out = Vec::new();
    for p in inputs {
        walk(p, &mut out);
    }
    out
}

fn label(s: Status) -> &'static str {
    match s {
        Status::Clean => "정상",
        Status::Sanitized => "재조합",
        Status::Blocked => "차단",
    }
}

fn format_result(name: &str, r: &CdrResult, verbose: bool) -> String {
    let tail = match &r.output_filename {
        Some(o) if r.status != Status::Blocked => format!(" → {o}"),
        _ => format!(" ({})", r.reason),
    };
    let mut s = format!(
        "[{}] {name} ({}, 탐지 {}건){tail}",
        label(r.status),
        r.detected_type,
        r.findings.len()
    );
    if verbose {
        for f in &r.findings {
            let loc = if f.location.is_empty() {
                String::new()
            } else {
                format!(" @ {}", f.location)
            };
            s.push_str(&format!(
                "\n    - [{:?}] {}: {}{loc}",
                f.severity, f.category, f.description
            ));
        }
        if !r.stats.is_empty() {
            let st: Vec<String> = r.stats.iter().map(|(k, v)| format!("{k}={v}")).collect();
            s.push_str(&format!("\n    · {}", st.join(", ")));
        }
    }
    s
}

struct Outcome {
    result: CdrResult,
    audit_failed: bool,
}

fn run(inputs: &[PathBuf], common: &Common, output: Option<(&Path, bool)>) -> ExitCode {
    let (policy, auditor) = match (common.policy(), common.auditor()) {
        (Ok(p), Ok(a)) => (p, a),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let engine = Engine::new(policy);
    let files = collect(inputs);
    if files.is_empty() {
        eprintln!("처리할 파일이 없습니다.");
        return ExitCode::from(1);
    }
    let write_lock = Mutex::new(());
    let print_lock = Mutex::new(());
    let verbose = common.verbose || output.is_none();

    let outcomes: Vec<Option<Outcome>> = par_map(&files, common.jobs(), |path| {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let data = match fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("읽기 실패: {} ({e})", path.display());
                return None;
            }
        };
        let started = Instant::now();
        let mut result = engine.process(&data, &name);
        // 감사 기록에 실패하면 결과물을 저장하지 않는다 (fail-closed)
        let mut audit_failed = false;
        if auditor.is_enabled() {
            if let Err(e) = auditor.record(
                &result,
                &data,
                &path.display().to_string(),
                &engine.policy,
                started.elapsed(),
            ) {
                eprintln!(
                    "감사 기록 실패 - 결과물을 저장하지 않음: {} ({e})",
                    path.display()
                );
                audit_failed = true;
            }
        }
        if let (false, Some((dir, overwrite)), Some(out), Some(out_name)) = (
            audit_failed,
            output,
            &result.output,
            &result.output_filename,
        ) {
            if result.status != Status::Blocked {
                match batch::write_atomic(dir, out_name, out, overwrite, &write_lock) {
                    Ok(p) => {
                        result.output_filename =
                            p.file_name().map(|n| n.to_string_lossy().to_string())
                    }
                    Err(e) => eprintln!("쓰기 실패: {} ({e})", dir.join(out_name).display()),
                }
            }
        }
        result.output = None; // 메모리 해제
        let line = format_result(&name, &result, verbose);
        let _g = print_lock.lock().unwrap_or_else(|e| e.into_inner());
        println!("{line}");
        Some(Outcome {
            result,
            audit_failed,
        })
    });
    let outcomes: Vec<Outcome> = outcomes.into_iter().flatten().collect();

    if let Some(report) = &common.report {
        let results: Vec<&CdrResult> = outcomes.iter().map(|o| &o.result).collect();
        match serde_json::to_string_pretty(&results) {
            Ok(json) => {
                if let Err(e) = fs::write(report, json) {
                    eprintln!("보고서 저장 실패: {e}");
                }
            }
            Err(e) => eprintln!("보고서 직렬화 실패: {e}"),
        }
    }

    let total = outcomes.len();
    let blocked = outcomes
        .iter()
        .filter(|o| o.result.status == Status::Blocked)
        .count();
    let sanitized = outcomes
        .iter()
        .filter(|o| o.result.status == Status::Sanitized)
        .count();
    println!(
        "\n총 {total}건: 정상 {}, 재조합 {sanitized}, 차단 {blocked}",
        total - sanitized - blocked
    );
    if outcomes.iter().any(|o| o.audit_failed) {
        ExitCode::from(3)
    } else if blocked > 0 {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

/// Ctrl+C / SIGTERM 을 받으면 true 가 되는 플래그
fn stop_flag() -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    let f = flag.clone();
    std::thread::spawn(move || {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return;
        };
        rt.block_on(async {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                if let Ok(mut term) = signal(SignalKind::terminate()) {
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {}
                        _ = term.recv() => {}
                    }
                    return;
                }
            }
            let _ = tokio::signal::ctrl_c().await;
        });
        f.store(true, Ordering::SeqCst);
    });
    flag
}

#[allow(clippy::too_many_arguments)]
fn watch(
    inbox: &Path,
    outbox: &Path,
    blocked: Option<&Path>,
    interval: u64,
    settle: u64,
    once: bool,
    common: &Common,
) -> ExitCode {
    let (policy, auditor) = match (common.policy(), common.auditor()) {
        (Ok(p), Ok(a)) => (p, a),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    if common.quarantine.is_none() {
        eprintln!(
            "주의: --quarantine 이 없으면 처리한 원본은 보관되지 않고 수신 폴더에서 삭제됩니다."
        );
    }
    let engine = Engine::new(policy);
    let cfg = WatchConfig {
        inbox: inbox.to_path_buf(),
        outbox: outbox.to_path_buf(),
        blocked: blocked.map(Path::to_path_buf),
        interval: Duration::from_secs(interval.max(1)),
        settle: Duration::from_secs(settle),
        jobs: common.jobs(),
        once,
    };
    let mut watcher = match Watcher::new(cfg, &engine, &auditor) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("감시 폴더 준비 실패: {e}");
            return ExitCode::from(1);
        }
    };
    if !once {
        eprintln!(
            "감시 시작: {} → {} (Ctrl+C 로 종료)",
            inbox.display(),
            outbox.display()
        );
    }
    let verbose = common.verbose;
    let failures = std::sync::atomic::AtomicUsize::new(0);
    let print_lock = Mutex::new(());
    let on_event = |ev: Event| {
        let line = match ev {
            Event::Processed { rel, result, .. } => {
                format_result(&rel.display().to_string(), result, verbose)
            }
            Event::Failed { rel, error } => {
                failures.fetch_add(1, Ordering::Relaxed);
                format!("[실패] {} ({error}) - 수신 폴더에 남겨 둠", rel.display())
            }
            Event::Cycle { .. } => return,
        };
        let _g = print_lock.lock().unwrap_or_else(|e| e.into_inner());
        println!("{line}");
    };
    let stop = stop_flag();
    watcher.run(&on_event, &|| stop.load(Ordering::SeqCst));
    if failures.load(Ordering::Relaxed) > 0 {
        ExitCode::from(3)
    } else {
        ExitCode::SUCCESS
    }
}

fn serve(bind: std::net::SocketAddr, timeout: u64, allow_relax: bool, common: &Common) -> ExitCode {
    let (policy, auditor) = match (common.policy(), common.auditor()) {
        (Ok(p), Ok(a)) => (p, a),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let state = cdr::server::AppState::new(policy, common.jobs(), Duration::from_secs(timeout))
        .with_auditor(auditor)
        .with_request_relaxation(allow_relax);
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("런타임 생성 실패: {e}");
            return ExitCode::from(1);
        }
    };
    match rt.block_on(cdr::server::serve(bind, state)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("서버 오류: {e}");
            ExitCode::from(1)
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match &cli.command {
        Command::Sanitize {
            inputs,
            output,
            overwrite,
            common,
        } => run(inputs, common, Some((output, *overwrite))),
        Command::Scan { inputs, common } => run(inputs, common, None),
        Command::Watch {
            inbox,
            outbox,
            blocked,
            interval,
            settle,
            once,
            common,
        } => watch(
            inbox,
            outbox,
            blocked.as_deref(),
            *interval,
            *settle,
            *once,
            common,
        ),
        Command::Serve {
            bind,
            timeout,
            allow_request_relax,
            common,
        } => serve(*bind, *timeout, *allow_request_relax, common),
        Command::Policy => {
            print!("{}", cdr::config::default_toml());
            ExitCode::SUCCESS
        }
    }
}
