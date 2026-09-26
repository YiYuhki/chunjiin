//! cdr 명령행 도구.
//!
//!   cdr sanitize 받은문서.docm -o clean/ --report report.json
//!   cdr scan 의심파일.pdf

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use cdr::{CdrResult, Engine, Policy, Status};

#[derive(Parser)]
#[command(
    name = "cdr",
    version,
    about = "CDR(Content Disarm & Reconstruction) - 오피스/PDF 문서 재조합 도구"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 문서를 재조합하여 안전한 파일로 저장
    Sanitize {
        #[command(flatten)]
        common: Common,
        /// 출력 디렉터리
        #[arg(short, long)]
        output: PathBuf,
        /// 같은 이름의 출력 파일 덮어쓰기
        #[arg(long)]
        overwrite: bool,
    },
    /// 저장 없이 분석 결과만 출력
    Scan {
        #[command(flatten)]
        common: Common,
    },
    /// REST API 서버 실행
    Serve {
        /// 바인드 주소
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: std::net::SocketAddr,
        /// 동시 처리 수 (기본: CPU 수)
        #[arg(long)]
        concurrency: Option<usize>,
        /// 요청당 처리 제한 시간(초)
        #[arg(long, default_value_t = 120)]
        timeout: u64,
        /// 최대 파일 크기(MB)
        #[arg(long, default_value_t = 100)]
        max_size: usize,
    },
}

#[derive(Args)]
struct Common {
    /// 파일 또는 디렉터리
    #[arg(required = true)]
    inputs: Vec<PathBuf>,
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
    #[arg(long, default_value_t = 150.0)]
    dpi: f32,
    /// 최대 파일 크기(MB)
    #[arg(long, default_value_t = 100)]
    max_size: usize,
    /// 탐지 항목 상세 출력
    #[arg(short, long)]
    verbose: bool,
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

fn print_result(r: &CdrResult, verbose: bool) {
    let tail = match (&r.output_filename, r.status) {
        (Some(o), _) => format!(" → {o}"),
        (None, _) => format!(" ({})", r.reason),
    };
    println!(
        "[{}] {} ({}, 탐지 {}건){}",
        label(r.status),
        r.filename,
        r.detected_type,
        r.findings.len(),
        tail
    );
    if verbose {
        for f in &r.findings {
            let loc = if f.location.is_empty() {
                String::new()
            } else {
                format!(" @ {}", f.location)
            };
            println!(
                "    - [{:?}] {}: {}{}",
                f.severity, f.category, f.description, loc
            );
        }
        if !r.stats.is_empty() {
            let s: Vec<String> = r.stats.iter().map(|(k, v)| format!("{k}={v}")).collect();
            println!("    · {}", s.join(", "));
        }
    }
}

fn run(common: &Common, output: Option<(&Path, bool)>) -> ExitCode {
    let policy = Policy {
        remove_hyperlinks: common.remove_links,
        strip_metadata: !common.keep_metadata,
        flatten_pdf_annotations: !common.no_flatten,
        pdf_rasterize: common.rasterize,
        neutralize_embedded_ole: common.neutralize_ole,
        raster_dpi: common.dpi,
        max_file_size: common.max_size * 1024 * 1024,
        ..Policy::default()
    };
    let engine = Engine::new(policy);
    let files = collect(&common.inputs);
    if files.is_empty() {
        eprintln!("처리할 파일이 없습니다.");
        return ExitCode::from(1);
    }
    if let Some((dir, _)) = output {
        if let Err(e) = fs::create_dir_all(dir) {
            eprintln!("출력 디렉터리 생성 실패: {e}");
            return ExitCode::from(1);
        }
    }

    let mut results = Vec::new();
    for path in &files {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let data = match fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("읽기 실패: {} ({e})", path.display());
                continue;
            }
        };
        let r = engine.process(&data, &name);
        if let (Some((dir, overwrite)), Some(out), Some(out_name)) =
            (output, &r.output, &r.output_filename)
        {
            let mut target = dir.join(out_name);
            let mut n = 1;
            while target.exists() && !overwrite {
                let p = Path::new(out_name);
                let stem = p
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                let ext = p
                    .extension()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                target = dir.join(format!("{stem}_{n}.{ext}"));
                n += 1;
            }
            if let Err(e) = fs::write(&target, out) {
                eprintln!("쓰기 실패: {} ({e})", target.display());
            }
        }
        print_result(&r, common.verbose || output.is_none());
        results.push(r);
    }

    if let Some(report) = &common.report {
        match serde_json::to_string_pretty(&results) {
            Ok(json) => {
                if let Err(e) = fs::write(report, json) {
                    eprintln!("보고서 저장 실패: {e}");
                }
            }
            Err(e) => eprintln!("보고서 직렬화 실패: {e}"),
        }
    }

    let total = results.len();
    let blocked = results
        .iter()
        .filter(|r| r.status == Status::Blocked)
        .count();
    let sanitized = results
        .iter()
        .filter(|r| r.status == Status::Sanitized)
        .count();
    println!(
        "\n총 {total}건: 정상 {}, 재조합 {sanitized}, 차단 {blocked}",
        total - sanitized - blocked
    );
    if blocked > 0 {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match &cli.command {
        Command::Sanitize {
            common,
            output,
            overwrite,
        } => run(common, Some((output, *overwrite))),
        Command::Scan { common } => run(common, None),
        Command::Serve {
            bind,
            concurrency,
            timeout,
            max_size,
        } => {
            let policy = Policy {
                max_file_size: max_size * 1024 * 1024,
                ..Policy::default()
            };
            let workers = concurrency.unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(2)
            });
            let state = cdr::server::AppState::new(
                policy,
                workers,
                std::time::Duration::from_secs(*timeout),
            );
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
            match rt.block_on(cdr::server::serve(*bind, state)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("서버 오류: {e}");
                    ExitCode::from(1)
                }
            }
        }
    }
}
