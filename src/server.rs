//! CDR REST API 서버 (axum).
//!
//! | 메서드 | 경로 | 설명 |
//! |---|---|---|
//! | POST | `/api/v1/sanitize` | multipart `file` → 재조합된 파일 (차단 시 422 + JSON 보고서) |
//! | POST | `/api/v1/scan` | multipart `file` → JSON 보고서 |
//! | GET | `/health` | 상태 확인 |
//! | GET | `/` | 브라우저 업로드 페이지 |
//!
//! 요청별 정책 조정: `?rasterize=true&dpi=150&remove_links=true&keep_metadata=true`

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Multipart, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use tokio::sync::Semaphore;

use crate::report::{CdrResult, Status};
use crate::{Engine, Policy};

#[derive(Clone)]
pub struct AppState {
    policy: Arc<Policy>,
    /// CPU 집약 작업 동시 실행 수 제한 (자원 고갈 방지)
    permits: Arc<Semaphore>,
    timeout: Duration,
}

impl AppState {
    pub fn new(policy: Policy, concurrency: usize, timeout: Duration) -> Self {
        AppState {
            policy: Arc::new(policy),
            permits: Arc::new(Semaphore::new(concurrency.max(1))),
            timeout,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct Options {
    rasterize: Option<bool>,
    dpi: Option<f32>,
    remove_links: Option<bool>,
    keep_metadata: Option<bool>,
    neutralize_ole: Option<bool>,
}

pub fn router(state: AppState) -> Router {
    let limit = state.policy.max_file_size + 1024 * 1024;
    Router::new()
        .route("/", get(index))
        .route(
            "/health",
            get(|| async {
                Json(serde_json::json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
            }),
        )
        .route("/api/v1/sanitize", post(sanitize))
        .route("/api/v1/scan", post(scan))
        .layer(DefaultBodyLimit::max(limit))
        .with_state(state)
}

pub async fn serve(addr: SocketAddr, state: AppState) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("CDR API 서버 시작: http://{addr}");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
}

fn error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

/// 업로드를 받아 재조합한다. 실패 시 HTTP 오류 응답을 돌려준다.
async fn run(
    state: &AppState,
    opts: &Options,
    mut multipart: Multipart,
) -> Result<CdrResult, Response> {
    let mut file: Option<(String, Vec<u8>)> = None;
    loop {
        match multipart.next_field().await {
            Ok(Some(field)) if field.name() == Some("file") => {
                let name = field.file_name().unwrap_or("unnamed").to_string();
                match field.bytes().await {
                    Ok(b) => file = Some((name, b.to_vec())),
                    Err(e) => {
                        return Err(error(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            format!("업로드 읽기 실패: {e}"),
                        ))
                    }
                }
            }
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(e) => {
                return Err(error(
                    StatusCode::BAD_REQUEST,
                    format!("multipart 해석 실패: {e}"),
                ))
            }
        }
    }
    let Some((name, data)) = file else {
        return Err(error(StatusCode::BAD_REQUEST, "'file' 필드가 없습니다"));
    };

    let mut policy = (*state.policy).clone();
    if let Some(v) = opts.rasterize {
        policy.pdf_rasterize = v;
    }
    if let Some(v) = opts.dpi {
        policy.raster_dpi = v.clamp(36.0, 300.0);
    }
    if let Some(v) = opts.remove_links {
        policy.remove_hyperlinks = v;
    }
    if let Some(v) = opts.keep_metadata {
        policy.strip_metadata = !v;
    }
    if let Some(v) = opts.neutralize_ole {
        policy.neutralize_embedded_ole = v;
    }

    let Ok(_permit) = state.permits.clone().acquire_owned().await else {
        return Err(error(StatusCode::SERVICE_UNAVAILABLE, "서버 종료 중"));
    };
    let task = tokio::task::spawn_blocking(move || Engine::new(policy).process(&data, &name));
    match tokio::time::timeout(state.timeout, task).await {
        Ok(Ok(r)) => Ok(r),
        Ok(Err(_)) => Err(error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "처리 중 내부 오류",
        )),
        Err(_) => Err(error(StatusCode::SERVICE_UNAVAILABLE, "처리 시간 초과")),
    }
}

async fn scan(
    State(state): State<AppState>,
    Query(opts): Query<Options>,
    multipart: Multipart,
) -> Response {
    match run(&state, &opts, multipart).await {
        Ok(r) => Json(r).into_response(),
        Err(resp) => resp,
    }
}

async fn sanitize(
    State(state): State<AppState>,
    Query(opts): Query<Options>,
    multipart: Multipart,
) -> Response {
    let mut r = match run(&state, &opts, multipart).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if r.status == Status::Blocked {
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(r)).into_response();
    }
    let body = r.output.take().unwrap_or_default();
    let name = r
        .output_filename
        .clone()
        .unwrap_or_else(|| "sanitized".into());

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    let ascii: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    let disposition = format!(
        "attachment; filename=\"{ascii}\"; filename*=UTF-8''{}",
        percent_encode(&name)
    );
    if let Ok(v) = HeaderValue::from_str(&disposition) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    let status = match r.status {
        Status::Clean => "clean",
        Status::Sanitized => "sanitized",
        Status::Blocked => "blocked",
    };
    headers.insert("x-cdr-status", HeaderValue::from_static(status));
    let extra = [
        ("x-cdr-detected-type", r.detected_type.clone()),
        ("x-cdr-findings", r.findings.len().to_string()),
        (
            "x-cdr-max-severity",
            r.max_severity
                .map(|s| format!("{s:?}").to_lowercase())
                .unwrap_or_else(|| "none".into()),
        ),
        (
            "x-cdr-output-sha256",
            r.output_sha256.clone().unwrap_or_default(),
        ),
    ];
    for (k, v) in extra {
        if let Ok(v) = HeaderValue::from_str(&v) {
            headers.insert(k, v);
        }
    }
    (StatusCode::OK, headers, body).into_response()
}

fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

const INDEX_HTML: &str = r#"<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CDR 문서 재조합</title>
<style>
body{font-family:system-ui,sans-serif;max-width:760px;margin:40px auto;padding:0 16px;color:#1f2328}
h1{font-size:1.4rem}.box{border:1px solid #d0d7de;border-radius:8px;padding:20px}
button{padding:8px 16px;margin:8px 8px 0 0;cursor:pointer}label{margin-right:16px}
pre{background:#f6f8fa;padding:12px;overflow:auto;font-size:.85rem;white-space:pre-wrap}
</style></head><body>
<h1>CDR 문서 재조합</h1>
<p>오피스(docx/xlsx/pptx, doc/xls/ppt)·한글(hwpx, hwp)·PDF 문서에서 허용된 콘텐츠만 꺼내 새 문서로 다시 조립합니다.</p>
<div class="box">
<input type="file" id="f"><br><br>
<label><input type="checkbox" id="raster"> PDF 이미지화(최고 보안)</label>
<label><input type="checkbox" id="links"> 하이퍼링크 제거</label><br>
<button onclick="run('scan')">분석</button><button onclick="run('sanitize')">재조합 후 다운로드</button>
</div>
<pre id="out"></pre>
<script>
async function run(kind){
  const f=document.getElementById('f').files[0]; if(!f) return;
  const fd=new FormData(); fd.append('file',f);
  const q=new URLSearchParams({rasterize:document.getElementById('raster').checked,remove_links:document.getElementById('links').checked});
  const out=document.getElementById('out'); out.textContent='처리 중...';
  const r=await fetch('/api/v1/'+kind+'?'+q,{method:'POST',body:fd});
  const ct=r.headers.get('content-type')||'';
  if(ct.includes('json')){out.textContent=JSON.stringify(await r.json(),null,2);return;}
  const blob=await r.blob(); const cd=r.headers.get('content-disposition')||'';
  const m=cd.match(/filename\*=UTF-8''([^;]+)/); const name=m?decodeURIComponent(m[1]):'sanitized';
  const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=name; a.click();
  out.textContent='상태: '+r.headers.get('x-cdr-status')+' / 탐지: '+r.headers.get('x-cdr-findings')+'건 → '+name;
}
</script></body></html>"#;
