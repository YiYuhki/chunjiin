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

use axum::extract::{ConnectInfo, DefaultBodyLimit, Multipart, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use tokio::sync::Semaphore;

use crate::audit::Auditor;
use crate::report::{CdrResult, Status};
use crate::{Engine, Policy};

#[derive(Clone)]
pub struct AppState {
    policy: Arc<Policy>,
    /// CPU 집약 작업 동시 실행 수 제한 (자원 고갈 방지)
    permits: Arc<Semaphore>,
    /// 동시에 메모리에 올려 둘 수 있는 업로드 수 제한
    uploads: Arc<Semaphore>,
    timeout: Duration,
    auditor: Arc<Auditor>,
    /// 요청 파라미터로 정책을 완화(래스터화 해제, 링크 유지, 메타데이터 유지, OLE 대체)할 수 있는지
    allow_relax: bool,
}

impl AppState {
    pub fn new(policy: Policy, concurrency: usize, timeout: Duration) -> Self {
        AppState {
            policy: Arc::new(policy),
            permits: Arc::new(Semaphore::new(concurrency.max(1))),
            uploads: Arc::new(Semaphore::new(concurrency.max(1) * 2)),
            timeout,
            auditor: Arc::new(Auditor::disabled()),
            allow_relax: false,
        }
    }

    /// 요청 파라미터로 운영 정책을 완화하는 것을 허용한다(기본: 강화만 허용).
    pub fn with_request_relaxation(mut self, allow: bool) -> Self {
        self.allow_relax = allow;
        self
    }

    /// 감사 로그/격리 보관을 켠다. 기록에 실패한 요청은 결과를 내주지 않는다(fail-closed).
    pub fn with_auditor(mut self, auditor: Auditor) -> Self {
        self.auditor = Arc::new(auditor);
        self
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
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

fn error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

/// 오류 응답을 상자에 담는다 (Result 의 Err 크기를 줄이기 위함)
fn fail(status: StatusCode, msg: impl Into<String>) -> Box<Response> {
    Box::new(error(status, msg))
}

/// 업로드를 받아 재조합한다. 실패 시 HTTP 오류 응답을 돌려준다.
async fn run(
    state: &AppState,
    opts: &Options,
    source: String,
    multipart: Multipart,
) -> Result<(CdrResult, Option<String>), Box<Response>> {
    // 업로드를 메모리에 올리기 전에 자리를 확보하고, 수신 자체에도 시간 제한을 둔다
    let Ok(_upload) = state.uploads.clone().acquire_owned().await else {
        return Err(fail(StatusCode::SERVICE_UNAVAILABLE, "서버 종료 중"));
    };
    let (name, data) = match tokio::time::timeout(state.timeout, read_upload(multipart)).await {
        Ok(r) => r?,
        Err(_) => return Err(fail(StatusCode::REQUEST_TIMEOUT, "업로드 수신 시간 초과")),
    };
    let policy = effective_policy(&state.policy, opts, state.allow_relax);

    // 처리 허가는 작업 스레드가 끝날 때까지 쥐고 있어야 한다. 시간 초과로 응답이 먼저 나가도
    // 작업은 계속 돌기 때문에, 허가를 여기서 놓으면 동시 처리 한도가 무너진다.
    let Ok(permit) = state.permits.clone().acquire_owned().await else {
        return Err(fail(StatusCode::SERVICE_UNAVAILABLE, "서버 종료 중"));
    };
    drop(_upload);
    let auditor = state.auditor.clone();
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let started = std::time::Instant::now();
        let r = Engine::new(policy.clone()).process(&data, &name);
        let audit = auditor
            .is_enabled()
            .then(|| auditor.record(&r, &data, &source, &policy, started.elapsed()));
        (r, audit)
    });
    match tokio::time::timeout(state.timeout, task).await {
        Ok(Ok((r, None))) => Ok((r, None)),
        Ok(Ok((r, Some(Ok(rec))))) => Ok((r, Some(rec.event_id))),
        Ok(Ok((_, Some(Err(e))))) => Err(fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("감사 기록 실패로 결과를 제공하지 않습니다: {e}"),
        )),
        Ok(Err(_)) => Err(fail(StatusCode::INTERNAL_SERVER_ERROR, "처리 중 내부 오류")),
        Err(_) => Err(fail(StatusCode::SERVICE_UNAVAILABLE, "처리 시간 초과")),
    }
}

/// 요청 파라미터를 반영한 정책. 완화가 허용되지 않으면 더 엄격해지는 방향만 받아들인다.
fn effective_policy(base: &Policy, opts: &Options, allow_relax: bool) -> Policy {
    let mut policy = base.clone();
    if let Some(v) = opts.dpi {
        policy.raster_dpi = v.clamp(36.0, 300.0);
    }
    let apply = |current: bool, requested: Option<bool>, stricter: bool| match requested {
        Some(v) if allow_relax || v == stricter => v,
        _ => current,
    };
    policy.pdf_rasterize = apply(policy.pdf_rasterize, opts.rasterize, true);
    policy.remove_hyperlinks = apply(policy.remove_hyperlinks, opts.remove_links, true);
    policy.strip_metadata = apply(policy.strip_metadata, opts.keep_metadata.map(|k| !k), true);
    policy.neutralize_embedded_ole =
        apply(policy.neutralize_embedded_ole, opts.neutralize_ole, false);
    policy
}

async fn read_upload(mut multipart: Multipart) -> Result<(String, Vec<u8>), Box<Response>> {
    let mut file: Option<(String, Vec<u8>)> = None;
    loop {
        match multipart.next_field().await {
            Ok(Some(field)) if field.name() == Some("file") => {
                let name = field.file_name().unwrap_or("unnamed").to_string();
                match field.bytes().await {
                    Ok(b) => file = Some((name, b.to_vec())),
                    Err(e) => {
                        return Err(fail(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            format!("업로드 읽기 실패: {e}"),
                        ))
                    }
                }
            }
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(e) => {
                return Err(fail(
                    StatusCode::BAD_REQUEST,
                    format!("multipart 해석 실패: {e}"),
                ))
            }
        }
    }
    file.ok_or_else(|| fail(StatusCode::BAD_REQUEST, "'file' 필드가 없습니다"))
}

type Peer = Option<Extension<ConnectInfo<SocketAddr>>>;

fn source_of(peer: &Peer) -> String {
    peer.as_ref()
        .map(|Extension(ConnectInfo(a))| a.ip().to_string())
        .unwrap_or_else(|| "api".into())
}

fn with_event_id(mut resp: Response, event_id: Option<String>) -> Response {
    if let Some(v) = event_id.and_then(|id| HeaderValue::from_str(&id).ok()) {
        resp.headers_mut().insert("x-cdr-event-id", v);
    }
    resp
}

async fn scan(
    State(state): State<AppState>,
    Query(opts): Query<Options>,
    peer: Peer,
    multipart: Multipart,
) -> Response {
    match run(&state, &opts, source_of(&peer), multipart).await {
        Ok((r, id)) => with_event_id(Json(r).into_response(), id),
        Err(resp) => *resp,
    }
}

async fn sanitize(
    State(state): State<AppState>,
    Query(opts): Query<Options>,
    peer: Peer,
    multipart: Multipart,
) -> Response {
    let (mut r, event_id) = match run(&state, &opts, source_of(&peer), multipart).await {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    if r.status == Status::Blocked {
        return with_event_id(
            (StatusCode::UNPROCESSABLE_ENTITY, Json(r)).into_response(),
            event_id,
        );
    }
    let event_header = event_id.and_then(|id| HeaderValue::from_str(&id).ok());
    let body = r.output.take().unwrap_or_default();
    let name = r
        .output_filename
        .clone()
        .unwrap_or_else(|| "sanitized".into());

    let mut headers = HeaderMap::new();
    if let Some(v) = event_header {
        headers.insert("x-cdr-event-id", v);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(q: &str) -> Options {
        let mut o = Options::default();
        for kv in q.split('&').filter(|s| !s.is_empty()) {
            let (k, v) = kv.split_once('=').unwrap();
            let b = Some(v == "true");
            match k {
                "rasterize" => o.rasterize = b,
                "remove_links" => o.remove_links = b,
                "keep_metadata" => o.keep_metadata = b,
                "neutralize_ole" => o.neutralize_ole = b,
                _ => {}
            }
        }
        o
    }

    #[test]
    fn requests_can_only_tighten_by_default() {
        let base = Policy {
            pdf_rasterize: true,
            ..Policy::default()
        };
        let p = effective_policy(
            &base,
            &opts("rasterize=false&keep_metadata=true&neutralize_ole=true&remove_links=true"),
            false,
        );
        assert!(
            p.pdf_rasterize,
            "운영자가 켠 래스터화를 요청으로 끌 수 없음"
        );
        assert!(p.strip_metadata, "메타데이터 유지 요청 무시");
        assert!(!p.neutralize_embedded_ole, "OLE 대체(차단 완화) 요청 무시");
        assert!(p.remove_hyperlinks, "링크 제거(강화) 요청은 반영");

        let p = effective_policy(
            &base,
            &opts("rasterize=false&keep_metadata=true&neutralize_ole=true"),
            true,
        );
        assert!(
            !p.pdf_rasterize && !p.strip_metadata && p.neutralize_embedded_ole,
            "완화 허용 시 반영"
        );
    }
}
