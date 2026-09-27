mod common;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use cdr::server::{router, AppState};
use cdr::Policy;
use http_body_util::BodyExt;
use tower::ServiceExt;

fn app() -> axum::Router {
    router(AppState::new(Policy::default(), 2, Duration::from_secs(60)))
}

fn multipart(filename: &str, data: &[u8]) -> (String, Vec<u8>) {
    let boundary = "----cdrtestboundary";
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes());
    body.extend_from_slice(data);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), body)
}

async fn post(
    uri: &str,
    filename: &str,
    data: &[u8],
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let (ct, body) = multipart(filename, data);
    let req = Request::post(uri)
        .header("content-type", ct)
        .body(Body::from(body))
        .unwrap();
    let res = app().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = res.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, headers, bytes)
}

#[tokio::test]
async fn health_and_index() {
    let res = app()
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let res = app()
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let html = res.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&html).contains("CDR"));
}

#[tokio::test]
async fn sanitize_returns_reassembled_file() {
    let (status, headers, body) =
        post("/api/v1/sanitize", "보고서.docm", &common::malicious_docm()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["x-cdr-status"], "sanitized");
    assert_eq!(headers["x-cdr-max-severity"], "critical");
    let cd = headers["content-disposition"].to_str().unwrap();
    assert!(
        cd.contains("filename*=UTF-8''%EB%B3%B4%EA%B3%A0%EC%84%9C.docx"),
        "{cd}"
    );
    assert!(body.starts_with(b"PK"));
    let parts = common::unzip(&body);
    assert!(!parts.iter().any(|(n, _)| n.contains("vbaProject")));
}

#[tokio::test]
async fn sanitize_blocked_returns_422_report() {
    let (status, _, body) = post("/api/v1/sanitize", "setup.exe", b"MZ\x90\x00\x03\x00").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "blocked");
}

#[tokio::test]
async fn scan_returns_json_report() {
    let (status, _, body) = post("/api/v1/scan", "a.pdf", &common::malicious_pdf()).await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "sanitized");
    assert_eq!(v["max_severity"], "critical");
    assert!(v.get("output").is_none());
}

#[tokio::test]
async fn rasterize_option_per_request() {
    let (status, _, body) = post(
        "/api/v1/scan?rasterize=true&dpi=72",
        "a.pdf",
        &common::clean_pdf(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["stats"]["pages_rasterized"], 1);
}

#[tokio::test]
async fn missing_file_field_is_400() {
    let req = Request::post("/api/v1/scan")
        .header("content-type", "multipart/form-data; boundary=x")
        .body(Body::from("--x--\r\n"))
        .unwrap();
    let res = app().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}
