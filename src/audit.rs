//! 감사 로그(JSONL)와 원본 격리 보관.
//!
//! - 감사 로그: 처리한 모든 파일마다 한 줄의 JSON 을 덧붙인다(시각, 이벤트 ID, 출처,
//!   입출력 SHA-256, 상태, 탐지 분류, 적용 정책, 처리 시간).
//! - 격리 보관: 재조합되었거나 차단된 파일의 **원본**을 `<격리 폴더>/<날짜>/<SHA-256>.bin`
//!   으로 보관하고 같은 이름의 `.json` 에 보고서를 남긴다. 실행·자동 열람되지 않도록
//!   확장자를 `.bin` 으로 하고 소유자만 읽을 수 있게 한다(유닉스 0600).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::policy::Policy;
use crate::report::{CdrResult, Severity, Status};

#[derive(Debug, Clone, Default)]
pub struct AuditConfig {
    /// 감사 로그(JSONL) 경로
    pub log_path: Option<PathBuf>,
    /// 격리 보관 폴더
    pub quarantine_dir: Option<PathBuf>,
    /// 위협이 없던(clean) 파일의 원본도 보관
    pub quarantine_clean: bool,
}

#[derive(Debug, Serialize)]
pub struct PolicySummary {
    pub pdf_rasterize: bool,
    pub neutralize_embedded_ole: bool,
    pub remove_hyperlinks: bool,
    pub strip_metadata: bool,
}

#[derive(Debug, Serialize)]
pub struct AuditRecord {
    pub ts: String,
    pub event_id: String,
    pub source: String,
    pub filename: String,
    pub detected_type: String,
    pub status: Status,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reason: String,
    pub max_severity: Option<Severity>,
    pub findings: usize,
    pub categories: Vec<String>,
    pub input_sha256: String,
    pub output_sha256: Option<String>,
    pub input_size: usize,
    pub output_size: usize,
    pub output_filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantine: Option<String>,
    pub duration_ms: u128,
    pub policy: PolicySummary,
}

pub struct Auditor {
    log: Option<Mutex<File>>,
    quarantine: Option<PathBuf>,
    quarantine_clean: bool,
}

impl Auditor {
    pub fn disabled() -> Self {
        Auditor {
            log: None,
            quarantine: None,
            quarantine_clean: false,
        }
    }

    pub fn open(cfg: &AuditConfig) -> io::Result<Self> {
        let log = match &cfg.log_path {
            Some(p) => {
                if let Some(parent) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
                    fs::create_dir_all(parent)?;
                }
                Some(Mutex::new(
                    OpenOptions::new().create(true).append(true).open(p)?,
                ))
            }
            None => None,
        };
        if let Some(q) = &cfg.quarantine_dir {
            fs::create_dir_all(q)?;
            restrict_dir(q);
        }
        Ok(Auditor {
            log,
            quarantine: cfg.quarantine_dir.clone(),
            quarantine_clean: cfg.quarantine_clean,
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.log.is_some() || self.quarantine.is_some()
    }

    /// 처리 결과를 기록하고 필요하면 원본을 격리 보관한다.
    pub fn record(
        &self,
        result: &CdrResult,
        original: &[u8],
        source: &str,
        policy: &Policy,
        duration: Duration,
    ) -> io::Result<AuditRecord> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let ts = rfc3339(now);
        let event_id = {
            let mut h = Sha256::new();
            h.update(now.as_nanos().to_le_bytes());
            h.update(result.input_sha256.as_bytes());
            h.update(source.as_bytes());
            h.finalize()
                .iter()
                .take(8)
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };

        let quarantine = match &self.quarantine {
            Some(dir) if result.status != Status::Clean || self.quarantine_clean => {
                Some(self.store(dir, &ts[..10], result, original)?)
            }
            _ => None,
        };

        let mut categories: Vec<String> =
            result.findings.iter().map(|f| f.category.clone()).collect();
        categories.sort();
        categories.dedup();
        let record = AuditRecord {
            ts,
            event_id,
            source: source.to_string(),
            filename: result.filename.clone(),
            detected_type: result.detected_type.clone(),
            status: result.status,
            reason: result.reason.clone(),
            max_severity: result.max_severity,
            findings: result.findings.len(),
            categories,
            input_sha256: result.input_sha256.clone(),
            output_sha256: result.output_sha256.clone(),
            input_size: result.input_size,
            output_size: result.output_size,
            output_filename: result.output_filename.clone(),
            quarantine,
            duration_ms: duration.as_millis(),
            policy: PolicySummary {
                pdf_rasterize: policy.pdf_rasterize,
                neutralize_embedded_ole: policy.neutralize_embedded_ole,
                remove_hyperlinks: policy.remove_hyperlinks,
                strip_metadata: policy.strip_metadata,
            },
        };

        if let Some(log) = &self.log {
            let mut line = serde_json::to_vec(&record).map_err(io::Error::other)?;
            line.push(b'\n');
            let mut f = log.lock().unwrap_or_else(|e| e.into_inner());
            f.write_all(&line)?;
            f.flush()?;
        }
        Ok(record)
    }

    fn store(
        &self,
        dir: &Path,
        day: &str,
        result: &CdrResult,
        original: &[u8],
    ) -> io::Result<String> {
        let sub = dir.join(day);
        fs::create_dir_all(&sub)?;
        restrict_dir(&sub);
        let sha = &result.input_sha256;
        let bin = sub.join(format!("{sha}.bin"));
        if !bin.exists() {
            write_private(&bin, original)?;
        }
        let report = serde_json::to_vec_pretty(result).map_err(io::Error::other)?;
        write_private(&sub.join(format!("{sha}.json")), &report)?;
        Ok(format!("{day}/{sha}.bin"))
    }
}

fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut opts = OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

fn restrict_dir(_path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(_path, fs::Permissions::from_mode(0o700));
    }
}

/// UNIX 시간 → RFC 3339 (UTC, 밀리초)
fn rfc3339(since_epoch: Duration) -> String {
    let secs = since_epoch.as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Howard Hinnant 의 civil_from_days
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        since_epoch.subsec_millis()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps() {
        assert_eq!(rfc3339(Duration::from_secs(0)), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            rfc3339(Duration::from_millis(1_790_380_800_123)),
            "2026-09-26T00:00:00.123Z"
        );
        assert_eq!(
            rfc3339(Duration::from_secs(951_782_400)),
            "2000-02-29T00:00:00.000Z"
        );
    }
}
