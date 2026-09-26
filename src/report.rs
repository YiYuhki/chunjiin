//! 처리 결과와 탐지 항목.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// 위협 요소 없음 - 재조합된 파일 제공
    Clean,
    /// 위협 요소를 배제하고 재조합한 파일 제공
    Sanitized,
    /// 재조합 불가 - 차단
    Blocked,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub category: String,
    pub severity: Severity,
    pub description: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub location: String,
}

/// 재조합 과정에서 발생한 탐지 항목과 통계를 모은다.
#[derive(Debug, Default)]
pub struct Findings {
    pub items: Vec<Finding>,
    pub stats: BTreeMap<String, u64>,
}

impl Findings {
    pub fn add(
        &mut self,
        category: &str,
        severity: Severity,
        description: impl Into<String>,
        location: impl Into<String>,
    ) {
        self.items.push(Finding {
            category: category.to_string(),
            severity,
            description: description.into(),
            location: location.into(),
        });
    }

    pub fn count(&mut self, key: &str, n: u64) {
        *self.stats.entry(key.to_string()).or_default() += n;
    }

    pub fn max_severity(&self) -> Option<Severity> {
        self.items.iter().map(|f| f.severity).max()
    }
}

#[derive(Debug, Serialize)]
pub struct CdrResult {
    pub filename: String,
    pub detected_type: String,
    pub status: Status,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reason: String,
    pub output_filename: Option<String>,
    pub input_sha256: String,
    pub output_sha256: Option<String>,
    pub input_size: usize,
    pub output_size: usize,
    pub max_severity: Option<Severity>,
    pub findings: Vec<Finding>,
    pub stats: BTreeMap<String, u64>,
    #[serde(skip)]
    pub output: Option<Vec<u8>>,
}

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}
