//! 처리 오류. 재조합이 불가능한 입력은 모두 `Blocked` 로 귀결된다(fail-closed).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CdrError {
    #[error("{reason}")]
    Blocked {
        category: &'static str,
        reason: String,
    },
}

impl CdrError {
    pub fn category(&self) -> &'static str {
        match self {
            CdrError::Blocked { category, .. } => category,
        }
    }
}

pub type Result<T> = std::result::Result<T, CdrError>;

pub fn blocked<T>(category: &'static str, reason: impl Into<String>) -> Result<T> {
    Err(CdrError::Blocked {
        category,
        reason: reason.into(),
    })
}
