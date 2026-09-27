//! CDR (Content Disarm & Reconstruction) - 오피스/한글/PDF 문서 재조합 엔진.
//!
//! 원본 문서를 "고치는" 대신, 원본에서 허용된 콘텐츠만 추출해 **새 문서를 조립**한다.
//! 허용 목록에 없는 요소(매크로, 스크립트, 임베디드 개체, 외부 참조 등)는
//! 새 문서에 애초에 존재하지 않는다.

pub mod archive;
pub mod audit;
pub mod batch;
pub mod config;
pub mod detect;
pub mod engine;
pub mod error;
pub mod hwpx;
pub mod imaging;
pub mod legacy;
pub mod mail;
pub mod metafile;
pub mod msg;
pub mod ooxml;
pub mod pdf;
pub mod policy;
pub mod report;
pub mod rtf;
pub mod server;
pub mod svg;
pub mod text;
pub mod watch;
pub mod xml;
pub mod zipsafe;

pub use engine::Engine;
pub use policy::Policy;
pub use report::{CdrResult, Finding, Severity, Status};
