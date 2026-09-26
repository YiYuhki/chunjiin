//! CDR 엔진: 형식 판별 → 재조합 → 재검증 → 결과 보고.

use crate::detect::{self, FileType, OLE_MAGIC};
use crate::error::{CdrError, Result};
use crate::imaging::{self, ImageKind};
use crate::policy::Policy;
use crate::report::{sha256_hex, CdrResult, Findings, Severity, Status};
use crate::{archive, hwpx, legacy, ooxml, pdf, rtf, text};

#[derive(Default)]
pub struct Engine {
    pub policy: Policy,
    /// 압축 파일 중첩 깊이 (최상위 0)
    depth: usize,
}

impl Engine {
    pub fn new(policy: Policy) -> Self {
        Engine { policy, depth: 0 }
    }

    /// 압축 파일 안의 항목을 처리하는 엔진
    pub(crate) fn nested(policy: Policy, depth: usize) -> Self {
        Engine { policy, depth }
    }

    pub fn process(&self, data: &[u8], filename: &str) -> CdrResult {
        let mut findings = Findings::default();
        let ftype = detect::detect_named(data, filename, self.policy.allow_text);
        let mut result = CdrResult {
            filename: filename.to_string(),
            detected_type: ftype.name().to_string(),
            status: Status::Blocked,
            reason: String::new(),
            output_filename: None,
            input_sha256: sha256_hex(data),
            output_sha256: None,
            input_size: data.len(),
            output_size: 0,
            max_severity: None,
            findings: Vec::new(),
            stats: Default::default(),
            output: None,
        };

        if data.len() > self.policy.max_file_size {
            return finish_blocked(
                result,
                findings,
                "size",
                format!("파일 크기 제한 초과 ({} bytes)", data.len()),
            );
        }

        let ext = detect::extension_of(filename);
        if !ext.is_empty() && !ftype.accepts_extension(&ext) && ftype != FileType::Unknown {
            findings.add(
                "type-mismatch",
                Severity::Medium,
                format!(
                    "확장자(.{ext})와 실제 형식({}) 불일치 - 실제 형식으로 재조합",
                    ftype.name()
                ),
                filename,
            );
        }

        // 패닉까지 포함해 모든 실패를 차단으로 처리한다(fail-closed)
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut f = Findings::default();
            let r = self.reassemble(data, ftype, &mut f);
            (r, f)
        }));
        let (output, inner) = match outcome {
            Ok((r, f)) => (r, f),
            Err(_) => {
                return finish_blocked(
                    result,
                    findings,
                    "internal",
                    "재조합 중 내부 오류".to_string(),
                );
            }
        };
        findings.items.extend(inner.items);
        for (k, v) in inner.stats {
            findings.count(&k, v);
        }
        let output = match output {
            Ok(o) => o,
            Err(e) => {
                let cat = e.category();
                return finish_blocked(result, findings, cat, e.to_string());
            }
        };

        // 재검증: 재조합 결과를 다시 재조합했을 때 MEDIUM 이상 탐지가 없어야 한다
        if let Some(residual) = self.verify(&output, ftype) {
            return finish_blocked(
                result,
                findings,
                "verify",
                format!("재검증 실패 - {residual}"),
            );
        }

        result.output_filename = Some(match ftype {
            // 텍스트는 원래 이름(허용된 확장자)을 그대로 쓴다
            FileType::Text | FileType::Csv | FileType::Tsv => {
                output_name(filename, FileType::Unknown) + "." + &detect::extension_of(filename)
            }
            _ => output_name(filename, ftype),
        });
        result.output_sha256 = Some(sha256_hex(&output));
        result.output_size = output.len();
        result.output = Some(output);
        result.status = if findings.items.iter().any(|f| f.severity >= Severity::Low) {
            Status::Sanitized
        } else {
            Status::Clean
        };
        result.max_severity = findings.max_severity();
        result.findings = findings.items;
        result.stats = findings.stats;
        result
    }

    fn reassemble(&self, data: &[u8], ftype: FileType, findings: &mut Findings) -> Result<Vec<u8>> {
        match ftype {
            FileType::Pdf => pdf::reassemble(data, &self.policy, findings),
            FileType::Docx | FileType::Xlsx | FileType::Pptx => {
                ooxml::reassemble(data, ftype, &self.policy, findings)
            }
            FileType::Hwpx => hwpx::reassemble(data, &self.policy, findings),
            FileType::Hwp => legacy::hwp::reassemble(data, &self.policy, findings),
            FileType::Doc => legacy::doc::reassemble(data, &self.policy, findings),
            FileType::Xls => legacy::xls::reassemble(data, &self.policy, findings),
            FileType::Ppt => legacy::ppt::reassemble(data, &self.policy, findings),
            FileType::Ole => Err(CdrError::Blocked {
                category: "legacy-format",
                reason: ole_reason(data),
            }),
            FileType::Zip => archive::reassemble(self, self.depth, data, findings),
            FileType::Rtf => rtf::reassemble(data, &self.policy, findings),
            FileType::Png | FileType::Jpeg | FileType::Gif | FileType::Bmp => {
                if !self.policy.allow_images {
                    return Err(CdrError::Blocked {
                        category: "unsupported",
                        reason: "단독 이미지 파일 처리가 비활성화되어 있음".into(),
                    });
                }
                let kind = match ftype {
                    FileType::Png => ImageKind::Png,
                    FileType::Jpeg => ImageKind::Jpeg,
                    FileType::Gif => ImageKind::Gif,
                    _ => ImageKind::Bmp,
                };
                let (bytes, _) = imaging::reencode(data, kind, &self.policy)?;
                findings.count("images_reencoded", 1);
                Ok(bytes)
            }
            FileType::Text => text::reassemble(data, text::Kind::Text, findings),
            FileType::Csv => text::reassemble(data, text::Kind::Delimited(','), findings),
            FileType::Tsv => text::reassemble(data, text::Kind::Delimited('\t'), findings),
            FileType::Unknown => {
                let reason = if data.starts_with(b"MZ") || data.starts_with(b"\x7fELF") {
                    "실행 파일은 허용되지 않음"
                } else {
                    "지원하지 않는 파일 형식 (오피스·한글·PDF·RTF·이미지·ZIP·텍스트 만 지원)"
                };
                Err(CdrError::Blocked {
                    category: "unsupported",
                    reason: reason.into(),
                })
            }
        }
    }

    fn verify(&self, output: &[u8], ftype: FileType) -> Option<String> {
        // 텍스트는 내용만으로 판별되지 않으므로 같은 형식으로 다시 해석한다
        let out_type = match ftype {
            FileType::Text | FileType::Csv | FileType::Tsv => ftype,
            _ => detect::detect(output),
        };
        if out_type != ftype.output_type() {
            return Some(format!("재조합 결과 형식 불일치({})", out_type.name()));
        }
        // 재검증은 구조 재조합만 수행한다(래스터화 결과를 다시 렌더링할 필요는 없음)
        let verifier = Engine::nested(
            Policy {
                pdf_rasterize: false,
                media_passthrough: true,
                ..self.policy.clone()
            },
            self.depth,
        );
        let mut f = Findings::default();
        if let Err(e) = verifier.reassemble(output, out_type, &mut f) {
            return Some(e.to_string());
        }
        let residual: Vec<String> = f
            .items
            .iter()
            .filter(|x| x.severity >= Severity::Medium)
            .take(5)
            .map(|x| format!("{}: {}", x.category, x.description))
            .collect();
        if residual.is_empty() {
            None
        } else {
            Some(residual.join("; "))
        }
    }
}

fn ole_reason(data: &[u8]) -> String {
    debug_assert!(data.starts_with(OLE_MAGIC));
    let utf16 = |s: &str| {
        s.encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<u8>>()
    };
    if detect::find(data, &utf16("EncryptedPackage")).is_some() {
        "암호화된 Office 문서는 검사할 수 없어 차단합니다".into()
    } else {
        "지원하지 않는 OLE 복합 문서(Outlook 메시지 등)라 차단합니다".into()
    }
}

fn finish_blocked(
    mut result: CdrResult,
    mut findings: Findings,
    category: &str,
    reason: String,
) -> CdrResult {
    findings.add(category, Severity::High, reason.clone(), "");
    result.status = Status::Blocked;
    result.reason = reason;
    result.max_severity = findings.max_severity();
    result.findings = findings.items;
    result.stats = findings.stats;
    result
}

pub fn output_name(filename: &str, ftype: FileType) -> String {
    let filename = text::strip_spoofing(filename);
    let base = filename
        .rsplit(['/', '\\'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("unnamed");
    let stem = match base.rsplit_once('.') {
        Some((s, _)) if !s.is_empty() => s,
        _ => base,
    };
    match ftype.output_extension() {
        Some(ext) => format!("{stem}.{ext}"),
        None => stem.to_string(),
    }
}
