//! 콘텐츠 스트림 연산자 허용 목록 필터와 재인코딩.

use std::collections::{HashMap, HashSet};

use lopdf::content::{Content, Operation};
use lopdf::Object;

/// PDF 32000-1 의 그리기 연산자 중 재조합에 허용하는 것
const ALLOWED_OPS: &[&str] = &[
    // 그래픽 상태
    "w", "J", "j", "M", "d", "ri", "i", "gs", "q", "Q", "cm",
    // 경로 생성/칠하기/클리핑
    "m", "l", "c", "v", "y", "h", "re", "S", "s", "f", "F", "f*", "B", "B*", "b", "b*", "n", "W",
    "W*", // 색
    "CS", "cs", "SC", "SCN", "sc", "scn", "G", "g", "RG", "rg", "K", "k",
    // 셰이딩, XObject, 인라인 이미지
    "sh", "Do", "BI", // 텍스트
    "BT", "ET", "Tc", "Tw", "Tz", "TL", "Tf", "Tr", "Ts", "Td", "TD", "Tm", "T*", "Tj", "TJ", "'",
    "\"", // Type3 글리프
    "d0", "d1", // 표시된 콘텐츠 (BDC 는 속성 없이 BMC 로 변환)
    "BMC", "BDC", "EMC",
];

/// 연산자를 허용 목록으로 거르고 q/Q, BT/ET, BMC/EMC 균형을 맞춘다.
/// `xobjects` 가 주어지면 존재하지 않는 XObject 를 그리는 `Do` 를 제거한다.
pub fn filter(
    ops: Vec<Operation>,
    xobjects: Option<&HashSet<Vec<u8>>>,
    dropped: &mut HashMap<String, u64>,
) -> Vec<Operation> {
    let mut out = Vec::with_capacity(ops.len());
    let mut q_depth = 0usize;
    let mut in_text = false;
    let mut mc_depth = 0usize;
    for mut op in ops {
        let name = op.operator.as_str();
        if !ALLOWED_OPS.contains(&name) {
            *dropped.entry(op.operator.clone()).or_default() += 1;
            continue;
        }
        match name {
            "q" => {
                if q_depth >= 256 {
                    *dropped.entry("q(depth)".into()).or_default() += 1;
                    continue;
                }
                q_depth += 1;
            }
            "Q" => {
                if q_depth == 0 {
                    continue;
                }
                q_depth -= 1;
            }
            "BT" => {
                if in_text {
                    continue;
                }
                in_text = true;
            }
            "ET" => {
                if !in_text {
                    continue;
                }
                in_text = false;
            }
            "BMC" => mc_depth += 1,
            "BDC" => {
                let tag = op
                    .operands
                    .first()
                    .cloned()
                    .unwrap_or(Object::Name(b"Span".to_vec()));
                op = Operation::new("BMC", vec![tag]);
                mc_depth += 1;
            }
            "EMC" => {
                if mc_depth == 0 {
                    continue;
                }
                mc_depth -= 1;
            }
            "Do" => {
                let ok = match (op.operands.first(), xobjects) {
                    (Some(Object::Name(n)), Some(set)) => set.contains(n),
                    (Some(Object::Name(_)), None) => true,
                    _ => false,
                };
                if !ok {
                    *dropped.entry("Do(제외된 XObject)".into()).or_default() += 1;
                    continue;
                }
            }
            // 해석 불가(필터 사용 등)한 인라인 이미지는 파서가 피연산자 없이 돌려준다
            "BI" if !matches!(op.operands.first(), Some(Object::Stream(_))) => {
                *dropped
                    .entry("BI(해석 불가 인라인 이미지)".into())
                    .or_default() += 1;
                continue;
            }
            _ => {}
        }
        if !operands_ok(&op.operands) {
            *dropped
                .entry(format!("{}(비정상 피연산자)", op.operator))
                .or_default() += 1;
            continue;
        }
        out.push(op);
    }
    if in_text {
        out.push(Operation::new("ET", vec![]));
    }
    for _ in 0..mc_depth {
        out.push(Operation::new("EMC", vec![]));
    }
    for _ in 0..q_depth {
        out.push(Operation::new("Q", vec![]));
    }
    out
}

fn operands_ok(operands: &[Object]) -> bool {
    operands.len() <= 64
        && operands.iter().all(|o| match o {
            Object::Reference(_) => false,
            Object::Real(r) => r.is_finite(),
            Object::Array(a) => a.len() <= 4096 && operands_ok_inner(a),
            _ => true,
        })
}

fn operands_ok_inner(items: &[Object]) -> bool {
    items.iter().all(|o| match o {
        Object::Reference(_) | Object::Array(_) | Object::Dictionary(_) | Object::Stream(_) => {
            false
        }
        Object::Real(r) => r.is_finite(),
        _ => true,
    })
}

/// 연산자 목록을 콘텐츠 스트림 바이트로 인코딩한다. 인라인 이미지는 BI … ID … EI 로 직접 쓴다.
pub fn encode(ops: &[Operation]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut batch: Vec<Operation> = Vec::new();
    let flush = |batch: &mut Vec<Operation>, out: &mut Vec<u8>| {
        if batch.is_empty() {
            return;
        }
        if let Ok(bytes) = (Content {
            operations: std::mem::take(batch),
        })
        .encode()
        {
            out.extend_from_slice(&bytes);
            out.push(b'\n');
        }
    };
    for op in ops {
        if op.operator == "BI" {
            flush(&mut batch, &mut out);
            if let Some(Object::Stream(s)) = op.operands.first() {
                let mut operands = Vec::new();
                for (k, v) in s.dict.iter() {
                    if matches!(
                        k.as_slice(),
                        b"Length" | b"F" | b"Filter" | b"DP" | b"DecodeParms"
                    ) {
                        continue;
                    }
                    operands.push(Object::Name(k.clone()));
                    operands.push(v.clone());
                }
                if let Ok(head) = (Content {
                    operations: vec![Operation::new("ID", operands)],
                })
                .encode()
                {
                    out.extend_from_slice(b"BI\n");
                    out.extend_from_slice(&head);
                    out.push(b'\n');
                    out.extend_from_slice(&s.content);
                    out.extend_from_slice(b"\nEI\n");
                }
            }
            continue;
        }
        batch.push(op.clone());
    }
    flush(&mut batch, &mut out);
    out
}
