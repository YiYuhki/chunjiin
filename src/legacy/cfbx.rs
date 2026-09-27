//! OLE 복합 파일(CFB) 안전 읽기와 새 컨테이너 조립.

use std::io::{Cursor, Read, Write};

use cfb::{CompoundFile, Version};

use crate::error::{blocked, Result};
use crate::policy::Policy;

pub struct Node {
    /// 선행 '/' 없는 경로 (예: "BodyText/Section0")
    pub path: String,
    pub is_storage: bool,
    pub clsid: [u8; 16],
    pub data: Vec<u8>,
}

pub struct Container {
    pub version: Version,
    pub root_clsid: [u8; 16],
    pub nodes: Vec<Node>,
}

impl Container {
    pub fn stream(&self, path: &str) -> Option<&[u8]> {
        self.nodes
            .iter()
            .find(|n| !n.is_storage && n.path.eq_ignore_ascii_case(path))
            .map(|n| n.data.as_slice())
    }

    pub fn has(&self, path: &str) -> bool {
        self.nodes.iter().any(|n| n.path.eq_ignore_ascii_case(path))
    }
}

pub fn read(data: &[u8], policy: &Policy) -> Result<Container> {
    let mut cf = match CompoundFile::open(Cursor::new(data)) {
        Ok(c) => c,
        Err(e) => return blocked("structure", format!("손상된 OLE 복합 파일: {e}")),
    };
    let version = cf.version();
    let root_clsid = *cf.root_entry().clsid().as_bytes();
    let entries: Vec<(String, bool, [u8; 16], u64)> = cf
        .walk()
        .filter(|e| !e.is_root())
        .map(|e| {
            let path = e
                .path()
                .to_string_lossy()
                .trim_start_matches('/')
                .to_string();
            (path, e.is_storage(), *e.clsid().as_bytes(), e.len())
        })
        .collect();
    if entries.len() > policy.max_zip_entries {
        return blocked(
            "structure",
            format!("OLE 엔트리 수 초과 ({})", entries.len()),
        );
    }
    let total: u64 = entries.iter().map(|e| e.3).sum();
    if total > policy.max_zip_total {
        return blocked("structure", "OLE 스트림 총량 초과");
    }
    let mut nodes = Vec::with_capacity(entries.len());
    for (path, is_storage, clsid, len) in entries {
        let mut buf = Vec::new();
        if !is_storage {
            let r = cf
                .open_stream(format!("/{path}"))
                .and_then(|s| s.take(len).read_to_end(&mut buf));
            if let Err(e) = r {
                return blocked("structure", format!("OLE 스트림 읽기 실패: {path} ({e})"));
            }
        }
        nodes.push(Node {
            path,
            is_storage,
            clsid,
            data: buf,
        });
    }
    Ok(Container {
        version,
        root_clsid,
        nodes,
    })
}

/// 주어진 노드만으로 새 복합 파일을 만든다.
pub fn write(version: Version, root_clsid: [u8; 16], nodes: &[Node]) -> Result<Vec<u8>> {
    let r: std::io::Result<Vec<u8>> = (|| {
        let mut cf = CompoundFile::create_with_version(version, Cursor::new(Vec::new()))?;
        cf.set_storage_clsid("/", uuid_from(root_clsid))?;
        for n in nodes.iter().filter(|n| n.is_storage) {
            let p = format!("/{}", n.path);
            cf.create_storage_all(&p)?;
            if n.clsid != [0; 16] {
                cf.set_storage_clsid(&p, uuid_from(n.clsid))?;
            }
        }
        for n in nodes.iter().filter(|n| !n.is_storage) {
            let p = format!("/{}", n.path);
            if let Some(parent) = std::path::Path::new(&p).parent() {
                if parent != std::path::Path::new("/") {
                    cf.create_storage_all(parent)?;
                }
            }
            let mut s = cf.create_stream(&p)?;
            s.write_all(&n.data)?;
        }
        // 저장소 생성·수정 시각을 고정해 같은 입력이면 항상 같은 결과가 나오게 한다(재현성·중복 제거)
        let storages: Vec<std::path::PathBuf> = cf
            .walk()
            .filter(|e| e.is_storage() && !e.is_root())
            .map(|e| e.path().to_path_buf())
            .collect();
        for p in storages {
            cf.set_created_time(&p, std::time::UNIX_EPOCH)?;
            cf.set_modified_time(&p, std::time::UNIX_EPOCH)?;
        }
        cf.flush()?;
        Ok(cf.into_inner().into_inner())
    })();
    match r {
        Ok(v) => Ok(v),
        Err(e) => blocked("reconstruct", format!("OLE 복합 파일 작성 실패: {e}")),
    }
}

fn uuid_from(b: [u8; 16]) -> uuid::Uuid {
    uuid::Uuid::from_bytes(b)
}

/// 원시 deflate(헤더 없음) 해제 (크기 제한)
pub fn inflate_raw(data: &[u8], limit: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut d = flate2::read::DeflateDecoder::new(data).take(limit as u64 + 1);
    d.read_to_end(&mut out).ok()?;
    (out.len() <= limit).then_some(out)
}

pub fn deflate_raw(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    let _ = e.write_all(data);
    e.finish().unwrap_or_default()
}

/// UTF-16LE 바이트를 문자열로
pub fn utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16_lossy(&units)
}
