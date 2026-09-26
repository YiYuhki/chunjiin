"""CDR REST API (FastAPI).

    POST /api/v1/sanitize   multipart 'file' → 무해화된 파일 (차단 시 422 + JSON 보고서)
    POST /api/v1/scan       multipart 'file' → JSON 보고서
    GET  /health
    GET  /                  간단한 업로드 페이지
"""

from __future__ import annotations

import os
from urllib.parse import quote

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response

from . import __version__
from .engine import CDREngine
from .policy import Policy
from .report import CDRResult, Status

policy = Policy(
    remove_hyperlinks=os.environ.get("CDR_REMOVE_LINKS", "0") == "1",
    strip_metadata=os.environ.get("CDR_KEEP_METADATA", "0") != "1",
    max_file_size=int(os.environ.get("CDR_MAX_SIZE_MB", "100")) * 1024 * 1024,
)
engine = CDREngine(policy)
app = FastAPI(title="CDR 문서 보안 API", version=__version__)


def _read_upload(file: UploadFile) -> bytes:
    data = file.file.read(policy.max_file_size + 1)
    if len(data) > policy.max_file_size:
        raise HTTPException(status_code=413, detail="파일 크기 제한 초과")
    return data


def _process(file: UploadFile) -> CDRResult:
    return engine.process(_read_upload(file), file.filename or "unnamed")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.post("/api/v1/scan")
def scan(file: UploadFile = File(...)) -> JSONResponse:
    return JSONResponse(_process(file).to_dict())


@app.post("/api/v1/sanitize")
def sanitize(file: UploadFile = File(...)) -> Response:
    result = _process(file)
    if result.status == Status.BLOCKED:
        return JSONResponse(result.to_dict(), status_code=422)
    name = result.output_filename or "sanitized"
    ascii_name = name.encode("ascii", "replace").decode().replace("?", "_").replace('"', "_")
    headers = {
        "Content-Disposition": f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(name)}",
        "X-CDR-Status": result.status.value,
        "X-CDR-Detected-Type": result.detected_type,
        "X-CDR-Findings": str(len(result.findings)),
        "X-CDR-Max-Severity": result.max_severity.value if result.max_severity else "none",
        "X-CDR-Output-SHA256": result.output_sha256,
    }
    return Response(result.output, media_type="application/octet-stream", headers=headers)


INDEX_HTML = """<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CDR 문서 보안</title>
<style>
body{font-family:system-ui,sans-serif;max-width:720px;margin:40px auto;padding:0 16px;color:#1f2328}
h1{font-size:1.4rem}.box{border:1px solid #d0d7de;border-radius:8px;padding:20px}
button{padding:8px 16px;margin-right:8px;cursor:pointer}pre{background:#f6f8fa;padding:12px;overflow:auto;font-size:.85rem}
</style></head><body>
<h1>CDR (Content Disarm &amp; Reconstruction)</h1>
<p>문서에서 매크로, 스크립트, OLE 개체, 외부 링크 등 능동 콘텐츠를 제거하고 안전한 파일로 재구성합니다.</p>
<div class="box">
<input type="file" id="f"><br><br>
<button onclick="run('scan')">분석</button><button onclick="run('sanitize')">무해화 후 다운로드</button>
</div>
<pre id="out"></pre>
<script>
async function run(kind){
  const f=document.getElementById('f').files[0]; if(!f) return;
  const fd=new FormData(); fd.append('file',f);
  const out=document.getElementById('out'); out.textContent='처리 중...';
  const r=await fetch('/api/v1/'+kind,{method:'POST',body:fd});
  const ct=r.headers.get('content-type')||'';
  if(ct.includes('json')){out.textContent=JSON.stringify(await r.json(),null,2);return;}
  const blob=await r.blob(); const cd=r.headers.get('content-disposition')||'';
  const m=cd.match(/filename\\*=UTF-8''([^;]+)/); const name=m?decodeURIComponent(m[1]):'sanitized';
  const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=name; a.click();
  out.textContent='상태: '+r.headers.get('x-cdr-status')+' / 탐지: '+r.headers.get('x-cdr-findings')+'건 → '+name;
}
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return INDEX_HTML
