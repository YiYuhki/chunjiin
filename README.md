# CDR — Content Disarm & Reconstruction

외부에서 유입되는 문서(메일 첨부, 업로드, 망연계 파일 등)에서 **악성 행위가 가능한 능동 콘텐츠를 제거하고,
안전한 요소만으로 파일을 새로 재구성**하는 문서 보안 엔진입니다.

시그니처 기반 백신과 달리 "악성인지"를 판단하지 않습니다. 형식 명세상 필요한 요소만 남기고
나머지(매크로, 스크립트, 임베디드 개체, 외부 참조 등)를 제거하기 때문에 **제로데이 공격에도 효과적**입니다.

```
입력 파일 ─▶ 형식 판별(매직 바이트) ─▶ 해체/무해화(Disarm) ─▶ 재구성(Reconstruct) ─▶ 재검증 ─▶ 안전한 파일 + 보고서
                                                       └─ 무해화 불가 ─▶ 차단(Blocked)
```

## 지원 형식과 무해화 항목

| 형식 | 무해화/재구성 내용 |
|---|---|
| **PDF** | JavaScript(OpenAction·/AA·이름 트리·폼), Launch/SubmitForm/ImportData/GoToR/RichMedia 액션, 위험 URI(`file:`, `javascript:` 등), 임베디드 파일·첨부 주석·포트폴리오, XFA 폼, 멀티미디어/3D 주석, `%%EOF` 뒤 덧붙은 데이터, 참조되지 않은 은닉 객체·증분 업데이트, 메타데이터 → qpdf 로 전체 재작성 |
| **Word** (docx/docm/dotx/dotm) | VBA 매크로, ActiveX, OLE 개체, altChunk, **원격 템플릿 인젝션**, 외부 프레임/하위 문서/외부 이미지(NTLM 유출), 위험 하이퍼링크, **DDE/DDEAUTO/INCLUDEPICTURE** 필드(분할·QUOTE 난독화 포함), 작성자 정보 → 매크로 형식을 docx 로 변환 |
| **Excel** (xlsx/xlsm/xltx/xlam) | VBA, **Excel 4.0(XLM) 매크로 시트**, `Auto_Open` 자동 실행 이름, DDE(`cmd|'...'!A0`)·`CALL`/`REGISTER`/`EXEC`/`WEBSERVICE` 수식(캐시 값은 유지), 외부 통합 문서 링크, 외부 데이터 연결 → xlsx 로 변환 |
| **PowerPoint** (pptx/pptm/ppsx/potx) | VBA, OLE/ActiveX, `ppaction://program`·`macro`·`ole` 실행 액션, 위험 링크 → pptx 로 변환 |
| **HWPX** (한컴오피스) | 문서 스크립트(`Scripts/`, JScript 매크로), OLE 개체 BinData, 실행 파일 형태의 내장 파일, 매니페스트 정리 |
| **RTF** | OLE 개체(`\object`, `\objdata` — CVE-2017-11882/0199 경로), `\*\datastore`, `\*\oleclsid`, 원격 템플릿(`\*\template`), 위험 필드 코드, 문서 끝 덧붙은 데이터 (`\bin` 바이너리 구간 올바르게 처리) |
| **이미지** (PNG/JPEG/GIF/BMP/TIFF) | 픽셀만 추출해 재인코딩 → EXIF/XMP/주석/ICC 제거, 폴리글롯·은닉 페이로드 제거, 디컴프레션 폭탄 차단, EXIF 회전은 픽셀에 적용 |
| **CSV/TSV** | 수식 인젝션(`=`, `+`, `-`, `@` 로 시작하는 셀) 무력화(숫자는 유지), 제어 문자·BiDi 오버라이드 제거 |
| **텍스트** | UTF-8 재작성, 제어 문자·BiDi 오버라이드(RLO 위장) 제거 |
| **ZIP** | 내부 파일을 재귀적으로 CDR 처리(최대 3단계), 차단된 파일은 압축에서 제외 |
| **레거시 OLE** (doc/xls/ppt/hwp) | 안전한 재구성이 불가하므로 **차단**. 매크로·스크립트·OLE·암호화 여부를 분석해 사유 보고 |
| 실행 파일/알 수 없는 형식 | **차단** |

### 공통 방어
- 확장자가 아닌 **매직 바이트/내부 구조로 형식 판별**, 확장자 위장 탐지 및 교정
- 압축 컨테이너: Zip bomb(엔트리 수·총 크기·압축률·실제 해제량), 경로 조작(`../`), 암호화 엔트리, 중복 엔트리 차단
- XML: DTD/엔터티를 해석하지 않는 파서 사용, **DOCTYPE 포함 시 차단(XXE/Billion laughs)**
- 암호화 문서(PDF 사용자 암호, 암호화 OOXML)는 검사 불가로 차단
- **재검증**: 재구성 결과를 다시 엔진에 통과시켜 MEDIUM 이상 잔여 위협이 있으면 차단
- 예기치 못한 오류는 모두 차단(fail-closed)

## 설치

```bash
pip install -e ".[api]"      # CLI + REST API
pip install -e ".[dev]"      # 테스트 포함
```

요구 사항: Python 3.10+ (`pikepdf`, `Pillow`, `lxml`, `olefile`)

## 사용법

### CLI

```bash
# 파일/디렉터리 무해화 → clean/ 에 저장, JSON 보고서 생성
cdr sanitize 받은편지함/ -o clean/ --report report.json -v

# 저장 없이 분석만
cdr scan 의심문서.docm

# 옵션
#   --remove-links    허용 스킴의 하이퍼링크까지 모두 제거
#   --keep-metadata   작성자/EXIF 등 메타데이터 유지
#   --max-size 50     최대 파일 크기(MB)
```

종료 코드: `0` 모두 처리됨, `2` 차단된 파일 있음, `1` 입력 오류

```
[무해화] 보고서.docm (docx, 탐지 14건) → 보고서.docx
    - [critical] macro: VBA 매크로 프로젝트 제거 @ word/vbaProject.bin
    - [critical] template-injection: 원격 템플릿 인젝션 제거: http://evil.example/template.dotm @ word/_rels/settings.xml.rels
    - [high] dde: 위험 필드 코드 무력화: DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe" @ word/document.xml
    ...
```

### REST API

```bash
cdr serve --host 0.0.0.0 --port 8080
```

| 메서드 | 경로 | 설명 |
|---|---|---|
| `POST` | `/api/v1/sanitize` | multipart `file` → 무해화된 파일. 헤더 `X-CDR-Status`, `X-CDR-Findings`, `X-CDR-Max-Severity`, `X-CDR-Output-SHA256`. 차단 시 **422** + JSON 보고서 |
| `POST` | `/api/v1/scan` | multipart `file` → JSON 보고서 |
| `GET` | `/health` | 상태 확인 |
| `GET` | `/` | 브라우저 업로드 페이지 |

```bash
curl -F "file=@invoice.docm" http://localhost:8080/api/v1/sanitize -OJ
curl -F "file=@invoice.pdf"  http://localhost:8080/api/v1/scan
```

환경 변수: `CDR_REMOVE_LINKS=1`, `CDR_KEEP_METADATA=1`, `CDR_MAX_SIZE_MB=100`

### Docker

```bash
docker build -t cdr .
docker run -p 8080:8080 cdr
```

### 라이브러리

```python
from cdr import CDREngine, Policy, Status

engine = CDREngine(Policy(remove_hyperlinks=False, strip_metadata=True))
result = engine.process(open("invoice.docm", "rb").read(), "invoice.docm")

if result.status == Status.BLOCKED:
    print("차단:", result.reason)
else:
    open(result.output_filename, "wb").write(result.output)   # invoice.docx
print(result.to_dict())
```

## 보고서 형식

```json
{
  "filename": "보고서.docm",
  "detected_type": "docx",
  "status": "sanitized",
  "output_filename": "보고서.docx",
  "input_sha256": "…", "output_sha256": "…",
  "max_severity": "critical",
  "findings": [
    {"category": "macro", "severity": "critical", "description": "VBA 매크로 프로젝트 제거",
     "location": "word/vbaProject.bin", "removed": true}
  ]
}
```

`status`: `clean`(위협 없음, 재구성본 제공) · `sanitized`(위협 제거 후 제공) · `blocked`(차단)

## 프로젝트 구조

```
src/cdr/
├── engine.py          # 판별 → 무해화 → 재검증 파이프라인, ZIP 재귀 처리
├── detect.py          # 매직 바이트 기반 형식 판별
├── policy.py          # 정책(크기 제한, 링크/메타데이터 처리 등)
├── report.py          # 결과/탐지 항목 모델
├── cli.py, api.py     # CLI, REST API
└── sanitizers/
    ├── pdf.py  ooxml.py  hwpx.py  rtf.py  image.py  text.py
    ├── ole.py         # 레거시 OLE 분석(차단 사유)
    └── _zip.py        # 안전한 압축 해제/재구성, 안전한 XML 파서
tests/                 # 악성 샘플을 코드로 생성하여 검증
```

## 테스트

```bash
pytest
```

## 한계 및 권장 사항

- 레거시 바이너리 형식(doc/xls/ppt/hwp)은 재구성하지 않고 차단합니다. 필요하면 격리 환경에서 OOXML/HWPX/PDF 로 변환한 뒤 CDR 을 적용하십시오.
- PDF 의 폰트·이미지 스트림 자체를 이용한 렌더러 취약점 공격까지 제거하려면, 최고 보안 등급에서 페이지를 이미지로 래스터화하는 방식을 추가로 고려하십시오.
- 제거되는 기능(매크로, 외부 링크 등)에 의존하는 업무 문서는 동작이 달라질 수 있으므로 원본은 격리 보관 정책과 함께 운영하는 것을 권장합니다.
