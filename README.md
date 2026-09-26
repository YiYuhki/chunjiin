# CDR — 문서 재조합(Content Disarm & Reconstruction) 엔진

외부에서 들어온 오피스 문서와 PDF를 **원본을 고치지 않고, 허용된 콘텐츠만 꺼내 새 문서로 다시 조립**하는 문서 보안 엔진입니다. Rust로 작성했습니다.

악성 여부를 판정하는 탐지 방식이 아닙니다. 허용 목록에 없는 요소(매크로, 스크립트, OLE 개체, 외부 참조, 은닉 데이터 등)는
"제거"되는 것이 아니라 **새 문서에 애초에 조립되지 않습니다.** 알려지지 않은 공격 기법(제로데이)도 허용 목록 밖에 있으면 결과물에 남지 않습니다.

```
원본 ──▶ 형식 판별 ──▶ 분해(파싱) ──▶ 허용 목록 필터 ──▶ 새 문서 조립 ──▶ 재검증 ──▶ 안전한 문서 + 보고서
         (매직 바이트)                                  (빈 문서에서 시작)            └─ 불가 ─▶ 차단
```

## 지원 형식

| 형식 | 입력 | 출력 |
|---|---|---|
| Word | docx, docm, dotx, dotm | docx |
| Excel | xlsx, xlsm, xltx, xltm, xlam | xlsx |
| PowerPoint | pptx, pptm, ppsx, ppsm, potx, potm | pptx |
| 한글 | hwpx | hwpx |
| PDF | pdf | pdf (선택: 페이지 이미지화) |
| 레거시 doc/xls/ppt/hwp, 암호화 문서, 실행 파일, 기타 | — | **차단** |

## 재조합 방식

### Office (OOXML)

1. 압축을 안전하게 해제합니다. Zip bomb(엔트리 수·총량·압축률·실제 해제량), 경로 조작(`../`), 암호화 엔트리를 차단합니다.
2. 패키지 루트 관계(`_rels/.rels`)에서 출발해 **허용된 관계 유형만** 따라가며 파트를 모읍니다.
   - 허용 예: 본문, 스타일, 설정, 글꼴 표, 머리글·바닥글, 각주, 메모, 테마, 이미지, 차트, SmartArt, 시트, 공유 문자열, 표, 피벗, 슬라이드·레이아웃·마스터·노트 등
   - 조립하지 않음: `vbaProject`, XLM 매크로 시트, ActiveX, OLE 개체, altChunk, 외부 통합 문서 링크, 데이터 연결, customUI, customXml, 프린터 설정, 임베디드 글꼴, **어디서도 참조되지 않는 은닉 파트**
3. 각 XML 파트를 DOM으로 파싱한 뒤 다시 구성합니다.
   - 표준 OOXML / Microsoft Office 확장 / VML / Dublin Core 네임스페이스만 허용합니다(그 밖의 요소·속성은 버림).
   - 조립되지 않은 파트를 가리키는 `r:id` 참조를 정리합니다(하이퍼링크는 텍스트를 남기고 링크만 풀고, PPT OLE 프레임은 통째로 제거).
   - Word: DDE / DDEAUTO / INCLUDEPICTURE / INCLUDETEXT / IMPORT / LINK 필드 코드를 비웁니다. 여러 run으로 쪼갠 코드(`DD`+`EAUTO`)와 중첩 필드 난독화도 처리합니다. 첨부 템플릿, docVars, 메일 병합 데이터 원본도 제거합니다.
   - Excel: DDE 수식(`cmd|'/c calc'!A0`)과 `CALL`, `REGISTER`, `EXEC`, `WEBSERVICE`, `FILTERXML`, `RTD` 수식을 없앱니다(캐시 값은 유지). `Auto_Open` 류 자동 실행 이름도 제거합니다.
   - PowerPoint: `ppaction://program`, `macro`, `ole` 실행 액션을 제거합니다.
   - 외부 경로(`file:`, `http:`, UNC, `ms-*:` 프로토콜 핸들러 등)를 가리키는 속성, `xml:base`, `HyperlinkBase`를 제거합니다.
   - DTD/DOCTYPE이 들어 있으면 문서를 차단합니다(XXE, Billion laughs).
4. 이미지는 픽셀만 디코딩해 새로 인코딩합니다(메타데이터·덧붙은 데이터·폴리글롯 제거). EMF/WMF/SVG/TIFF는 조립하지 않습니다.
5. 차트의 원본 데이터 통합 문서(내장 xlsx)는 **같은 엔진으로 재귀 재조합**해서 보존합니다.
6. `[Content_Types].xml`과 모든 `.rels`는 원본을 쓰지 않고 새로 생성합니다. 매크로·템플릿·쇼 형식은 일반 문서 형식으로 바뀝니다.

### PDF

1. qpdf 계열 파서(lopdf)로 원본을 해석합니다. 암호화 문서(사용자 암호)는 차단하고, 스트림 해제량을 제한합니다.
2. **빈 PDF 문서를 새로 만듭니다.**
3. 각 페이지의 콘텐츠 스트림을 연산자 단위로 파싱합니다. 허용 목록(경로·색·텍스트·이미지·셰이딩 등 표준 그리기 연산자)에 있는 연산자만 다시 인코딩하고, q/Q·BT/ET·BMC/EMC 균형을 보정합니다.
4. 페이지가 쓰는 리소스(글꼴·이미지·그래픽 상태·색공간·패턴·셰이딩)만 옮겨 담습니다. 이때 액션·스크립트·첨부·외부 참조 키는 복사하지 않습니다.
   - 폼 XObject, 타일링 패턴, Type3 글리프의 콘텐츠도 같은 방식으로 재구성합니다.
   - Flate/LZW/ASCII/RunLength 스트림은 풀어서 다시 압축합니다. JPEG은 형식을 검증합니다.
   - JBIG2/JPX 이미지는 코덱 취약점 위험 때문에 조립하지 않습니다.
5. 주석과 폼 필드는 외형(appearance)을 페이지 본문에 **평면화**합니다. 링크는 허용된 URI와 문서 안 페이지 이동만 새로 만듭니다.
6. 카탈로그는 `Pages`와 `Outlines`(책갈피: 제목 + 페이지 이동만)로만 새로 구성합니다. JavaScript, OpenAction, 추가 액션(/AA), 첨부 파일, XFA/AcroForm, 포트폴리오, XMP/문서 정보 메타데이터, 증분 업데이트 이력, 참조되지 않은 객체, `%%EOF` 뒤에 붙은 데이터는 새 문서에 존재하지 않습니다.

### PDF 최고 보안 모드 (`--rasterize`)

구조 재조합을 끝낸 PDF를 순수 Rust 렌더러([hayro](https://crates.io/crates/hayro), `unsafe` 금지)로 페이지마다 렌더링합니다. 그 이미지만으로 PDF를 다시 만듭니다.
글꼴 프로그램, 벡터 그래픽, 원본 이미지 코덱 데이터 등 **원본에서 온 바이트가 하나도 남지 않습니다.** 텍스트 선택, 검색, 링크, 책갈피는 사라집니다.
렌더러는 원본이 아니라 이미 재조합된 문서를 입력으로 받습니다. 기본값은 150DPI이고, 페이지당 4천만 화소를 넘지 않게 해상도를 자동으로 낮춥니다.

### 한글 (HWPX)

1. `mimetype`(`application/hwp+zip`)과 패키지 매니페스트(`Contents/content.hpf`)를 확인합니다.
2. 매니페스트 항목 중 허용된 것만 새 패키지에 조립합니다.
   - 조립함: XML 파트(헤더·섹션·설정·차트 등, 허용 네임스페이스로 재구성), 이미지(재인코딩), 미리보기
   - 조립하지 않음: 문서 스크립트(`Scripts/`, JScript 매크로), OLE 개체, 실행 파일·글꼴 등 비이미지 바이너리, 외부 경로 항목(`C:\…`, URL), 매니페스트에 없는 은닉 파일
   - 한컴이 모든 문서에 넣는 **빈 기본 스크립트 템플릿**은 Info로 보고합니다. 실제 코드가 있는 스크립트만 Critical로 구분합니다.
3. 본문을 이렇게 재구성합니다.
   - `hp:ole`와 `hp:video`를 제거합니다.
   - 제외된 바이너리를 가리키는 그림은 제거하고, 임베디드 글꼴 참조는 해제합니다.
   - 허용되지 않은 하이퍼링크 필드(`file:`, UNC 등)는 대상을 비웁니다. 한컴 형식(`http\://…;1;0;0;`, 스킴 없는 `www.…`)도 해석합니다.
4. `mimetype`을 무압축 첫 엔트리로 둔 새 OCF 패키지를 작성합니다. 매니페스트와 `META-INF` 목록은 조립된 파일에 맞게 정리합니다.

### 공통

- 확장자가 아니라 내용으로 형식을 판별합니다. 확장자 위장은 탐지해서 교정합니다.
- **재검증**: 결과물을 엔진에 한 번 더 넣어, MEDIUM 이상 탐지가 남아 있으면 차단합니다.
- **fail-closed**: 모든 오류와 내부 패닉은 차단으로 처리합니다.

## 빌드와 사용

```bash
cargo build --release
./target/release/cdr --help
```

```bash
# 파일/디렉터리 재조합 → clean/ 에 저장, JSON 보고서 생성
cdr sanitize 받은편지함/ -o clean/ --report report.json -v

# 저장 없이 분석만
cdr scan 의심문서.docm
```

| 옵션 | 설명 |
|---|---|
| `--remove-links` | 허용 스킴(http/https/mailto)의 하이퍼링크까지 모두 제외 |
| `--keep-metadata` | 작성자 등 메타데이터 유지 |
| `--no-flatten` | PDF 주석/폼 외형을 평면화하지 않고 버림 |
| `--rasterize` | PDF 최고 보안 모드(페이지 이미지화) |
| `--dpi <N>` | 이미지화 해상도(기본 150) |
| `--max-size <MB>` | 최대 입력 크기(기본 100MB) |
| `--overwrite` | 출력 파일 덮어쓰기 |

종료 코드: `0` 모두 처리됨, `2` 차단된 파일 있음, `1` 입력 오류

출력 예:

```
[재조합] 보고서.docm (docx, 탐지 20건) → 보고서.docx
    - [Critical] macro: VBA 매크로 - 새 문서에 조립하지 않음 @ word/vbaProject.bin
    - [Critical] template-injection: 원격/첨부 템플릿(템플릿 인젝션) 제외: http://evil.example/template.dotm @ word/_rels/settings.xml.rels
    - [High] dde: 위험 필드 코드 무력화: DDEAUTO c:\windows\system32\cmd.exe "/k calc.exe" @ word/document.xml
    ...
    · images_reencoded=1, input_parts=15, output_parts=9
```

### REST API 서버

```bash
cdr serve --bind 0.0.0.0:8080 [--concurrency 4] [--timeout 120] [--max-size 100]
```

| 메서드 | 경로 | 설명 |
|---|---|---|
| `POST` | `/api/v1/sanitize` | multipart `file`을 받아 재조합된 파일을 돌려줍니다. 응답 헤더: `X-CDR-Status`, `X-CDR-Findings`, `X-CDR-Max-Severity`, `X-CDR-Detected-Type`, `X-CDR-Output-SHA256`. 차단되면 **422**와 JSON 보고서를 돌려줍니다. |
| `POST` | `/api/v1/scan` | multipart `file`을 받아 JSON 보고서를 돌려줍니다. |
| `GET` | `/health` | 상태 확인 |
| `GET` | `/` | 브라우저 업로드 페이지 |

요청마다 정책을 바꿀 수 있습니다: `?rasterize=true&dpi=150&remove_links=true&keep_metadata=true`

```bash
curl -F "file=@invoice.docm" http://localhost:8080/api/v1/sanitize -OJ
curl -F "file=@report.pdf" "http://localhost:8080/api/v1/scan?rasterize=true"
```

재조합 작업은 별도 스레드 풀에서 실행합니다. 동시 처리 수(세마포어), 요청 크기, 처리 시간으로 자원 고갈을 막습니다.

### 라이브러리로 사용

```rust
use cdr::{Engine, Policy, Status};

let engine = Engine::new(Policy { remove_hyperlinks: false, ..Policy::default() });
let result = engine.process(&std::fs::read("invoice.docm")?, "invoice.docm");
match result.status {
    Status::Blocked => eprintln!("차단: {}", result.reason),
    _ => std::fs::write(result.output_filename.as_ref().unwrap(), result.output.as_ref().unwrap())?,
}
println!("{}", serde_json::to_string_pretty(&result)?);
```

### Docker

```bash
docker build -t cdr .
# 일괄 처리
docker run --rm -v "$PWD/in:/in:ro" -v "$PWD/out:/out" cdr sanitize /in -o /out --report /out/report.json
# API 서버
docker run --rm -p 8080:8080 cdr serve --bind 0.0.0.0:8080
```

## 보고서(JSON)

```json
{
  "filename": "보고서.docm",
  "detected_type": "docx",
  "status": "sanitized",
  "output_filename": "보고서.docx",
  "input_sha256": "…", "output_sha256": "…",
  "max_severity": "critical",
  "findings": [
    { "category": "macro", "severity": "critical",
      "description": "VBA 매크로 - 새 문서에 조립하지 않음", "location": "word/vbaProject.bin" }
  ],
  "stats": { "input_parts": 15, "output_parts": 9, "images_reencoded": 1 }
}
```

`status`: `clean`(위협 없음, 재조합본 제공) · `sanitized`(위협 요소를 배제하고 재조합) · `blocked`(차단)

## 구조

```
src/
├── engine.rs          판별 → 재조합 → 재검증 파이프라인 (fail-closed)
├── detect.rs          매직 바이트 기반 형식 판별
├── policy.rs          정책(크기 제한, 링크/메타데이터/평면화)
├── report.rs          결과·탐지 항목·통계
├── xml.rs             재조합용 최소 XML DOM (DTD 불허, 네임스페이스 해석)
├── zipsafe.rs         안전한 압축 해제 / 결정적 재압축
├── imaging.rs         이미지 디코딩 → 재인코딩
├── hwpx.rs            HWPX 매니페스트 기반 재조합
├── server.rs          REST API (axum)
├── ooxml/
│   ├── mod.rs         관계 그래프 탐색 → 파트 재구성 → 새 패키지 조립
│   ├── rules.rs       관계 유형·콘텐츠 형식·네임스페이스 허용 목록
│   └── content.rs     XML 요소 재구성 (필드·수식·액션·속성 규칙)
├── pdf/
│   ├── mod.rs         새 PDF 생성, 리소스 복사, 주석 평면화, 링크·책갈피 재생성
│   ├── content.rs     콘텐츠 스트림 연산자 허용 목록 / 재인코딩
│   ├── raster.rs      최고 보안 모드: 페이지 렌더링 → 이미지 PDF
│   └── scan.rs        원본 위협 요소 분석(보고용)
└── main.rs            CLI
tests/                 악성 샘플을 코드로 생성해 검증하는 통합 테스트
```

## 테스트

```bash
cargo test
```

## 한계

- 레거시 바이너리 형식(doc/xls/ppt/hwp)은 차단합니다. 필요하면 격리 환경에서 OOXML/HWPX/PDF로 변환한 뒤 재조합하십시오.
- HWPX 결과물은 실제 한컴 문서 49종으로 검증했습니다. 구조 무결성, 본문 텍스트 일치, 독립 파서(hwpxlib)의 읽기·쓰기를 확인했습니다. 한컴오피스에서 직접 열어 보는 확인은 하지 않았습니다.
- 래스터화 모드는 hayro 렌더러의 지원 범위를 따릅니다(일부 블렌딩/녹아웃 그룹 미지원).
- PDF 글꼴 프로그램(TrueType/CFF)은 구조를 재작성하지 않고 그대로 옮깁니다. 글꼴 파서 취약점까지 막으려면 글꼴 재생성이나 페이지 래스터화 모드를 추가로 고려해야 합니다.
- PDF 인라인 이미지 중 필터가 걸린 것은 파서가 지원하지 않아 제외됩니다.
- Office의 EMF/WMF/SVG 이미지와 GIF 애니메이션(첫 프레임만 남음)은 재조합하지 않습니다.
- 매크로·외부 연결 등 제거되는 기능에 의존하는 업무 문서는 동작이 달라집니다. 원본을 격리 보관하는 정책과 함께 운영하십시오.
