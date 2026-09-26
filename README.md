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
| 한글 5.x (바이너리) | hwp | hwp |
| Word 97-2003 | doc, dot | doc |
| Excel 97-2003 (BIFF8/BIFF5) | xls, xlt, xla | xls |
| PowerPoint 97-2003 | ppt, pot, pps | ppt |
| PDF | pdf | pdf (선택: 페이지 이미지화) |
| 암호화·DRM·배포용 문서, Word 6/95·PowerPoint 95, 실행 파일, 기타 | — | **차단** |

## 재조합 방식

### Office (OOXML)

1. 압축을 안전하게 해제합니다. Zip bomb(엔트리 수·총량·압축률·실제 해제량), 경로 조작(`../`), 암호화 엔트리를 차단합니다.
2. 패키지 루트 관계(`_rels/.rels`)에서 출발해 **허용된 관계 유형만** 따라가며 파트를 모읍니다.
   - 허용 예: 본문, 스타일, 설정, 글꼴 표, 머리글·바닥글, 각주, 메모, 테마, 이미지, 차트, SmartArt, 시트, 공유 문자열, 표, 피벗, 슬라이드·레이아웃·마스터·노트 등
   - 조립하지 않음: `vbaProject`, XLM 매크로 시트, ActiveX, OLE 개체, altChunk, 외부 통합 문서 링크, 데이터 연결, customUI, customXml, 프린터 설정, 임베디드 글꼴, **어디서도 참조되지 않는 은닉 파트**
3. 각 XML 파트를 DOM으로 파싱한 뒤 다시 구성합니다.
   - 표준 OOXML / Microsoft Office 확장 / VML / Dublin Core 네임스페이스만 허용합니다(그 밖의 요소·속성은 버림).
   - 조립되지 않은 파트를 가리키는 `r:id` 참조를 정리합니다(하이퍼링크는 텍스트를 남기고 링크만 풀고, PPT OLE 프레임은 통째로 제거).
   - Word: DDE / DDEAUTO / INCLUDEPICTURE / INCLUDETEXT / IMPORT / LINK / DATABASE / RD 필드 코드와, 허용되지 않은 대상(UNC·`file:` 등)을 가리키는 HYPERLINK 필드를 비웁니다. 여러 run으로 쪼갠 코드(`DD`+`EAUTO`)와 중첩 필드 난독화도 처리합니다. 첨부 템플릿, docVars, 메일 병합 데이터 원본도 제거합니다.
   - Excel: DDE 수식(`cmd|'/c calc'!A0`)과 `CALL`, `REGISTER`, `EXEC`, `WEBSERVICE`, `FILTERXML`, `RTD` 수식, 허용되지 않은 대상의 `HYPERLINK`/`IMAGE` 수식을 없앱니다(캐시 값은 유지). 셀 수식뿐 아니라 이름 정의, 조건부 서식(`cfRule`), 데이터 유효성 검사 수식도 검사하며, 해당 규칙은 통째로 제거합니다. `Auto_Open` 류 자동 실행 이름도 제거합니다.
   - PowerPoint: `ppaction://program`, `macro`, `ole` 실행 액션을 제거합니다.
   - 외부 경로를 가리키는 속성, `xml:base`, `HyperlinkBase`를 제거합니다. 외부 여부는 문자열 패턴이 아니라 구조로 판단합니다: 계층형 URI(`스킴://`), UNC(`\\`, `//`, `/\` 혼용 포함), 드라이브 경로, `ms-*:`·`search-ms:`·`mhtml:` 등 프로토콜 핸들러.
   - XML 노드 수 제한(`max_xml_nodes`)은 파트별이 아니라 **문서 전체 합계**에 적용합니다(작은 파트 여러 개로 한도를 나눠 쓰는 우회 방지).
   - DTD/DOCTYPE이 들어 있으면 문서를 차단합니다(XXE, Billion laughs).
4. 이미지는 픽셀만 디코딩해 새로 인코딩합니다(메타데이터·덧붙은 데이터·폴리글롯 제거). EMF/WMF/SVG/TIFF는 조립하지 않습니다.
5. 차트의 원본 데이터 통합 문서(내장 xlsx)는 **같은 엔진으로 재귀 재조합**해서 보존합니다.
6. `[Content_Types].xml`과 모든 `.rels`는 원본을 쓰지 않고 새로 생성합니다. 매크로·템플릿·쇼 형식은 일반 문서 형식으로 바뀝니다.

### PDF

1. qpdf 계열 파서(lopdf)로 원본을 해석합니다. 암호화 문서(사용자 암호)는 차단하고, 스트림 해제량을 제한합니다.
2. **빈 PDF 문서를 새로 만듭니다.**
3. 각 페이지의 콘텐츠 스트림을 연산자 단위로 파싱합니다. 허용 목록(경로·색·텍스트·이미지·셰이딩 등 표준 그리기 연산자)에 있는 연산자만 다시 인코딩하고, q/Q·BT/ET·BMC/EMC 균형을 보정합니다.
4. 페이지가 쓰는 리소스(글꼴·이미지·그래픽 상태·색공간·패턴·셰이딩)만 옮겨 담습니다. 이때 액션·스크립트·첨부·외부 참조 키는 복사하지 않습니다.
   - 폼 XObject, 타일링 패턴, Type3 글리프의 콘텐츠도 같은 방식으로 재구성합니다. 판정에 쓰는 키(`/Subtype`, `/Filter` 등)가 간접 참조여도 풀어서 판단하고, 같은 객체라도 쓰임(일반/콘텐츠)별로 따로 복사해 캐시를 통한 필터 우회를 막습니다. 글꼴 사전은 정의된 키만 옮깁니다.
   - 콘텐츠 스트림은 해석 전에 토큰 수를 세어 스트림당 400만, 문서 전체 4천만을 넘으면 차단합니다(작은 압축 스트림으로 메모리를 고갈시키는 공격 방어).
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
   - 허용되지 않은 하이퍼링크 필드(`file:`, UNC 등)는 대상을 비웁니다. 한컴 형식(`http\://…;1;0;0;`, 스킴 없는 `www.…`)도 해석합니다. `Path`와 실제 실행되는 `Command`를 모두 검사하고, 하나라도 허용되지 않으면 둘 다 비웁니다.
4. `mimetype`을 무압축 첫 엔트리로 둔 새 OCF 패키지를 작성합니다. 매니페스트와 `META-INF` 목록은 조립된 파일에 맞게 정리합니다.

### 레거시 바이너리 문서 (HWP 5.x / doc / xls / ppt)

OLE 복합 파일(CFB)은 **새 컨테이너를 만들어 허용된 스트림만** 옮겨 담습니다. 스트림 내부는 방식이 둘로 나뉩니다.
- HWP처럼 레코드에 절대 오프셋이 없는 형식은 레코드를 재구성합니다.
- doc/ppt처럼 오프셋이 얽힌 형식은 **길이가 바뀌지 않게 제자리에서** 무력화합니다.

떼어낼 수 없는 능동 콘텐츠가 있으면 차단합니다(fail-closed).

| 형식 | 조립하는 것 | 조립하지 않음 / 무력화 | 차단 |
|---|---|---|---|
| **HWP 5.x** | FileHeader(속성 비트 정리), DocInfo, BodyText, 래스터 이미지 BinData(재인코딩), 미리보기 | 문서 스크립트(JScript), **EPS/PostScript**, OLE, DocOptions(연결 문서·DRM·서명), XMLTemplate, 문서 이력. 레코드 재구성으로 외부 파일 연결(BIN_DATA LINK) 경로와 허용되지 않은 하이퍼링크 필드 제거 | 암호, 배포용, DRM, 인증서 암호화 |
| **doc** | WordDocument, 사용 중인 테이블 스트림, Data, CompObj | VBA(Macros), ObjectPool(OLE, 미리보기 그림은 유지), 사용하지 않는 테이블 스트림(이전 편집 잔재), MsoDataStore. FIB의 명령 사용자 지정·매크로 이름·**첨부 서식 파일 연결** 제거. 조각 테이블을 따라 **DDE/INCLUDE*/LINK/위험 HYPERLINK 필드 코드를 같은 길이 공백으로 덮어씀** | 암호화, Word 6/95 |
| **xls** | Workbook, 피벗 캐시, CompObj | VBA(_VBA_PROJECT_CUR), 사용자 정의 XML, 이전 형식 스트림, 변경 추적 기록. 하이퍼링크(HLINK) 레코드를 구조대로 해석해 허용되지 않은 대상(URL·파일 모니커)만 제자리에서 공백으로 덮어씀(표시 문자열은 유지). `--neutralize-ole` 사용 시 임베디드 OLE(MBD*)를 빈 저장소로 대체 | 암호화, **Excel 4.0 매크로 시트**, VB 모듈 시트, DDE/OLE 링크, ActiveX, 외부 요청 함수(`WEBSERVICE`/`FILTERXML`/`IMAGE`), 임베디드 OLE(기본값) |
| **ppt** | PowerPoint Document, Current User, Pictures, CompObj | 매크로·프로그램 실행·OLE 동작을 "동작 없음"으로, 위험 하이퍼링크 대상(상대 경로 포함)을 공백으로 바꿈(제자리). 압축 여부와 관계없이 임베디드 개체를 인식. `--neutralize-ole` 사용 시 OLE/VBA 저장소를 같은 자리의 빈 OLE 파일로 덮어쓰고 매크로 표시를 끔 | 암호화, ActiveX, PowerPoint 95, 임베디드 OLE/VBA(기본값), 레코드 구조 밖에 숨긴 저장소 |

`--neutralize-ole`은 개체 **내용만** 비웁니다. 슬라이드와 시트에 저장된 미리보기 그림은 그대로 남습니다. PPT는 정상 레코드 트리의 최상위 영구 객체만 덮어쓰고, 전수 검색에서만 발견되는 저장소는 은닉 시도로 보고 차단합니다.
Apache POI 테스트 문서로 확인한 결과는 다음과 같습니다.
- PPT 차단 57→27건, XLS 차단 41→36건으로 줄었습니다.
- 대체한 PPT 내장 개체 229개가 모두 정상 OLE 파일로 해제됐고, 텍스트는 원본과 같습니다.
- Office에서 개체를 활성화했을 때의 동작은 확인하지 못했으므로 기본값은 차단입니다.

PPT의 위험 레코드는 트리 순회에만 의존하지 않습니다. 비정상 컨테이너 속에 숨긴 경우까지 잡도록 **스트림 전체를 레코드 헤더 패턴으로 전수 검색**합니다.

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
| `--config <FILE>` | 정책 파일(TOML). 명시한 명령행 옵션이 파일 값보다 우선 |
| `-j, --jobs <N>` | 동시 처리 수(기본: CPU 수). 결과·보고서 순서는 입력 순서 유지 |
| `--remove-links` | 허용 스킴(http/https/mailto)의 하이퍼링크까지 모두 제외 |
| `--keep-metadata` | 작성자 등 메타데이터 유지 |
| `--no-flatten` | PDF 주석/폼 외형을 평면화하지 않고 버림 |
| `--rasterize` | PDF 최고 보안 모드(페이지 이미지화) |
| `--dpi <N>` | 이미지화 해상도(기본 150) |
| `--max-size <MB>` | 최대 입력 크기(기본 100MB) |
| `--overwrite` | 출력 파일 덮어쓰기 |
| `--neutralize-ole` | 레거시 PPT/XLS 임베디드 OLE를 차단하지 않고 빈 개체로 대체 |
| `--audit-log <FILE>` | 감사 로그(JSONL)에 처리 결과를 한 줄씩 추가 |
| `--quarantine <DIR>` | 재조합·차단된 파일의 원본을 격리 보관 |
| `--quarantine-clean` | 정상 파일의 원본도 격리 보관 |

종료 코드: `0` 모두 처리됨, `2` 차단된 파일 있음, `3` 감사 기록 실패(해당 결과물은 저장하지 않음), `1` 입력 오류

### 정책 파일

```bash
cdr policy > cdr.toml          # 기본값과 설명이 들어간 정책 파일 생성
cdr sanitize inbox/ -o clean/ --config cdr.toml
```

`[limits]`(크기·압축·XML·이미지·PDF 제한), `[links]`(허용 스킴, 링크 제거), `[content]`(메타데이터, 평면화, OLE 대체), `[pdf]`(이미지화·해상도·품질) 네 부분으로 구성됩니다.
- 정책 누락을 막기 위해 **알 수 없는 키(오타)는 오류로 거부**합니다.
- `file`, `javascript` 같은 위험 스킴은 허용 목록에 넣을 수 없습니다.
- 정책은 기본값 → 정책 파일 → 명시한 명령행 옵션 순으로 적용됩니다.

### 감시 폴더 모드 (망연계·메일 게이트웨이용)

```bash
cdr watch --inbox /data/수신 --outbox /data/송신 --blocked /data/차단 \
          --quarantine /data/격리 --audit-log /var/log/cdr/audit.jsonl --config cdr.toml
```

수신 폴더에 들어온 문서를 자동으로 재조합해 송신 폴더로 넘깁니다. "들어온 문서는 반드시 CDR을 거쳐서만 나간다"는 흐름을 한 명령으로 구성합니다.
- 크기와 수정 시각이 `--settle`초(기본 3) 동안 변하지 않은 파일만 처리합니다. 복사 중인 파일은 건드리지 않습니다.
- 숨김 파일과 `.part`, `.tmp`, `.crdownload` 등 쓰는 중인 파일은 건너뜁니다.
- 결과물은 숨김 임시 파일에 쓴 뒤 이름을 바꿉니다. 송신 측이 쓰는 도중의 파일을 가져가지 않습니다. 임시 파일은 매번 고유한 이름으로 새로 만들어(`O_EXCL`) 미리 심어 둔 파일이나 심볼릭 링크를 따라가지 않습니다.
- 심볼릭 링크는 따라가지 않습니다. 목록 작성 뒤 파일을 링크로 바꿔치기하면(열기 전후 파일 식별자 비교) 처리하지 않습니다.
- 하위 폴더 구조를 유지합니다. 차단된 문서는 결과물 대신 `<이름>.blocked.json` 보고서만 `--blocked`에 남깁니다.
- 감사 기록과 결과물 쓰기가 **모두 성공했을 때만** 원본을 수신 폴더에서 지웁니다. 실패한 파일은 내용이 바뀌기 전까지 다시 시도하지 않습니다.
- 수신 폴더와 송신·차단 폴더가 서로 포함 관계이면 시작을 거부합니다. 무한 재처리를 막기 위해서입니다.
- Ctrl+C와 SIGTERM을 받으면 진행 중인 주기를 마치고 종료합니다. `--once`로 현재 파일만 처리하고 끝낼 수도 있습니다(cron용).

### 감사 로그와 격리 보관

```bash
cdr sanitize inbox/ -o clean/ --audit-log /var/log/cdr/audit.jsonl --quarantine /srv/cdr/quarantine
```

- **감사 로그(JSONL)**: 처리한 파일마다 한 줄을 추가합니다. 시각(UTC), 이벤트 ID, 출처(파일 경로 또는 클라이언트 IP), 입출력 SHA-256·크기, 상태, 최고 심각도, 탐지 분류, 적용 정책, 처리 시간이 들어갑니다. SIEM 수집에 바로 쓸 수 있습니다.
  ```json
  {"ts":"2026-09-26T08:50:55.673Z","event_id":"d99176fab696be28","source":"/inbox/보고서.docm","filename":"보고서.docm","detected_type":"docx","status":"sanitized","max_severity":"critical","findings":20,"categories":["macro","dde","template-injection",...],"input_sha256":"9236…","output_sha256":"…","quarantine":"2026-09-26/9236….bin","duration_ms":4,"policy":{…}}
  ```
- **격리 보관**: 재조합됐거나 차단된 파일의 **원본**을 `<폴더>/<날짜>/<SHA-256>.bin`에 저장하고, 같은 이름의 `.json`에 보고서를 남깁니다. 실수로 실행되지 않도록 확장자를 `.bin`으로 쓰고, 권한은 파일 0600·폴더 0700입니다. 같은 원본은 한 번만 저장합니다.
- **fail-closed**: 감사 기록에 실패하면 결과물을 내주지 않습니다. CLI는 종료 코드 3, API는 500을 돌려줍니다.

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
cdr serve --bind 0.0.0.0:8080 [--jobs 4] [--timeout 120] [--max-size 100] [--config cdr.toml] \
          [--audit-log audit.jsonl] [--quarantine quarantine/] [--allow-request-relax]
```

| 메서드 | 경로 | 설명 |
|---|---|---|
| `POST` | `/api/v1/sanitize` | multipart `file`을 받아 재조합된 파일을 돌려줍니다. 응답 헤더: `X-CDR-Status`, `X-CDR-Findings`, `X-CDR-Max-Severity`, `X-CDR-Detected-Type`, `X-CDR-Output-SHA256`. 차단되면 **422**와 JSON 보고서를 돌려줍니다. |
| `POST` | `/api/v1/scan` | multipart `file`을 받아 JSON 보고서를 돌려줍니다. |
| `GET` | `/health` | 상태 확인 |
| `GET` | `/` | 브라우저 업로드 페이지 |

요청마다 정책을 **강화하는 방향으로만** 바꿀 수 있습니다: `?rasterize=true&dpi=150&remove_links=true`
서버 정책을 완화하는 요청(`keep_metadata=true`, `neutralize_ole=true`로 기본 차단 해제, `rasterize=false` 등)은 무시합니다. 신뢰할 수 있는 내부 호출자만 있는 환경에서 완화를 허용하려면 `--allow-request-relax`로 서버를 띄우십시오.
감사 로그를 켜면 응답 헤더 `X-CDR-Event-Id`가 로그의 `event_id`와 같아 요청을 추적할 수 있습니다.

```bash
curl -F "file=@invoice.docm" http://localhost:8080/api/v1/sanitize -OJ
curl -F "file=@report.pdf" "http://localhost:8080/api/v1/scan?rasterize=true"
```

재조합 작업은 별도 스레드 풀에서 실행합니다. 동시 업로드 수와 동시 처리 수(세마포어), 요청 크기, 업로드·처리 시간 제한으로 자원 고갈을 막습니다. 처리 슬롯은 작업 스레드가 끝날 때까지 유지되므로, 시간 초과로 응답한 뒤에도 뒤에서 도는 작업이 한도를 넘지 않습니다.

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
├── legacy/
│   ├── cfbx.rs        OLE 복합 파일 안전 읽기 / 새 컨테이너 조립
│   ├── hwp.rs         HWP 5.x (레코드 재구성)
│   ├── doc.rs         Word 97-2003 (FIB 정리, 필드 코드 제자리 무력화)
│   ├── xls.rs         Excel 97-2003 (BIFF 레코드 판정)
│   └── ppt.rs         PowerPoint 97-2003 (동작·링크 제자리 무력화)
├── server.rs          REST API (axum)
├── audit.rs           감사 로그(JSONL)·원본 격리 보관
├── config.rs          정책 파일(TOML)
├── batch.rs           순서 보존 병렬 처리·원자적 결과물 쓰기
├── watch.rs           감시 폴더 모드
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
# 결정적 변조(퍼징) 테스트 반복 횟수 늘리기
CDR_FUZZ_ITERS=2000 cargo test --release --test robustness
```

- `tests/security.rs`: 보안 검토에서 재현된 우회·자원 고갈 사례의 회귀 테스트(PDF 연산자 폭탄·간접 참조 우회·Type3 캐시 우회·JPX, OOXML 노드 예산·전체 압축률, Word/Excel 링크 필드·수식, HWPX Command, XLS HLINK·외부 요청 함수, PPT 상대 경로 링크·비압축 OLE)
- `tests/robustness.rs`: 모든 형식의 샘플을 컨테이너를 풀어 내부 파트 단위로 변조한 뒤, 내부 오류(패닉)가 없고 재조합 결과가 다시 차단되지 않는지 확인

## 한계

- 레거시 형식에서 떼어낼 수 없는 능동 콘텐츠(XLS의 Excel 4.0 매크로 시트, ActiveX 등)는 차단합니다. 임베디드 OLE는 기본값이 차단이며 `--neutralize-ole`로 빈 개체로 대체할 수 있습니다. 필요하면 격리 환경에서 OOXML/HWPX로 변환한 뒤 재조합하십시오.
- XLS에서 VBA 저장소를 빼도 워크북의 VBA 표시 레코드(OBPROJ)는 남습니다(오프셋 보존). 매크로 본체는 없습니다.
- doc/xls/ppt 이미지(Data, Pictures 스트림)와 PDF 글꼴 프로그램은 재인코딩하지 않고 그대로 옮깁니다.
- 검증은 실제 문서와 독립 파서로 했습니다. MS Office와 한컴오피스에서 직접 열어 보는 확인은 하지 않았습니다.
  - HWPX 49종: hwpxlib로 49/49 읽기·쓰기 성공, 본문 텍스트 동일
  - HWP 42종: hwplib로 42/42 읽기·쓰기 성공, 본문 텍스트 동일
  - Apache POI 테스트 문서: xls 366/366, ppt 88/88, doc 121/128 텍스트 동일. doc의 나머지 7건은 조립하지 않은 내장 OLE 개체 안의 텍스트입니다.
- 래스터화 모드는 hayro 렌더러의 지원 범위를 따릅니다(일부 블렌딩/녹아웃 그룹 미지원).
- PDF 글꼴 프로그램(TrueType/CFF)은 구조를 재작성하지 않고 그대로 옮깁니다. 글꼴 파서 취약점까지 막으려면 글꼴 재생성이나 페이지 래스터화 모드를 추가로 고려해야 합니다.
- PDF 인라인 이미지 중 필터가 걸린 것은 파서가 지원하지 않아 제외됩니다.
- Office의 EMF/WMF/SVG 이미지와 GIF 애니메이션(첫 프레임만 남음)은 재조합하지 않습니다.
- 매크로·외부 연결 등 제거되는 기능에 의존하는 업무 문서는 동작이 달라집니다. 원본을 격리 보관하는 정책과 함께 운영하십시오.
