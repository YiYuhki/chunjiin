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
| RTF | rtf (`.doc`로 위장한 RTF 포함) | rtf |
| 전자우편 | eml (MIME) | eml — 헤더·본문·첨부를 재조합해 MIME 을 새로 작성 |
| Outlook 메시지 | msg | **eml** — 필요한 속성만 꺼내 표준 메일로 새로 작성 |
| 이미지 | png, jpg/jpeg, gif, bmp | png, jpg, gif, png(BMP) — 픽셀만 재인코딩 |
| 메타파일(벡터 그림) | emf, wmf | emf, wmf — 허용된 그리기 레코드만 새로 작성 |
| SVG | svg (확장자가 .svg 일 때만) | svg — 허용된 요소·속성만 새로 작성 |
| 압축 파일 | zip (한 단계 중첩까지) | zip — 항목마다 재조합, 차단된 항목은 제외 |
| 텍스트·CSV | txt, log, csv, tsv (UTF-8/UTF-16/CP949) | 같은 형식·같은 인코딩 — 제어·양방향 재정의 문자 제거, CSV 수식 주입 무력화 |
| 암호화·DRM·배포용 문서, Word 6/95·PowerPoint 95, 실행 파일, 스크립트(.bat/.vbs/.js/.hta 등), 기타 | — | **차단** |

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
4. 이미지는 픽셀만 디코딩해 새로 인코딩합니다(메타데이터·덧붙은 데이터·폴리글롯 제거). EMF/WMF는 레코드 단위로 재조합하고([메타파일](#메타파일emfwmf)), SVG(Office 2016+의 `asvg:svgBlip`)는 허용 목록으로 다시 쓰며([SVG](#svg)), TIFF 등은 조립하지 않습니다.
5. 차트의 원본 데이터 통합 문서(내장 xlsx)는 **같은 엔진으로 재귀 재조합**해서 보존합니다.
6. `[Content_Types].xml`과 모든 `.rels`는 원본을 쓰지 않고 새로 생성합니다. 매크로·템플릿·쇼 형식은 일반 문서 형식으로 바뀝니다.

### PDF

1. qpdf 계열 파서(lopdf)로 원본을 해석합니다. 암호화 문서(사용자 암호)는 차단하고, 스트림 해제량을 제한합니다.
2. **빈 PDF 문서를 새로 만듭니다.**
3. 각 페이지의 콘텐츠 스트림을 연산자 단위로 파싱합니다. 허용 목록(경로·색·텍스트·이미지·셰이딩 등 표준 그리기 연산자)에 있는 연산자만 다시 인코딩하고, q/Q·BT/ET·BMC/EMC 균형을 보정합니다.
4. 페이지가 쓰는 리소스(글꼴·이미지·그래픽 상태·색공간·패턴·셰이딩)만 옮겨 담습니다. 이때 액션·스크립트·첨부·외부 참조 키는 복사하지 않습니다.
   - 폼 XObject, 타일링 패턴, Type3 글리프의 콘텐츠도 같은 방식으로 재구성합니다. 판정에 쓰는 키(`/Subtype`, `/Filter` 등)가 간접 참조여도 풀어서 판단하고, 같은 객체라도 쓰임(일반/콘텐츠)별로 따로 복사해 캐시를 통한 필터 우회를 막습니다. 글꼴 사전은 정의된 키만 옮깁니다.
   - 콘텐츠 스트림은 해석 전에 토큰 수를 세어 스트림당 400만, 문서 전체 4천만을 넘으면 차단합니다(작은 압축 스트림으로 메모리를 고갈시키는 공격 방어).
   - Flate/LZW/ASCII/RunLength 스트림은 풀어서 다시 압축합니다(필터마다 매개변수가 있는 `DecodeParms` 배열도 필터별로 적용). **이미지 XObject의 JPEG은 화소로 디코딩해 JPEG으로 다시 압축하고, CCITT 팩스 이미지는 1비트 표본으로 풀어 옮깁니다**(원본 코덱 데이터와 뒤에 덧붙은 데이터가 남지 않음). CMYK(Adobe) JPEG은 뷰어마다 반전 규칙이 달라 끝까지 디코딩해 형식을 검증한 뒤 원본을 옮깁니다. 사전의 크기와 JPEG의 실제 크기가 다르면 JPEG의 크기를 씁니다.
   - **인라인 이미지(`BI … ID … EI`)는 직접 해석해 필터 없는 표본으로 다시 씁니다.** ASCIIHex·ASCII85·LZW·Flate·RunLength는 풀고, JPEG(DCT)은 화소로 디코딩하며, CCITT 팩스(G4, G3 1차원·2차원, EOL 유무·바이트 정렬)는 자체 디코더로 1비트 표본으로 풉니다. 리소스 이름·ICCBased·Cal 색 공간은 장치 색 공간으로, Indexed는 기준 색 공간의 8비트 표본으로 펼칩니다. JBIG2·JPX와 Separation·DeviceN·Lab 색 공간의 인라인 이미지는 뺍니다. 데이터 끝(`EI`)은 필터를 풀어 보며 찾되, 후보 수·해제 시도 횟수·표본 크기(이미지당 32MB, 문서당 256MB)에 상한을 둡니다. 연산자 사이의 NUL·폼피드 구분자도 공백으로 바꿔, 그 뒤의 콘텐츠가 잘려 나가지 않게 합니다.
   - pdf.js 테스트 PDF 982건을 이전 버전과 비교했을 때 원본 렌더링과의 차이가 14건 줄었고 늘어난 파일은 없습니다. 인라인 이미지가 든 22건은 모두 MuPDF 렌더링이 원본과 같습니다.
   - **내장 글꼴 프로그램은 다시 만들거나 전 글리프를 검증합니다.**
     - TrueType(FontFile2, TrueType 외곽선 OpenType)과 CFF 기반 OpenType은 새 sfnt로 조립합니다. 힌팅 바이트코드(fpgm·prep·cvt, 글리프별 명령어)와 name·레이아웃·서명 등 나머지 테이블은 버립니다. glyf는 플래그·좌표·복합 구성 요소를 해석한 길이만 옮기고(loca 단조 증가·복합 참조 순환 검사), cmap은 해석한 문자→글리프 대응으로 형식 4/12/13을 새로 만들며, post는 이름 없는 형식 3으로, 나머지는 규격 길이로 잘라 씁니다. 외곽선이 있어야 하는 모든 글리프를 독립 파서(ttf-parser)로 해석해 검증합니다.
     - CFF(Type1C/CIDFontType0C)와 Type 1(FontFile)은 모든 글리프 프로그램(charstring)을 독립 해석기(ttf-parser, read-fonts)로 끝까지 실행해 보고, 하나라도 비정상이면 제외합니다.
     - 글꼴 사전·글꼴 기술자는 정의된 키만 옮겨, 알 수 없는 키로 글꼴 프로그램을 검증 없이 옮기는 우회를 막습니다.
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
   - 조립함: XML 파트(헤더·섹션·설정·차트 등, 허용 네임스페이스로 재구성), 이미지(재인코딩), 메타파일·SVG(재조합), 미리보기
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
| **HWP 5.x** | FileHeader(속성 비트 정리), DocInfo, BodyText, BinData(래스터 이미지 재인코딩, EMF/WMF 재조합), 미리보기 | 문서 스크립트(JScript), **EPS/PostScript**, OLE, DocOptions(연결 문서·DRM·서명), XMLTemplate, 문서 이력. 레코드 재구성으로 외부 파일 연결(BIN_DATA LINK) 경로와 허용되지 않은 하이퍼링크 필드 제거 | 암호, 배포용, DRM, 인증서 암호화 |
| **doc** | WordDocument, 사용 중인 테이블 스트림, Data(그림 제자리 재인코딩·메타파일 제자리 재조합), CompObj | VBA(Macros), ObjectPool(OLE, 미리보기 그림은 유지), 사용하지 않는 테이블 스트림(이전 편집 잔재), MsoDataStore. FIB의 명령 사용자 지정·매크로 이름·**첨부 서식 파일 연결** 제거. 조각 테이블을 따라 **DDE/INCLUDE*/LINK/위험 HYPERLINK 필드 코드를 같은 길이 공백으로 덮어씀** | 암호화, Word 6/95 |
| **xls** | Workbook(그림 제자리 재인코딩·메타파일 제자리 재조합), 피벗 캐시, CompObj | VBA(_VBA_PROJECT_CUR), 사용자 정의 XML, 이전 형식 스트림, 변경 추적 기록. 하이퍼링크(HLINK) 레코드를 구조대로 해석해 허용되지 않은 대상(URL·파일 모니커)만 제자리에서 공백으로 덮어씀(표시 문자열은 유지). `--neutralize-ole` 사용 시 임베디드 OLE(MBD*)를 빈 저장소로 대체 | 암호화, **Excel 4.0 매크로 시트**, VB 모듈 시트, DDE/OLE 링크, ActiveX, 외부 요청 함수(`WEBSERVICE`/`FILTERXML`/`IMAGE`), 임베디드 OLE(기본값) |
| **ppt** | PowerPoint Document, Current User, **Pictures(재조합)**, CompObj | 매크로·프로그램 실행·OLE 동작을 "동작 없음"으로, 위험 하이퍼링크 대상(상대 경로 포함)을 공백으로 바꿈(제자리). 압축 여부와 관계없이 임베디드 개체를 인식. 그림 스트림은 새로 만들고(JPEG/PNG/DIB 재인코딩, EMF/WMF 재조합, PICT·TIFF는 빈 PNG, 그림 목록이 가리키지 않는 데이터 제거, 손상된 그림은 빈 그림으로 대체) 본문 그림 목록(FBSE)의 위치·크기 필드만 제자리에서 고침. `--neutralize-ole` 사용 시 OLE/VBA 저장소를 같은 자리의 빈 OLE 파일로 덮어쓰고 매크로 표시를 끔 | 암호화, ActiveX, PowerPoint 95, 임베디드 OLE/VBA(기본값), 레코드 구조 밖에 숨긴 저장소 |

`--neutralize-ole`은 개체 **내용만** 비웁니다. 슬라이드와 시트에 저장된 미리보기 그림은 그대로 남습니다. PPT는 정상 레코드 트리의 최상위 영구 객체만 덮어쓰고, 전수 검색에서만 발견되는 저장소는 은닉 시도로 보고 차단합니다.
Apache POI 테스트 문서로 확인한 결과는 다음과 같습니다.
- PPT 차단 57→27건, XLS 차단 41→36건으로 줄었습니다.
- 대체한 PPT 내장 개체 229개가 모두 정상 OLE 파일로 해제됐고, 텍스트는 원본과 같습니다.
- Office에서 개체를 활성화했을 때의 동작은 확인하지 못했으므로 기본값은 차단입니다.

PPT의 위험 레코드는 트리 순회에만 의존하지 않습니다. 비정상 컨테이너 속에 숨긴 경우까지 잡도록 **스트림 전체를 레코드 헤더 패턴으로 전수 검색**합니다.

### 전자우편(EML·MSG)

메일 게이트웨이용으로 `.eml`(RFC 5322/MIME) 메일을 재조합합니다.
- 헤더는 발신·수신·제목·날짜·메시지 ID 등 필요한 것만 옮깁니다(X-*, Received 등 경로·추적 정보 제거, 헤더 주입 방지를 위해 줄 접기·제어 문자 정리). 제목은 디코딩한 값을 다시 인코딩합니다.
- 텍스트 본문은 제어·양방향 재정의 문자를 제거합니다.
- HTML 본문은 허용 목록 기반 정제기(ammonia)로 스크립트·이벤트 처리기·폼·iframe·object·`<base>`·`<meta http-equiv>`(refresh 등)를 제거하고, 링크는 허용 스킴만, 이미지는 메일 안 첨부(`cid:`)만 남깁니다(외부 추적 이미지 제거). 인라인 스타일은 외부 자원(`url()`, `@import`)·스크립트 표현식이 없을 때만 남깁니다.
- 첨부는 같은 엔진으로 하나씩 재조합합니다(ZIP과 같은 중첩 제한·해제 예산, 첨부된 메일도 재귀 처리). 차단된 첨부는 빼고 본문 끝에 제거 안내를 덧붙이며, `[archive] strict = true`면 메일 전체를 차단합니다. 인라인 이미지는 재인코딩해 `Content-ID`를 유지합니다.
- 결과는 내용 해시 기반의 결정적 경계 문자열과 base64로 새로 씁니다(첨부된 메일은 규격대로 8bit).
- 서명 메일(S/MIME `multipart/signed`)의 분리 서명은 뺍니다. 내용을 다시 쓰면 원래 서명이 맞지 않기 때문입니다. 암호화된 메일(`application/pkcs7-mime`)은 내용을 검사할 수 없어 해당 첨부를 차단합니다.
- mail-parser 테스트 메일 107건(정상·RFC 예제·형식이 깨진 메일): 106건 재조합(형식이 깨진 1건 차단), 결과를 다시 넣으면 모두 정상, 이름 없는 텍스트 파트까지 본문 텍스트 보존.

**Outlook 메시지(.msg)** 는 OLE 복합 파일에 MAPI 속성을 담은 형식입니다. 필요한 속성만 꺼내 **표준 메일(.eml)로 새로 쓰고**, 본문 정제와 첨부 재조합은 EML과 같은 경로를 탑니다. 확장자가 달라도 내용으로 판별하며, 압축 파일·메일 안의 `.msg`도 `.eml`로 바뀝니다.
- 헤더: 원래 인터넷 헤더(`PR_TRANSPORT_MESSAGE_HEADERS`)가 있으면 그중 필요한 것만, 없으면 발신자·수신자 표·제목·보낸 시각 속성으로 만듭니다. 숨은 참조(Bcc) 수신자는 옮기지 않고, SMTP 주소가 없는 Exchange 내부 주소는 이름만 남깁니다(`이름:;`).
- 본문: HTML → RTF에 감싼 HTML(압축 RTF를 풀어 `\fromhtml1` 복원, Outlook이 흔히 저장하는 형태) → 텍스트 순으로 씁니다. 8비트 문자열은 메시지 코드 페이지, 없으면 메시지 로캘의 코드 페이지로 해석합니다.
- 첨부: 값으로 담긴 파일과 내장 메시지(`.eml` 첨부로 재귀 변환, 8단계까지)만 옮깁니다. 파일 경로·URL을 가리키는 참조 첨부와 OLE 개체 첨부는 빼고 제거 안내를 붙입니다. 서명된 메시지는 안에 든 원래 MIME 메일에서 본문과 첨부를 꺼냅니다.
- 명명 속성, 양식·서명·추적 정보, 전송 경로 헤더 전체 등 나머지 속성은 옮기지 않습니다.
- 스트림을 읽고 압축 RTF를 푼 총량은 파일 크기의 2배 + 16MB로 제한합니다. 여러 스트림이 같은 섹터를 가리키도록 조작한 복합 파일이나 압축 RTF 폭탄(2바이트가 17바이트로 풀림)을 막습니다.
- Apache POI 테스트 메시지 41건: 39건 재조합(구조가 깨진 퍼징 표본 2건 차단). POI로 꺼낸 원본과 비교해 제목·본문·첨부 이름이 같습니다. 다른 경우는 POI가 코드 페이지를 잘못 추정한 키릴·중국어 표본(이 엔진 쪽이 올바르게 해석), 본문 제어 문자 1개 제거, 서명 첨부 1건뿐입니다. 결과를 다시 넣으면 모두 정상이고, 실제 표본을 변조한 1,689건에서 내부 오류가 없었습니다.

### RTF

RTF는 수식 편집기 개체(CVE-2017-11882), OLE 링크(CVE-2017-0199) 등 문서형 악성코드에 가장 많이 쓰이는 형식입니다. 토큰(그룹·제어어·텍스트) 트리로 해석한 뒤 허용된 요소만 새로 직렬화합니다.
- OLE 개체(`\object`)는 조립하지 않고, 개체의 표시용 결과(`\result`)만 남깁니다.
- 알 수 없는 `\*` 목적지 그룹은 버립니다(`\*\datastore`, `\*\template` 외부 서식 파일, `\*\themedata`, 글꼴 내장, 문서 변수, 양식 필드의 매크로 `ffentrymcr`/`ffexitmcr` 등). `\*`는 "모르면 건너뛰라"는 표시라 정상 문서 표시에는 영향이 없고, 목록·각주 구분선·수식·도형·양식 필드 등 서식에 필요한 그룹은 허용 목록으로 남깁니다.
- 그림: PNG/JPEG는 픽셀만 재인코딩하고, 메타파일(EMF/WMF)은 레코드 단위로 재조합합니다. 비트맵·PICT 등 그 밖의 형식은 버립니다.
- 필드: DDE·INCLUDE·LINK, 허용되지 않은 대상(`javascript:`, 로컬 파일 등)의 HYPERLINK는 결과 텍스트만 남깁니다.
- 그림 밖의 이진 데이터(`\bin`), 비정상 제어어(32자 초과, 32비트 범위 밖 매개변수), 문서 끝 뒤 데이터는 버리고, 중첩 깊이 512를 넘으면 차단합니다. 문서 정보(`\info`)는 메타데이터 정책에 따라 뺍니다.
- LibreOffice RTF 테스트 문서 520건: 차단 0건, 추출 텍스트가 원본과 같고(비교 도구가 `\bin`을 처리하지 못하는 1건 제외), 결과물을 다시 넣으면 520건 모두 정상으로 판정됩니다.

### 압축 파일(ZIP)과 단독 이미지

메일 첨부와 망연계 전송에서 흔한 **ZIP 압축 파일은 항목마다 같은 엔진으로 재조합**합니다.
- 각 항목은 형식 판별 → 재조합 → 재검증을 따로 거치고, 결과물만으로 새 압축 파일을 만듭니다(결정적 재압축, 시각 고정). 이름은 결과 형식에 맞게 바뀝니다(`보고서.docm` → `보고서.docx`, 겹치면 번호 부여).
- 차단된 항목(실행 파일, 지원하지 않는 형식, 암호화 문서 등)은 빼고 `archive-member`로 보고합니다. `[archive] strict = true`로 두면 하나라도 차단될 때 압축 파일 전체를 차단합니다.
- 항목의 탐지 내역은 `항목 경로 > 위치` 형태로 보고서에 올라옵니다.
- 압축 안의 압축은 한 단계까지만 풀고, 해제 총량 제한(`max_zip_total_mb`)은 항목 안의 모든 압축 컨테이너(docx·xlsx·hwpx·중첩 ZIP)까지 합산한 예산으로 적용합니다(중첩 Zip bomb 방어). 결과 이름에서 양방향 재정의 문자(RLO 등)를 뺍니다. 암호화 항목과 경로 조작은 기존과 같이 차단합니다.

단독 이미지 파일(PNG/JPEG/GIF/BMP)은 픽셀만 디코딩해 새로 인코딩합니다. 메타데이터·덧붙은 데이터·폴리글롯이 사라지고, BMP는 PNG로, 애니메이션 GIF는 첫 프레임만 남습니다. `[content] allow_images = false`로 끌 수 있습니다(단독 메타파일도 같은 설정을 따릅니다).

### 메타파일(EMF/WMF)

메타파일은 GDI 그리기 명령을 나열한 벡터 그림입니다. 이스케이프 레코드(WMF `SETABORTPROC`, CVE-2005-4560), 범위를 벗어난 개체 번호·좌표 개수, 깨진 비트맵 레코드는 Windows GDI와 여러 렌더러의 취약점 악용 경로로 쓰였습니다. 레코드를 하나씩 해석해 **허용 목록의 그리기 레코드만 검증된 정규형으로 새 메타파일에 다시 씁니다.** 단독 파일뿐 아니라 docx/xlsx/pptx, HWPX, HWP BinData, doc/xls/ppt 그림 저장소(압축을 풀어 재조합한 뒤 다시 압축), RTF 그림(`\emfblip`, `\wmetafile`), 메일 첨부 안의 메타파일에 모두 적용됩니다.
- 머리글은 새로 만듭니다(설명 문자열·픽셀 형식·OpenGL 정보 제거, 크기·레코드 수 재계산, WMF 배치 머리글 검사합 재계산).
- 좌표 배열·다각형 묶음·영역·그라데이션 레코드는 개수와 레코드 크기, 색인 범위가 맞는지 확인하고 선언된 만큼만 옮깁니다. 글자 레코드는 문자열과 글자 간격 배열을 정해진 위치에 다시 배치합니다.
- 개체 번호는 개체 표 범위 안이어야 합니다. WMF는 개체가 비어 있는 가장 낮은 자리를 차지하므로 개체 표를 따라가며 살아 있는 개체만 선택·삭제를 허용하고, 옮길 수 없는 생성 레코드는 빈 브러시로 바꿔 번호가 어긋나지 않게 합니다.
- 비트맵(DIB)은 헤더를 40바이트 정규형으로 바꾸고, 색상표는 선언된 개수만, 화소는 너비·높이·비트 수로 계산한 크기만 옮깁니다(덧붙은 데이터 제거). RLE·JPEG·PNG 압축은 풀어서 무압축으로 씁니다. 화소 수는 문서 단위 예산에 합산합니다.
- 주석(EMF+ 포함)·이스케이프·색 프로필·OpenGL·장치 종속 무늬 브러시·영역 개체 등은 옮기지 않습니다. 형식이 맞지 않아 버린 레코드는 Medium, 주석·이스케이프 등은 Low로 보고합니다.

실제 표본으로 확인한 결과는 다음과 같습니다(메타파일).
- LibreOffice·Apache POI 테스트 메타파일 117건(암호화된 취약점 표본·깨진 머리글 36건 제외)을 LibreOffice로 렌더링해 비교했습니다. 76건은 화소가 같고, 나머지는 EMF+ 레코드를 가진 그림, WMF 이스케이프에 내장된 EMF를 LibreOffice가 우선 그리는 그림, 원래 깨진 퍼징 표본이었습니다.
- POI 테스트 문서의 doc·xls·ppt 70건에 든 메타파일 408개가 재조합 후 모두 POI(HEMF/HWMF)로 해석됩니다. doc/xls 제자리 처리 227개 중 1개만 새 압축이 원래 자리보다 커서 빈 메타파일로 바뀌었습니다.
- POI 테스트 OOXML 31건의 메타파일 60개가 모두 유지되고 POI로 해석됩니다(이전에는 제외).
- 실제 표본을 변조한 3,917건에서 내부 오류가 없었고, 결과물을 다시 넣으면 모두 정상입니다.

### SVG

SVG는 XML로 된 벡터 그림이지만 스크립트(`<script>`, `onload` 등 이벤트 처리기), 외부 자원(`href`, CSS `url()`·`@import`), HTML 삽입(`<foreignObject>`), 애니메이션으로 속성을 바꾸는 우회(`<set attributeName="href">`)를 담을 수 있습니다. XXE를 막는 같은 XML 파서로 해석한 뒤 **허용 목록의 요소·속성만** 새 문서에 다시 씁니다. 단독 `.svg` 파일(확장자가 `.svg`이고 루트가 `<svg>`일 때만), docx/xlsx/pptx의 SVG 그림, HWPX의 SVG, 메일 첨부에 적용됩니다.
- 요소: 도형·경로·글자·그라데이션·무늬·클립·마스크·마커·필터 효과 등 그리기 요소만 옮깁니다. `<script>`, `<foreignObject>`, 애니메이션(`animate`/`set`), 편집기 정보 등 다른 네임스페이스의 요소는 옮기지 않고, 링크(`<a>`)는 풀어 내용만 남깁니다.
- 속성: 표현·기하 속성만 옮기고 이벤트 처리기(`on*`)는 버립니다. 참조(`href`, `url()`)는 문서 안(`#id`)만 허용합니다. `<image>`/`<feImage>`의 내장 래스터 그림(`data:image/...`)은 픽셀만 재인코딩하고, 외부 그림을 가리키는 `<image>`는 옮기지 않습니다.
- CSS(`style` 속성, `<style>`)는 `@import`·`@font-face`·문서 밖 `url()`·`data:`·`expression`·백슬래시 이스케이프(난독화)가 없을 때만 옮깁니다.
- DOCTYPE은 내부 선언(엔터티)이 없을 때만 무시하고, 있으면 차단합니다.
- `<use>`·무늬·마커·`<style>` 규칙의 참조를 펼친 요소 수가 XML 노드 한도(기본 500만)를 넘거나 참조 사슬이 16단계를 넘으면 차단합니다. XML의 billion laughs처럼 작은 파일이 렌더러를 멈추게 하는 구조(`use` 폭탄)를 막습니다. 순환 참조는 렌더러가 그리지 않으므로 세지 않습니다.
- LibreOffice SVG 테스트 파일 135건: 차단 0건, LibreOffice 렌더링이 원본과 모두 같고, 결과물을 다시 넣으면 모두 정상입니다. 실제 파일을 변조한 3,375건에서 내부 오류가 없었습니다.

### 텍스트·CSV

스크립트(.bat/.vbs/.js/.hta 등)도 텍스트이므로 내용만으로 받지 않습니다. **허용 확장자(txt, log, csv, tsv)이면서 문자 인코딩으로 온전히 해석될 때만** 재조합합니다(NUL·실행 파일 서명이 있으면 차단).
- UTF-8(BOM 유무), UTF-16(BOM), CP949/EUC-KR을 판별해 디코딩하고, 같은 인코딩으로 다시 씁니다(한글 CSV가 Excel에서 그대로 열림).
- 제어 문자(탭·줄바꿈 제외)와 양방향 텍스트 재정의·방향 표시 문자(RLO·LRM·RLM·ALM 등 — 표시 순서를 뒤집어 `exe.pdf`처럼 위장)를 제거합니다.
- CSV/TSV: 스프레드시트에서 수식으로 실행될 수 있는 셀(`=`, `@`로 시작하거나, `+`/`-`로 시작하지만 순수한 숫자가 아닌 값, 탭·CR로 시작하는 값 — 앞 공백 뒤 첫 글자, 전각 `＝＋－＠` 포함)에 작은따옴표를 붙여 문자열로 만듭니다. 구분자 추정을 이용한 우회를 막기 위해 쉼표·세미콜론·탭을 모두 셀 경계로 보고 검사합니다. `=cmd|' /C calc'!A0`, `-2+3+cmd|...` 같은 DDE 주입이 실행되지 않습니다. 숫자(`-12.5`, `+1e10`)와 부호만 있는 셀(`-`)은 그대로 둡니다. 따옴표·구분자·줄바꿈 구조는 유지합니다.
- `[content] allow_text = false`로 끌 수 있습니다.

### 공통

- 확장자가 아니라 내용으로 형식을 판별합니다. 확장자 위장은 탐지해서 교정합니다.
- **재검증**: 결과물을 엔진에 한 번 더 넣어, MEDIUM 이상 탐지가 남아 있으면 차단합니다.
- **fail-closed**: 모든 오류와 내부 패닉은 차단으로 처리합니다.
- **재현성**: 같은 입력과 정책이면 결과물은 항상 같은 바이트입니다(OLE 복합 파일의 저장소 시각도 고정). 결과물 해시로 중복 제거와 감사 대조를 할 수 있습니다.

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
├── svg.rs             SVG 허용 목록 재작성
├── mail.rs            메일(EML) 해석 → 헤더·본문 정제, 첨부 재조합 → 새 MIME
├── msg.rs             Outlook 메시지(MSG) 속성 → EML (압축 RTF·감싼 HTML 복원)
├── metafile/
│   ├── emf.rs         EMF 레코드 검증 → 새 메타파일
│   ├── wmf.rs         WMF 레코드 검증(개체 표 추적) → 새 메타파일
│   └── dib.rs         메타파일 안 비트맵 정규화(RLE·JPEG·PNG 해제)
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
│   ├── inline.rs      인라인 이미지 해석 → 필터 없는 표본 (CCITT·JPEG 디코딩, Indexed 펼침)
│   ├── ccitt.rs       CCITT 팩스 디코더 (G4, G3 1·2차원)
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

- `tests/msg.rs`: .msg → .eml 변환(헤더 주입·숨은 참조 제거, 이름만 있는 수신자, HTML 정제, 참조·OLE·실행 첨부 제거 안내, 내장 메시지 재귀, 인라인 그림 재인코딩), RTF에 감싼 HTML 본문, 위장 확장자·압축 파일 안의 .msg, 압축 RTF 폭탄
- `tests/mail.rs`: 메일 헤더 정리·HTML 정제(스크립트·이벤트·추적 이미지·폼)·첨부 재조합·차단 첨부 안내·인라인 이미지
- `tests/metafile.rs`: EMF/WMF 주석·이스케이프·범위 밖 개체·덧붙은 비트맵 데이터 제거, 머리글 재계산, 고정점, docx·RTF·doc 안 메타파일, 개체 생성 폭주
- `tests/svg.rs`: SVG 스크립트·이벤트·외부 참조·CSS·foreignObject·애니메이션 우회 제거, 내장 그림 재인코딩, DOCTYPE 엔터티 차단, `use`·무늬 폭탄과 깊은 참조 사슬 차단, docx `svgBlip`
- `tests/rtf.rs`: RTF OLE 개체(수식 편집기)·외부 서식 파일·숨겨진 데이터·DDE 필드·그림·중첩 깊이·비정상 제어어
- `tests/archive.rs`: ZIP 항목별 재조합·차단 항목 제외·엄격 모드·중첩 깊이·중첩 해제 예산, 단독 이미지
- `tests/pdf_inline.rs`: 이미지 XObject의 JPEG 재압축·CCITT 해제, PDF 인라인 이미지(ASCIIHex+Flate 예측자, JPEG 뒤 덧붙은 데이터, CCITT G4, 리소스 Indexed 색 공간, 공백 값 표본, NUL 구분자, JBIG2 제외, 크기·데이터 부족)
- `tests/security.rs`: 보안 검토에서 재현된 우회·자원 고갈 사례의 회귀 테스트(PDF 연산자 폭탄·간접 참조 우회·Type3 캐시 우회·JPX, OOXML 노드 예산·전체 압축률, Word/Excel 링크 필드·수식, HWPX Command, XLS HLINK·외부 요청 함수, PPT 상대 경로 링크·비압축 OLE)
- `tests/robustness.rs`: 모든 형식의 샘플을 컨테이너를 풀어 내부 파트 단위로 변조한 뒤, 내부 오류(패닉)가 없고 재조합 결과가 다시 차단되지 않는지 확인

## 한계

- 레거시 문서의 그림 레코드와 그림 목록(FBSE)은 레코드 헤더 모양으로 찾습니다. 본문 안에 그림 레코드처럼 보이는 바이트를 일부러 넣으면 그 자리가 재인코딩되어 해당 문서의 표시가 깨질 수 있습니다(공격자 자신의 문서만 손상되며, 원본 바이트가 결과물에 남지는 않습니다).
- 레거시 형식에서 떼어낼 수 없는 능동 콘텐츠(XLS의 Excel 4.0 매크로 시트, ActiveX 등)는 차단합니다. 임베디드 OLE는 기본값이 차단이며 `--neutralize-ole`로 빈 개체로 대체할 수 있습니다. 필요하면 격리 환경에서 OOXML/HWPX로 변환한 뒤 재조합하십시오.
- XLS에서 VBA 저장소를 빼도 워크북의 VBA 표시 레코드(OBPROJ)는 남습니다(오프셋 보존). 매크로 본체는 없습니다.
- doc/xls의 래스터 그림(JPEG/PNG)은 **제자리에서** 재인코딩합니다(xls는 CONTINUE 레코드로 나뉜 그림도 논리 스트림으로 이어 처리). 오프셋이 얽혀 있어 스트림을 다시 쓸 수 없으므로, 새 인코딩을 원래 자리에 쓰고 남는 공간은 0으로 채웁니다(레코드 길이·오프셋 불변). 자리에 맞추기 위해 색상표 PNG(1~8비트), 색 형식 축소(불투명→알파 제거, 무채색→회색조), 행별 적응 필터, JPEG 품질 단계 조정을 차례로 시도하고, 그래도 크면 크기를 단계적으로 줄입니다. 원본은 어떤 경우에도 남기지 않습니다(끝내 들어가지 않으면 자리를 0으로 채움). 문서 단위 누적 화소 예산을 넘으면 차단합니다. POI 테스트 문서에서 doc 그림 92개 중 90개, xls는 한 레코드 안의 그림 60개 중 53개를 재조합했고, 그림 수·형식·크기와 텍스트는 원본과 같았습니다. 메타파일(EMF/WMF)은 레코드 단위로 재조합합니다. PPT의 PICT·TIFF 등 재조합할 수 없는 형식은 빈 PNG로 바꾸고 그림 목록의 형식 값도 맞춥니다. PDF CFF 글꼴은 구조를 새로 쓰지는 않지만 전 글리프를 검증한 뒤 옮깁니다. PPT 래스터 그림은 재조합합니다(POI 테스트 문서 117건에서 그림 수·형식·크기·슬라이드 참조와 텍스트가 원본과 동일, 원본에서도 깨져 있던 PNG 1개만 빈 그림으로 대체).
- 검증은 실제 문서와 독립 파서로 했습니다. MS Office와 한컴오피스에서 직접 열어 보는 확인은 하지 않았습니다.
  - HWPX 49종: hwpxlib로 49/49 읽기·쓰기 성공, 본문 텍스트 동일
  - HWP 42종: hwplib로 42/42 읽기·쓰기 성공, 본문 텍스트 동일
  - Apache POI 테스트 문서: xls 366/366, ppt 88/88, doc 121/128 텍스트 동일. doc의 나머지 7건은 조립하지 않은 내장 OLE 개체 안의 텍스트입니다.
- 래스터화 모드는 hayro 렌더러의 지원 범위를 따릅니다(일부 블렌딩/녹아웃 그룹 미지원).
- PDF TrueType 글꼴은 힌팅을 제거하므로 힌팅을 적용하는 렌더러(PDFium 등)에서 작은 글자의 픽셀 배치가 미세하게 달라질 수 있습니다. 실제 글꼴 177종 재조합 성공, 글꼴 26종 × 2가지 PDF 52건에서 MuPDF 렌더링 화소 동일·텍스트 동일을 확인했습니다. 실제 글꼴 188종(TrueType·CFF OpenType) 재조합과 URW Type 1 글꼴 35종 검증에서 오탐이 없었고, 이를 넣은 PDF 109건(TrueType 52·CFF 22·Type 1 35)에서 MuPDF 렌더링 화소와 텍스트가 원본과 같았습니다(PDFium은 TrueType 힌팅 제거로 작은 글자의 화소만 미세하게 다름). CFF/Type 1 글꼴은 구조를 새로 쓰지 않고 검증 후 옮기므로, 글꼴 파서 취약점까지 원천 차단하려면 페이지 래스터화 모드를 쓰십시오.
- PDF 인라인 이미지 중 JBIG2·JPX 필터와 Separation·DeviceN·Lab 색 공간을 쓰는 것은 제외됩니다. CMYK JPEG은 검증 후 원본 코덱 데이터를 옮깁니다. 다른 JPEG은 다시 압축하므로(품질 92) 화소 값이 미세하게 달라질 수 있습니다.
- GIF 애니메이션은 첫 프레임만 남습니다. SVG는 참조를 펼친 요소 수로 자원 사용을 제한하지만, 큰 필터 영역·흐림 반경처럼 요소 수와 무관하게 렌더링 비용이 큰 속성 값은 제한하지 않습니다.
- 메타파일의 EMF+(GDI+) 레코드는 옮기지 않습니다. Office가 만드는 EMF+는 대부분 GDI 대체 레코드를 함께 담은 이중 형식이라 GDI 레코드로 그려지지만, 안티앨리어싱·그라데이션 등 표현이 조금 달라질 수 있습니다. EMF+로만 그려진 그림은 비어 보일 수 있어 보고서에 표시합니다. WMF 이스케이프에 내장된 EMF, 영역 개체, 장치 종속 무늬 브러시도 옮기지 않습니다.
- doc/xls의 메타파일은 제자리에서 재조합해 다시 압축합니다. 새 압축이 원래 자리보다 크면, 재조합 결과가 원본을 푼 내용과 바이트 단위로 같을 때만 원래 압축 스트림을 두고, 아니면 빈 메타파일로 바꿉니다.
- Outlook 메시지(.msg)는 표준 메일(.eml)로 바뀝니다. 일정·연락처·작업 같은 비메일 항목은 제목·본문·첨부만 남고 항목 고유 정보(일정 시간·참석자 응답 등)는 옮기지 않습니다. 암호화된 S/MIME 메시지는 내용을 검사할 수 없어 해당 첨부를 차단합니다.
- 매크로·외부 연결 등 제거되는 기능에 의존하는 업무 문서는 동작이 달라집니다. 원본을 격리 보관하는 정책과 함께 운영하십시오.
