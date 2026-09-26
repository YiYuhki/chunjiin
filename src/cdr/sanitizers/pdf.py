"""PDF CDR.

qpdf(pikepdf) 로 문서를 파싱·복구한 뒤 능동 콘텐츠를 제거하고, 문서 트리에서
도달 가능한 객체만으로 파일을 새로 작성한다(참조되지 않는 은닉 객체, 증분 업데이트,
파일 끝 덧붙임 데이터가 모두 사라진다).

제거 대상
- JavaScript (문서 이름 트리, OpenAction, 추가 액션 /AA, 폼 필드, 주석)
- Launch / SubmitForm / ImportData / GoToR / GoToE / RichMedia / Rendition / Movie / Sound 액션
- 허용되지 않은 스킴의 URI 액션 (정책에 따라 모든 URI)
- 임베디드 파일, 파일 첨부 주석, 포트폴리오(Collection)
- XFA 폼, RichMedia/3D/Screen/Movie/Sound 주석
- 문서 정보/XMP 메타데이터 (정책)
"""

from __future__ import annotations

import io
from urllib.parse import urlsplit

import pikepdf
from pikepdf import Array, Dictionary, Name, Stream

from ..errors import BlockedError
from ..policy import Policy
from ..report import FindingCollector, Severity

DANGEROUS_ACTIONS: dict[str, tuple[str, Severity, str]] = {
    "/JavaScript": ("javascript", Severity.CRITICAL, "JavaScript 액션"),
    "/Launch": ("launch", Severity.CRITICAL, "외부 프로그램 실행(Launch) 액션"),
    "/SubmitForm": ("data-exfiltration", Severity.HIGH, "폼 데이터 전송(SubmitForm) 액션"),
    "/ImportData": ("external-resource", Severity.HIGH, "외부 데이터 가져오기(ImportData) 액션"),
    "/GoToR": ("external-resource", Severity.MEDIUM, "원격 문서 이동(GoToR) 액션"),
    "/GoToE": ("embedded-file", Severity.MEDIUM, "임베디드 문서 이동(GoToE) 액션"),
    "/RichMediaExecute": ("rich-media", Severity.HIGH, "RichMedia 실행 액션"),
    "/Rendition": ("rich-media", Severity.HIGH, "Rendition 액션"),
    "/Movie": ("rich-media", Severity.MEDIUM, "Movie 액션"),
    "/Sound": ("rich-media", Severity.MEDIUM, "Sound 액션"),
}

DANGEROUS_ANNOTS: dict[str, tuple[str, Severity, str]] = {
    "/FileAttachment": ("embedded-file", Severity.HIGH, "파일 첨부 주석"),
    "/RichMedia": ("rich-media", Severity.HIGH, "RichMedia(Flash 등) 주석"),
    "/Screen": ("rich-media", Severity.MEDIUM, "Screen(멀티미디어) 주석"),
    "/Movie": ("rich-media", Severity.MEDIUM, "Movie 주석"),
    "/Sound": ("rich-media", Severity.MEDIUM, "Sound 주석"),
    "/3D": ("rich-media", Severity.MEDIUM, "3D 주석"),
}


def _is_dict(obj: object) -> bool:
    return isinstance(obj, (Dictionary, Stream))


def _name(obj: object) -> str:
    try:
        return str(obj) if isinstance(obj, Name) else ""
    except Exception:
        return ""


class _PdfSanitizer:
    def __init__(self, pdf: pikepdf.Pdf, policy: Policy, fc: FindingCollector) -> None:
        self.pdf = pdf
        self.policy = policy
        self.fc = fc

    # -- 액션 판별 -----------------------------------------------------------
    def _action_is_dangerous(self, action: object, where: str) -> bool:
        if not _is_dict(action):
            return False
        s = _name(action.get("/S"))
        if s in DANGEROUS_ACTIONS:
            cat, sev, desc = DANGEROUS_ACTIONS[s]
            self.fc.add(cat, sev, f"{desc} 제거", where)
            return True
        if "/JS" in action:
            self.fc.add("javascript", Severity.CRITICAL, "JavaScript 코드(/JS) 제거", where)
            return True
        if s == "/URI":
            uri = str(action.get("/URI", ""))
            scheme = urlsplit(uri.strip()).scheme.lower()
            if scheme not in self.policy.allowed_uri_schemes:
                self.fc.add("dangerous-link", Severity.HIGH, f"허용되지 않은 URI 제거: {uri[:200]}", where)
                return True
            if self.policy.remove_hyperlinks:
                self.fc.add("hyperlink", Severity.LOW, f"URI 제거(정책): {uri[:200]}", where)
                return True
        return False

    def _clean_action_chain(self, holder: object, key: str, where: str) -> None:
        """holder[key] 의 액션(또는 액션 배열)을 검사하고 /Next 체인까지 정리한다."""
        value = holder.get(key)
        if value is None:
            return
        if isinstance(value, Array):
            kept = [a for a in value if not self._action_is_dangerous(a, where)]
            for a in kept:
                if _is_dict(a):
                    self._clean_action_chain(a, "/Next", where)
            if kept:
                holder[key] = Array(kept)
            else:
                del holder[key]
            return
        if self._action_is_dangerous(value, where):
            nxt = value.get("/Next") if _is_dict(value) else None
            del holder[key]
            if nxt is not None:
                holder[key] = nxt
                self._clean_action_chain(holder, key, where)
            return
        if _is_dict(value):
            self._clean_action_chain(value, "/Next", where)

    # -- 문서 수준 ----------------------------------------------------------
    def clean_catalog(self) -> None:
        root = self.pdf.Root
        if "/OpenAction" in root:
            oa = root.OpenAction
            if _is_dict(oa):
                self._clean_action_chain(root, "/OpenAction", "Catalog/OpenAction")
        if "/AA" in root:
            self.fc.add("auto-exec", Severity.HIGH, "문서 추가 액션(/AA) 제거", "Catalog/AA")
            del root["/AA"]

        names = root.get("/Names")
        if _is_dict(names):
            if "/JavaScript" in names:
                self.fc.add("javascript", Severity.CRITICAL, "문서 수준 JavaScript 이름 트리 제거", "Catalog/Names/JavaScript")
                del names["/JavaScript"]
            if "/EmbeddedFiles" in names:
                self.fc.add("embedded-file", Severity.HIGH, "임베디드 파일 제거", "Catalog/Names/EmbeddedFiles")
                del names["/EmbeddedFiles"]
        if "/Collection" in root:
            self.fc.add("embedded-file", Severity.MEDIUM, "PDF 포트폴리오(Collection) 제거", "Catalog/Collection")
            del root["/Collection"]

        acro = root.get("/AcroForm")
        if _is_dict(acro):
            if "/XFA" in acro:
                self.fc.add("xfa", Severity.HIGH, "XFA 폼(스크립트 가능) 제거", "Catalog/AcroForm/XFA")
                del acro["/XFA"]
            if "/NeedsRendering" in root:
                del root["/NeedsRendering"]

        if self.policy.strip_metadata:
            if "/Metadata" in root:
                self.fc.add("metadata", Severity.INFO, "XMP 메타데이터 제거", "Catalog/Metadata")
                del root["/Metadata"]
            if "/Info" in self.pdf.trailer:
                if len(self.pdf.trailer.Info.keys()) > 0:
                    self.fc.add("metadata", Severity.INFO, "문서 정보(작성자 등) 제거", "Trailer/Info")
                del self.pdf.trailer["/Info"]

    # -- 페이지/주석 ----------------------------------------------------------
    def clean_pages(self) -> None:
        for i, page in enumerate(self.pdf.pages, start=1):
            pobj = page.obj
            if "/AA" in pobj:
                self.fc.add("auto-exec", Severity.HIGH, "페이지 추가 액션(/AA) 제거", f"page {i}")
                del pobj["/AA"]
            annots = pobj.get("/Annots")
            if not isinstance(annots, Array):
                continue
            kept = []
            for annot in annots:
                if not _is_dict(annot):
                    continue
                sub = _name(annot.get("/Subtype"))
                if sub in DANGEROUS_ANNOTS:
                    cat, sev, desc = DANGEROUS_ANNOTS[sub]
                    self.fc.add(cat, sev, f"{desc} 제거", f"page {i}")
                    continue
                kept.append(annot)
            pobj["/Annots"] = Array(kept)

    # -- 전체 객체 트리 순회 -----------------------------------------------------
    def clean_all_objects(self) -> None:
        """트레일러부터 도달 가능한 모든 사전을 순회하며 액션/스크립트를 제거한다."""
        seen: set[tuple[int, int]] = set()
        stack: list[object] = [self.pdf.trailer]
        while stack:
            obj = stack.pop()
            if isinstance(obj, (Dictionary, Stream, Array)) and obj.is_indirect:
                og = obj.objgen
                if og in seen:
                    continue
                seen.add(og)
            if isinstance(obj, Array):
                stack.extend(obj)
                continue
            if not _is_dict(obj):
                continue
            where = f"obj {obj.objgen[0]}" if obj.is_indirect else "direct object"
            if "/AA" in obj:
                self.fc.add("auto-exec", Severity.HIGH, "추가 액션(/AA) 제거", where)
                del obj["/AA"]
            for key in ("/A", "/OpenAction", "/PA"):
                if key in obj and _is_dict(obj.get(key)):
                    self._clean_action_chain(obj, key, where)
            if "/JS" in obj:
                self.fc.add("javascript", Severity.CRITICAL, "JavaScript 코드(/JS) 제거", where)
                del obj["/JS"]
                if _name(obj.get("/S")) == "/JavaScript":
                    obj["/S"] = Name("/Named")
                    obj["/N"] = Name("/NextPage")
            if _name(obj.get("/Type")) == "/EmbeddedFile" and isinstance(obj, Stream):
                self.fc.add("embedded-file", Severity.HIGH, "임베디드 파일 스트림 비움", where)
                obj.write(b"")
            if "/EF" in obj:
                self.fc.add("embedded-file", Severity.HIGH, "파일 명세의 임베디드 파일(/EF) 제거", where)
                del obj["/EF"]
            if "/RichMediaContent" in obj:
                del obj["/RichMediaContent"]
            for key in list(obj.keys()):
                if key in ("/Parent", "/P"):
                    continue  # 역참조는 건너뛰어 순회량을 줄인다
                try:
                    stack.append(obj.get(key))
                except Exception:
                    continue


def sanitize_pdf(data: bytes, policy: Policy, fc: FindingCollector) -> bytes:
    try:
        pdf = pikepdf.open(io.BytesIO(data))
    except pikepdf.PasswordError as e:
        raise BlockedError("암호로 보호된 PDF - 내용 검사 불가", "encrypted") from e
    except pikepdf.PdfError as e:
        raise BlockedError(f"PDF 파싱 실패: {e}", "structure") from e

    with pdf:
        if pdf.is_encrypted:
            fc.add("encryption", Severity.INFO, "권한 암호 제거 후 재작성")

        head = data[:1024].find(b"%PDF-")
        if head > 0:
            fc.add("polyglot", Severity.MEDIUM, f"PDF 헤더 앞 {head} bytes 의 데이터 제거", "header")
        tail = data.rstrip(b"\r\n\t \x00")
        if not tail.endswith(b"%%EOF"):
            eof = data.rfind(b"%%EOF")
            if eof != -1 and len(data) - eof > 64:
                fc.add("hidden-data", Severity.MEDIUM, "%%EOF 이후 덧붙은 데이터 제거", "trailer")

        s = _PdfSanitizer(pdf, policy, fc)
        try:
            s.clean_catalog()
            s.clean_pages()
            s.clean_all_objects()
        except BlockedError:
            raise
        except Exception as e:
            raise BlockedError(f"PDF 무해화 중 오류: {e}", "reconstruct") from e

        out = io.BytesIO()
        try:
            pdf.remove_unreferenced_resources()
            pdf.save(
                out,
                encryption=False,
                compress_streams=True,
                object_stream_mode=pikepdf.ObjectStreamMode.generate,
                fix_metadata_version=False,
                deterministic_id=True,
            )
        except Exception as e:
            raise BlockedError(f"PDF 재구성 실패: {e}", "reconstruct") from e
        return out.getvalue()
