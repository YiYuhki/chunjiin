"""명령행 인터페이스.

사용 예
    cdr sanitize 받은문서.docm -o clean/
    cdr sanitize inbox/ -o clean/ --report report.json
    cdr scan 의심파일.pdf
    cdr serve --port 8080
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .engine import CDREngine
from .policy import Policy
from .report import CDRResult, Status

STATUS_LABEL = {
    Status.CLEAN: "정상",
    Status.SANITIZED: "무해화",
    Status.BLOCKED: "차단",
}


def _iter_inputs(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            files.extend(sorted(f for f in p.rglob("*") if f.is_file()))
        elif p.is_file():
            files.append(p)
        else:
            print(f"경고: 파일을 찾을 수 없음 - {p}", file=sys.stderr)
    return files


def _policy_from_args(args: argparse.Namespace) -> Policy:
    policy = Policy()
    policy.remove_hyperlinks = args.remove_links
    policy.strip_metadata = not args.keep_metadata
    policy.max_file_size = args.max_size * 1024 * 1024
    return policy


def _print_result(r: CDRResult, verbose: bool) -> None:
    label = STATUS_LABEL[r.status]
    extra = f" → {r.output_filename}" if r.output_filename else f" ({r.reason})"
    print(f"[{label}] {r.filename} ({r.detected_type}, 탐지 {len(r.findings)}건){extra}")
    if verbose:
        for f in r.findings:
            loc = f" @ {f.location}" if f.location else ""
            print(f"    - [{f.severity.value}] {f.category}: {f.description}{loc}")


def _run(args: argparse.Namespace, write: bool) -> int:
    engine = CDREngine(_policy_from_args(args))
    files = _iter_inputs(args.inputs)
    if not files:
        print("처리할 파일이 없습니다.", file=sys.stderr)
        return 1

    outdir = Path(args.output) if write else None
    if outdir:
        outdir.mkdir(parents=True, exist_ok=True)

    results = []
    blocked = 0
    for path in files:
        r = engine.process(path.read_bytes(), path.name)
        results.append(r)
        if r.status == Status.BLOCKED:
            blocked += 1
        elif outdir and r.output is not None:
            target = outdir / r.output_filename
            n = 1
            while target.exists() and not args.overwrite:
                target = outdir / f"{Path(r.output_filename).stem}_{n}{Path(r.output_filename).suffix}"
                n += 1
            target.write_bytes(r.output)
        _print_result(r, args.verbose or not write)

    if args.report:
        Path(args.report).write_text(
            json.dumps([r.to_dict() for r in results], ensure_ascii=False, indent=2), encoding="utf-8"
        )

    total = len(results)
    sanitized = sum(r.status == Status.SANITIZED for r in results)
    print(f"\n총 {total}건: 정상 {total - sanitized - blocked}, 무해화 {sanitized}, 차단 {blocked}")
    return 2 if blocked else 0


def _serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError:
        print("API 서버에는 추가 패키지가 필요합니다: pip install 'cdr[api]'", file=sys.stderr)
        return 1
    uvicorn.run("cdr.api:app", host=args.host, port=args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cdr", description="CDR(Content Disarm & Reconstruction) 문서 보안 도구")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("inputs", nargs="+", help="파일 또는 디렉터리")
        p.add_argument("--report", help="JSON 보고서 저장 경로")
        p.add_argument("--remove-links", action="store_true", help="모든 하이퍼링크 제거")
        p.add_argument("--keep-metadata", action="store_true", help="메타데이터 유지")
        p.add_argument("--max-size", type=int, default=100, help="최대 파일 크기(MB, 기본 100)")
        p.add_argument("-v", "--verbose", action="store_true", help="탐지 항목 상세 출력")

    ps = sub.add_parser("sanitize", help="무해화 후 재구성된 파일 저장")
    common(ps)
    ps.add_argument("-o", "--output", required=True, help="출력 디렉터리")
    ps.add_argument("--overwrite", action="store_true", help="같은 이름의 출력 파일 덮어쓰기")

    pa = sub.add_parser("scan", help="파일을 저장하지 않고 분석 결과만 출력")
    common(pa)

    pv = sub.add_parser("serve", help="REST API 서버 실행")
    pv.add_argument("--host", default="127.0.0.1")
    pv.add_argument("--port", type=int, default=8080)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "sanitize":
        return _run(args, write=True)
    if args.command == "scan":
        return _run(args, write=False)
    return _serve(args)


if __name__ == "__main__":
    sys.exit(main())
