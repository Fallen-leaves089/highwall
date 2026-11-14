from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NOTICES = ROOT / "THIRD_PARTY_NOTICES.md"
MANIFEST = ROOT / "subprojects" / "native-core" / "Cargo.toml"
TARGETS = ("x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc")
ROOT_PACKAGE = "highwall-native-core"
BEGIN_MARKER = "<!-- BEGIN THIRD-PARTY CRATES -->"
END_MARKER = "<!-- END THIRD-PARTY CRATES -->"

Crate = tuple[str, str, str]


def normalize_license_expression(expression: str) -> str:
    expression = re.sub(r"\s*\(\*\)\s*$", "", expression.strip())
    expression = re.sub(r"\s*/\s*", " OR ", expression)
    expression = re.sub(r"\s+", " ", expression)
    expression = re.sub(
        r"\b(and|or|with)\b",
        lambda match: match.group(1).upper(),
        expression,
        flags=re.IGNORECASE,
    )
    return expression.strip()


def parse_notice_crates(text: str) -> set[Crate]:
    try:
        section = text.split(BEGIN_MARKER, 1)[1].split(END_MARKER, 1)[0]
    except IndexError as error:
        raise SystemExit(f"missing third-party crate markers in {NOTICES}") from error

    crates: set[Crate] = set()
    for raw_line in section.splitlines():
        line = raw_line.strip()
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if cells[0] in {"Crate", "---"}:
            continue
        if len(cells) != 4:
            raise SystemExit(f"malformed third-party crate row: {raw_line}")
        name, version, license_expression, _source = cells
        crates.add((name, version, normalize_license_expression(license_expression)))
    return crates


def cargo_tree_crates(target: str) -> set[Crate]:
    command = [
        "cargo",
        "tree",
        "--offline",
        "--locked",
        "--manifest-path",
        str(MANIFEST),
        "--target",
        target,
        "--edges",
        "normal,build",
        "--prefix",
        "none",
        "--format",
        "{p}|{l}",
    ]
    result = subprocess.run(command, cwd=ROOT, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip()
        raise SystemExit(f"cargo tree failed for {target}: {message}")

    crates: set[Crate] = set()
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        package_text, separator, license_expression = line.partition("|")
        if not separator:
            continue
        match = re.match(r"^(\S+) v(\S+)", package_text)
        if match is None:
            continue
        name, version = match.groups()
        if name == ROOT_PACKAGE:
            continue
        crates.add((name, version, normalize_license_expression(license_expression)))
    return crates


def main() -> int:
    notice_crates = parse_notice_crates(NOTICES.read_text(encoding="utf-8"))
    runtime_crates: set[Crate] = set()
    for target in TARGETS:
        runtime_crates.update(cargo_tree_crates(target))

    missing = sorted(runtime_crates - notice_crates)
    stale = sorted(notice_crates - runtime_crates)
    if missing or stale:
        if missing:
            print("runtime crates missing from THIRD_PARTY_NOTICES.md:", file=sys.stderr)
            for crate in missing:
                print(f"  {crate[0]} {crate[1]} | {crate[2]}", file=sys.stderr)
        if stale:
            print("stale crates in THIRD_PARTY_NOTICES.md:", file=sys.stderr)
            for crate in stale:
                print(f"  {crate[0]} {crate[1]} | {crate[2]}", file=sys.stderr)
        return 1

    print(f"THIRD_PARTY_NOTICES.md matches {len(runtime_crates)} runtime crates for {len(TARGETS)} targets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
