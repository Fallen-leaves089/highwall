from __future__ import annotations

import argparse
import re
from pathlib import Path

PYTHON_VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:(?:a|b|rc)([1-9][0-9]*))?$"
)
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:alpha|beta|rc)\.([1-9][0-9]*))?$"
)


def _read(path: Path) -> str:
    if not path.is_file():
        raise ValueError(f"file does not exist: {path}")
    with path.open("r", encoding="utf-8", newline="") as source:
        return source.read()


def _write(path: Path, text: str) -> None:
    with path.open("w", encoding="utf-8", newline="") as destination:
        destination.write(text)


def _line_ending(line: str) -> str:
    if line.endswith("\r\n"):
        return "\r\n"
    if line.endswith("\n"):
        return "\n"
    return ""


def _replace_assignment(path: Path, name: str, value: str) -> None:
    text = _read(path)
    pattern = re.compile(rf'^{re.escape(name)} = "[^"\r\n]*"$')
    replacements = 0
    output: list[str] = []
    for line in text.splitlines(keepends=True):
        ending = _line_ending(line)
        content = line[: len(line) - len(ending)] if ending else line
        if pattern.fullmatch(content):
            replacements += 1
            output.append(f'{name} = "{value}"{ending}')
        else:
            output.append(line)
    if replacements != 1:
        raise ValueError(f"expected exactly one {name} assignment in {path}, found {replacements}")
    _write(path, "".join(output))


def set_python_version(version: str, pyproject: Path, module: Path) -> None:
    if PYTHON_VERSION.fullmatch(version) is None:
        raise ValueError(f"not a PEP 440 release version: {version}")
    _replace_assignment(pyproject, "version", version)
    _replace_assignment(module, "__version__", version)


def set_cargo_version(version: str, manifest: Path, lockfile: Path, package: str) -> None:
    if SEMVER.fullmatch(version) is None:
        raise ValueError(f"not a Cargo-compatible release version: {version}")
    _replace_assignment(manifest, "version", version)

    text = _read(lockfile)
    pattern = re.compile(
        rf'(?m)^\[\[package\]\]\r?\nname = "{re.escape(package)}"\r?\nversion = "[^"\r\n]+"\r?\n'
    )
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        raise ValueError(f"expected exactly one {package} package entry in {lockfile}, found {len(matches)}")
    match = matches[0]
    line_ending = "\r\n" if "\r\n" in match.group(0) else "\n"
    replacement = f'[[package]]{line_ending}name = "{package}"{line_ending}version = "{version}"{line_ending}'
    _write(lockfile, text[: match.start()] + replacement + text[match.end() :])


def main() -> int:
    parser = argparse.ArgumentParser(description="Set release versions in a checked-out source tree")
    subparsers = parser.add_subparsers(dest="kind", required=True)

    python_parser = subparsers.add_parser("python")
    python_parser.add_argument("version")
    python_parser.add_argument("--pyproject", type=Path, required=True)
    python_parser.add_argument("--module", type=Path, required=True)

    cargo_parser = subparsers.add_parser("cargo")
    cargo_parser.add_argument("version")
    cargo_parser.add_argument("--manifest", type=Path, required=True)
    cargo_parser.add_argument("--lockfile", type=Path, required=True)
    cargo_parser.add_argument("--package", required=True)

    args = parser.parse_args()
    try:
        if args.kind == "python":
            set_python_version(args.version, args.pyproject, args.module)
        else:
            set_cargo_version(args.version, args.manifest, args.lockfile, args.package)
    except ValueError as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
