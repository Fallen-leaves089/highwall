"""Reject HighWall distribution artifacts that contain secrets or build residue."""

from __future__ import annotations

import argparse
import re
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

FORBIDDEN_SUFFIXES = (".pem", ".key", ".crt", ".der", ".p12", ".pfx")
FORBIDDEN_NAMES = {"audit.jsonl", "config.local.json", ".coverage"}
FORBIDDEN_PARTS = {"__pycache__", ".git", ".runtime", "secrets"}
MAX_MEMBER_BYTES = 50 * 1024 * 1024


def fail(message: str) -> None:
    raise SystemExit(message)


def safe_name(name: str) -> None:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        fail(f"unsafe archive member path: {name}")
    if any(part in FORBIDDEN_PARTS or part.startswith(".runtime") for part in path.parts):
        fail(f"archive contains forbidden path: {name}")
    if path.name in FORBIDDEN_NAMES or path.name.startswith("audit.jsonl"):
        fail(f"archive contains forbidden file: {name}")
    if path.suffix.lower() in FORBIDDEN_SUFFIXES:
        fail(f"archive contains key or certificate material: {name}")
    if "target" in path.parts or any(part.startswith("target-") for part in path.parts):
        fail(f"archive contains Rust build output: {name}")


def check_members(members: list[tuple[str, int]]) -> None:
    for name, size in members:
        safe_name(name)
        if size > MAX_MEMBER_BYTES:
            fail(f"archive member is unexpectedly large: {name} ({size} bytes)")


def metadata_version(text: str) -> str | None:
    match = re.search(r"^Version:\s*(\S+)\s*$", text, flags=re.MULTILINE)
    return match.group(1) if match else None


def check_wheel(path: Path, expected_version: str | None) -> None:
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        check_members([(info.filename, info.file_size) for info in infos])
        required = {
            "highwall/__init__.py",
            "highwall/py.typed",
        }
        missing = sorted(required.difference(names))
        if missing:
            fail(f"wheel is missing required files: {missing}")
        if any(name.startswith(("tests/", "docs/", "scripts/", "deploy/", "subprojects/")) for name in names):
            fail("wheel contains source-only directories")
        metadata_name = next((name for name in names if name.endswith(".dist-info/METADATA")), None)
        if metadata_name is None:
            fail("wheel is missing METADATA")
        version = metadata_version(archive.read(metadata_name).decode("utf-8", errors="replace"))
        if expected_version is not None and version != expected_version:
            fail(f"wheel version is {version!r}, expected {expected_version!r}")


def check_sdist(path: Path, expected_version: str | None) -> None:
    with tarfile.open(path) as archive:
        members = archive.getmembers()
        check_members([(member.name, member.size) for member in members if member.isfile()])
        names = [member.name for member in members if member.isfile()]
        required = {"LICENSE", "NOTICE", "README.md", "pyproject.toml"}
        for name in required:
            if not any(member_name.endswith("/" + name) for member_name in names):
                fail(f"sdist is missing {name}")
        pkg_info = next((name for name in names if name.endswith("/PKG-INFO")), None)
        if pkg_info is None:
            fail("sdist is missing PKG-INFO")
        member = archive.extractfile(pkg_info)
        if member is None:
            fail("sdist PKG-INFO could not be read")
        version = metadata_version(member.read().decode("utf-8", errors="replace"))
        if expected_version is not None and version != expected_version:
            fail(f"sdist version is {version!r}, expected {expected_version!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dist", nargs="?", default="dist")
    parser.add_argument("--version", dest="expected_version")
    args = parser.parse_args()

    dist = Path(args.dist)
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        fail(f"expected exactly one wheel and one sdist in {dist}")

    check_wheel(wheels[0], args.expected_version)
    check_sdist(sdists[0], args.expected_version)
    print("distribution contents OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
