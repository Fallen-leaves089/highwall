"""Reject L4Wall distribution artifacts that contain secrets or test material."""

from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path

FORBIDDEN_PARTS = {
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "deploy",
    "docs",
    "scripts",
    "tests",
}
FORBIDDEN_NAMES = {"audit.jsonl", "config.json", "offenders.json"}
FORBIDDEN_SUFFIXES = {".jks", ".key", ".p12", ".pem", ".pfx", ".pyc", ".pyo"}


def _bad_path(name: str, *, allow_egg_info: bool = False) -> bool:
    normalized = name.replace("\\", "/")
    path = Path(normalized)
    if path.name in FORBIDDEN_NAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
        return True
    if not allow_egg_info and "l4wall.egg-info" in normalized:
        return True
    return bool(FORBIDDEN_PARTS.intersection(path.parts))


def _require_basename(names: list[str], required: str, archive: str) -> None:
    if not any(Path(name.replace("\\", "/")).name == required for name in names):
        raise SystemExit(f"{archive} is missing {required}")


def main() -> int:
    dist = Path(sys.argv[1] if len(sys.argv) > 1 else "dist")
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit(f"expected one wheel and one sdist in {dist}")

    with zipfile.ZipFile(wheels[0]) as archive:
        names = archive.namelist()
        if not any(
            Path(name.replace("\\", "/")).parts[:1] == ("l4wall",) and name.endswith("/py.typed")
            for name in names
        ):
            raise SystemExit("wheel is missing l4wall/py.typed")
        for required in ("LICENSE", "NOTICE"):
            _require_basename(names, required, "wheel")
        bad = [name for name in names if _bad_path(name)]
        if bad:
            raise SystemExit(f"wheel contains forbidden files: {bad}")

    with tarfile.open(sdists[0]) as archive:
        names = archive.getnames()
        for required in ("LICENSE", "NOTICE", "config.example.json"):
            _require_basename(names, required, "sdist")
        bad = [name for name in names if _bad_path(name, allow_egg_info=True)]
        if bad:
            raise SystemExit(f"sdist contains forbidden files: {bad}")

    print("distribution contents OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
