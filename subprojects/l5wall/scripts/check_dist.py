"""Reject L5Wall distribution artifacts that contain secrets or test material."""

from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path

FORBIDDEN = (".pem", ".key", "__pycache__", ".pyc")


def main() -> int:
    dist = Path(sys.argv[1] if len(sys.argv) > 1 else "dist")
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit(f"expected one wheel and one sdist in {dist}")

    with zipfile.ZipFile(wheels[0]) as archive:
        names = archive.namelist()
        if not any(name.endswith("l5wall/py.typed") for name in names):
            raise SystemExit("wheel is missing l5wall/py.typed")
        if any(name.startswith("tests/") for name in names):
            raise SystemExit("wheel contains tests")
        bad = [name for name in names if any(token in name for token in FORBIDDEN)]
        if bad:
            raise SystemExit(f"wheel contains forbidden files: {bad}")

    with tarfile.open(sdists[0]) as archive:
        names = archive.getnames()
        for required in ("LICENSE", "NOTICE"):
            if not any(name.endswith("/" + required) for name in names):
                raise SystemExit(f"sdist is missing {required}")
        if any("/tests/" in name for name in names):
            raise SystemExit("sdist contains tests")
        bad = [name for name in names if any(token in name for token in FORBIDDEN)]
        if bad:
            raise SystemExit(f"sdist contains forbidden files: {bad}")

    print("distribution contents OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
