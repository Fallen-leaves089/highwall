from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_proof(
    first: Path,
    second: Path,
    output: Path,
    *,
    version: str,
    target: str,
    rustc_version: str,
) -> dict[str, object]:
    first_hash = sha256(first)
    second_hash = sha256(second)
    if first_hash != second_hash:
        raise ValueError(f"builds are not reproducible: {first_hash} != {second_hash}")
    proof: dict[str, object] = {
        "schema": 1,
        "version": version,
        "target": target,
        "asset": second.name,
        "sha256": second_hash,
        "builds": 2,
        "reproducible": True,
        "source_date_epoch": 0,
        "rustc": rustc_version,
    }
    output.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return proof


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare two clean native builds and write a proof file")
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--second", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--rustc-version", required=True)
    args = parser.parse_args()
    try:
        write_proof(
            args.first,
            args.second,
            args.output,
            version=args.version,
            target=args.target,
            rustc_version=args.rustc_version,
        )
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
