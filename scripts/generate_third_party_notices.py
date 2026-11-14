from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NOTICES = ROOT / "THIRD_PARTY_NOTICES.md"
MANIFEST = ROOT / "subprojects" / "native-core" / "Cargo.toml"
CONFIG = ROOT / "subprojects" / "native-core" / "about.toml"
TEMPLATE = ROOT / "subprojects" / "native-core" / "about.hbs"


def normalize_notice_text(text: str) -> str:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip(" \t") for line in normalized.split("\n")]
    return "\n".join(lines).rstrip("\n") + "\n"


def generate(output_file: Path) -> None:
    cargo_about = os.environ.get("CARGO_ABOUT")
    command = [cargo_about, "generate"] if cargo_about else ["cargo", "about", "generate"]
    command.extend(
        [
            "--manifest-path",
            str(MANIFEST),
            "--config",
            str(CONFIG),
            "--locked",
            "--offline",
            "--fail",
        ]
    )

    with tempfile.TemporaryDirectory(prefix="highwall-third-party-") as temp_dir:
        raw_output = Path(temp_dir) / "THIRD_PARTY_NOTICES.raw.md"
        subprocess.run(
            [*command, "--output-file", str(raw_output), str(TEMPLATE)],
            cwd=ROOT,
            check=True,
        )
        text = raw_output.read_text(encoding="utf-8")
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_bytes(normalize_notice_text(text).encode("utf-8"))

    print(f"wrote {output_file}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Regenerate THIRD_PARTY_NOTICES.md")
    parser.add_argument("--output-file", type=Path, default=NOTICES)
    args = parser.parse_args()
    generate(args.output_file.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
