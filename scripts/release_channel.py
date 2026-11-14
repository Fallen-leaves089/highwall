from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path

PREFIXES = ("v", "l4wall-v", "l5wall-v")
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-(alpha|beta|rc)\.([1-9][0-9]*))?$"
)
LABELS = {
    "alpha": "Alpha",
    "beta": "Beta",
    "rc": "Release Candidate",
    "stable": "Stable",
}


@dataclass(frozen=True)
class ReleaseChannel:
    tag: str
    version: str
    package_version: str
    channel: str
    prerelease: bool
    label: str

    def github_output(self) -> str:
        value = "true" if self.prerelease else "false"
        return "\n".join(
            [
                f"tag={self.tag}",
                f"version={self.version}",
                f"package_version={self.package_version}",
                f"channel={self.channel}",
                f"prerelease={value}",
                f"label={self.label}",
            ]
        ) + "\n"


def package_version(version: str) -> str:
    match = SEMVER.fullmatch(version)
    if match is None:
        raise ValueError(f"invalid release version: {version}")
    base = ".".join(match.group(index) for index in (1, 2, 3))
    prerelease = match.group(5)
    if prerelease is None:
        return base
    tag = {"alpha": "a", "beta": "b", "rc": "rc"}[match.group(4)]
    return f"{base}{tag}{prerelease}"


def classify_release(tag: str, prefix: str) -> ReleaseChannel:
    if prefix not in PREFIXES:
        raise ValueError(f"unsupported tag prefix: {prefix}")
    if not tag.startswith(prefix):
        raise ValueError(f"expected tag prefix {prefix}, got {tag}")
    version = tag[len(prefix) :]
    match = SEMVER.fullmatch(version)
    if match is None:
        raise ValueError(
            f"expected {prefix}<major>.<minor>.<patch>[-alpha.N|-beta.N|-rc.N], got {tag}"
        )
    channel = match.group(4) or "stable"
    return ReleaseChannel(
        tag=tag,
        version=version,
        package_version=package_version(version),
        channel=channel,
        prerelease=channel != "stable",
        label=LABELS[channel],
    )


def write_github_output(path: Path, release: ReleaseChannel) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as output:
        output.write(release.github_output())


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate and classify a release tag")
    parser.add_argument("tag")
    parser.add_argument("--prefix", required=True, choices=PREFIXES)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()

    try:
        release = classify_release(args.tag, args.prefix)
    except ValueError as error:
        raise SystemExit(str(error)) from error

    if args.github_output is not None:
        write_github_output(args.github_output, release)
    else:
        print(release.github_output(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
