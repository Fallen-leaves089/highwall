"""Start a child process without inheriting the caller's standard handles."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stdout", required=True)
    parser.add_argument("--stderr", required=True)
    parser.add_argument("--working-dir", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)

    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        parser.error("a command is required after --")

    standard_output = Path(args.stdout)
    standard_error = Path(args.stderr)
    standard_output.parent.mkdir(parents=True, exist_ok=True)
    standard_error.parent.mkdir(parents=True, exist_ok=True)

    creation_flags = 0
    start_new_session = False
    if os.name == "nt":
        creation_flags = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "DETACHED_PROCESS", 0)
        )
    else:
        start_new_session = True

    with standard_output.open("ab", buffering=0) as output_handle, standard_error.open(
        "ab", buffering=0
    ) as error_handle:
        process = subprocess.Popen(
            command,
            cwd=args.working_dir,
            stdin=subprocess.DEVNULL,
            stdout=output_handle,
            stderr=error_handle,
            close_fds=True,
            creationflags=creation_flags,
            start_new_session=start_new_session,
        )

    print(json.dumps({"pid": process.pid}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
