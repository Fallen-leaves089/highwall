#!/usr/bin/env python3
"""Deterministic mutation fuzzing for HighWall's strict parser boundary."""

from __future__ import annotations

import argparse
import random
import string
import sys
import time
import traceback
from pathlib import Path
from typing import Callable

from highwall.config import Config, load_config
from highwall.errors import HighWallError
from highwall.protocol import RequestHead, read_request_head
from highwall.waf import _decode_component, _normalize_target, validate_head

ROOT = Path(__file__).resolve().parents[1]

_REQUEST_SEEDS = (
    b"GET / HTTP/1.1\r\nHost: test.local\r\n\r\n",
    b"HEAD /api/item?id=1 HTTP/1.1\r\nHost: test.local\r\n\r\n",
    b"POST /api/notes HTTP/1.1\r\nHost: test.local\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
    b"GET /%2e%2e/secret HTTP/1.1\r\nHost: test.local\r\n\r\n",
    b"GET /files?name=....//secret HTTP/1.1\r\nHost: test.local\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: test.local\r\nTransfer-Encoding: chunked\r\n\r\n",
)

_TARGET_SEEDS = (
    "/",
    "/ok",
    "/api/item?id=1",
    "/files?name=..",
    "/files?name=%252e%252e%252fsecret",
    "/a;b/../c",
    "/a./",
    "/a%20",
    "/%ff",
    "/a?q=%2e%2e%2f",
    "/a\\b",
    "/a#b",
    "//evil",
    "http://evil/",
)

_TARGET_CHARS = string.ascii_letters + string.digits + "/%\\?#;. _-~[]{}()!$&'+,=:@"


class BytesReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0

    def readline(self, limit: int) -> bytes:
        if self.position >= len(self.data):
            return b""
        end = self.data.find(b"\r\n", self.position)
        if end < 0:
            end = len(self.data)
        else:
            end += 2
        chunk = self.data[self.position : min(end, self.position + max(1, limit))]
        self.position += len(chunk)
        return chunk

    def read(self, length: int) -> bytes:
        chunk = self.data[self.position : self.position + max(0, length)]
        self.position += len(chunk)
        return chunk


def _mutate_bytes(rng: random.Random) -> bytes:
    data = bytearray(rng.choice(_REQUEST_SEEDS))
    for _ in range(rng.randint(1, 8)):
        operation = rng.randrange(4)
        if operation == 0 and data:
            data[rng.randrange(len(data))] = rng.randrange(256)
        elif operation == 1:
            position = rng.randrange(len(data) + 1)
            data[position:position] = rng.randbytes(rng.randint(1, 8))
        elif operation == 2 and data:
            position = rng.randrange(len(data))
            del data[position : position + rng.randint(1, min(8, len(data) - position))]
        else:
            data.extend(rng.choice(_REQUEST_SEEDS))
    return bytes(data)


def _random_target(rng: random.Random) -> str:
    if rng.random() < 0.6:
        target = rng.choice(_TARGET_SEEDS)
    else:
        target = "/" + "".join(rng.choice(_TARGET_CHARS) for _ in range(rng.randint(0, 80)))
    if rng.random() < 0.25:
        position = rng.randrange(len(target) + 1)
        target = target[:position] + rng.choice(("%", "\\", "#", "?", ";", "..", "\x00")) + target[position:]
    return target


def _run_check(name: str, case: str, operation: Callable[[], object]) -> tuple[str, float, str] | None:
    started = time.perf_counter()
    try:
        operation()
    except HighWallError:
        pass
    except Exception:
        return name, time.perf_counter() - started, case + "\n" + traceback.format_exc()
    return None


def fuzz(config: Config, *, iterations: int, seed: int, slow_ms: int) -> int:
    rng = random.Random(seed)
    policy = config.policy
    checks = 0
    slow_cases = 0
    max_case_seconds = 0.0
    unexpected = 0

    for _ in range(iterations):
        request_data = _mutate_bytes(rng)
        target = _random_target(rng)

        cases: tuple[tuple[str, str, Callable[[], object]], ...] = (
            (
                "read_request_head",
                request_data.hex(),
                lambda request_data=request_data: read_request_head(
                    BytesReader(request_data), "127.0.0.1", policy
                ),
            ),
            (
                "_normalize_target",
                repr(target),
                lambda target=target: _normalize_target(target, policy),
            ),
            (
                "_decode_component",
                repr(target),
                lambda target=target: _decode_component(target, policy.reject_encoded_separators, "fuzz"),
            ),
            (
                "validate_head",
                repr(target),
                lambda target=target: validate_head(
                    RequestHead(
                        method="GET",
                        target=target,
                        version="HTTP/1.1",
                        headers=(("Host", "test.local"),),
                        content_length=0,
                        client_ip="127.0.0.1",
                    ),
                    "127.0.0.1",
                    policy,
                ),
            ),
        )

        for name, case, operation in cases:
            checks += 1
            started = time.perf_counter()
            failure = _run_check(name, case, operation)
            elapsed = time.perf_counter() - started
            max_case_seconds = max(max_case_seconds, elapsed)
            if elapsed > slow_ms / 1000.0:
                slow_cases += 1
            if failure is not None:
                unexpected += 1
                failed_name, _, detail = failure
                print(f"UNEXPECTED EXCEPTION in {failed_name}\n{detail}", file=sys.stderr)
                if unexpected >= 5:
                    break
        if unexpected >= 5:
            break

    print(
        "fuzz: "
        f"iterations={iterations} checks={checks} seed={seed} "
        f"max_case_ms={max_case_seconds * 1000:.3f} slow_cases={slow_cases} unexpected={unexpected}"
    )
    return 1 if unexpected else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mutation-fuzz HighWall's parser boundary.")
    parser.add_argument("--iterations", type=int, default=5000, help="number of mutation rounds")
    parser.add_argument("--seed", type=int, default=20261028, help="deterministic random seed")
    parser.add_argument("--slow-ms", type=int, default=50, help="report cases slower than this many milliseconds")
    parser.add_argument("--config", default=str(ROOT / "config.example.json"), help="configuration used for policy parsing")
    args = parser.parse_args(argv)
    if args.iterations < 1:
        parser.error("--iterations must be at least 1")
    if args.slow_ms < 1:
        parser.error("--slow-ms must be at least 1")
    return fuzz(load_config(Path(args.config)), iterations=args.iterations, seed=args.seed, slow_ms=args.slow_ms)


if __name__ == "__main__":
    raise SystemExit(main())
