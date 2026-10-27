"""Bounded asynchronous webhook alert delivery."""

from __future__ import annotations

import json
import queue
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from typing import Any, Callable

from .metrics import Metrics

_MAX_URL_LENGTH = 2048
_MAX_TOKEN_LENGTH = 512


class AlertConfigurationError(ValueError):
    """Raised when an enabled alert channel is unsafe or incomplete."""


def validate_webhook_url(value: str, *, allow_http: bool = False) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_URL_LENGTH:
        raise AlertConfigurationError("alert webhook URL is empty or too long")
    if any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in value):
        raise AlertConfigurationError("alert webhook URL contains forbidden characters")
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError as exc:
        raise AlertConfigurationError("alert webhook URL is malformed") from exc
    scheme = parsed.scheme.lower()
    if scheme == "https":
        pass
    elif scheme == "http" and allow_http:
        pass
    else:
        raise AlertConfigurationError("alert webhook URL must use HTTPS unless allow_http is enabled")
    if not parsed.hostname:
        raise AlertConfigurationError("alert webhook URL must include a host")
    if parsed.username is not None or parsed.password is not None:
        raise AlertConfigurationError("alert webhook URL must not contain user information")
    if parsed.fragment:
        raise AlertConfigurationError("alert webhook URL must not contain a fragment")
    try:
        parsed.port
    except ValueError as exc:
        raise AlertConfigurationError("alert webhook URL contains an invalid port") from exc
    return value


def validate_alert_token(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    if not 16 <= len(value) <= _MAX_TOKEN_LENGTH:
        raise AlertConfigurationError("alert token must be 16-512 printable ASCII characters")
    if any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in value):
        raise AlertConfigurationError("alert token contains forbidden characters")
    return value


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _default_sender(url: str, token: str | None, payload: dict[str, Any], timeout: float) -> int:
    body = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": "HighWall-Alert/1",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            response.read(4096)
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)


class AlertDispatcher:
    """Send alerts off the request path with bounded memory and retries."""

    def __init__(
        self,
        *,
        url: str | None,
        token: str | None,
        timeout: float,
        max_queue: int,
        cooldown_seconds: float,
        metrics: Metrics,
        sender: Callable[[str, str | None, dict[str, Any], float], int] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.url = url
        self.token = token
        self.timeout = max(0.1, float(timeout))
        self.max_queue = max(1, int(max_queue))
        self.cooldown_seconds = max(1.0, float(cooldown_seconds))
        self.metrics = metrics
        self._sender = sender or _default_sender
        self._clock = clock
        self._queue: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=self.max_queue)
        self._lock = threading.Lock()
        self._cooldowns: OrderedDict[str, float] = OrderedDict()
        self._thread: threading.Thread | None = None
        self.enabled = bool(url)
        if self.enabled:
            self._thread = threading.Thread(target=self._worker, name="highwall-alerts", daemon=True)
            self._thread.start()

    def _mark_sent(self, key: str, now: float) -> bool:
        last = self._cooldowns.get(key)
        if last is not None and now - last < self.cooldown_seconds:
            return False
        self._cooldowns[key] = now
        self._cooldowns.move_to_end(key)
        while len(self._cooldowns) > 4096:
            self._cooldowns.popitem(last=False)
        return True

    def emit(self, payload: dict[str, Any], dedupe_key: str, *, cooldown_seconds: float | None = None) -> bool:
        if not self.enabled or not self.url:
            return False
        now = self._clock()
        with self._lock:
            last = self._cooldowns.get(dedupe_key)
            cooldown = self.cooldown_seconds if cooldown_seconds is None else max(1.0, float(cooldown_seconds))
            if last is not None and now - last < cooldown:
                return False
            try:
                self._queue.put_nowait(payload)
            except queue.Full:
                self.metrics.inc("alert_dropped_total")
                return False
            self._cooldowns[dedupe_key] = now
            self._cooldowns.move_to_end(dedupe_key)
            while len(self._cooldowns) > 4096:
                self._cooldowns.popitem(last=False)
        self.metrics.set("alert_queue_depth", float(self._queue.qsize()))
        return True

    def _worker(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is None:
                    return
                last_error = False
                for attempt in range(2):
                    try:
                        status = self._sender(self.url or "", self.token, item, self.timeout)
                        if 200 <= status < 300:
                            self.metrics.inc("alert_sent_total")
                            last_error = False
                            break
                        last_error = True
                    except Exception:
                        last_error = True
                    if attempt == 0:
                        time.sleep(0.2)
                if last_error:
                    self.metrics.inc("alert_failed_total")
            finally:
                self.metrics.set("alert_queue_depth", float(self._queue.qsize()))
                self._queue.task_done()

    def flush(self, timeout: float = 5.0) -> bool:
        if not self.enabled:
            return True
        done = threading.Event()

        def wait() -> None:
            self._queue.join()
            done.set()

        threading.Thread(target=wait, name="highwall-alert-flush", daemon=True).start()
        return done.wait(timeout)

    def close(self) -> None:
        if self._thread is None:
            return
        try:
            self._queue.put(None, timeout=0.2)
        except queue.Full:
            pass
        self._thread.join(timeout=2.0)
        self._thread = None
