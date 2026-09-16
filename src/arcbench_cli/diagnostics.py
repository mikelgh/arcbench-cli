"""Optional, private JSONL diagnostics; never record request bodies or headers."""

from __future__ import annotations

import errno
import http.client
import json
import os
import re
import socket
import ssl
import stat
import sys
import urllib.error
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_CREDENTIAL = re.compile(
    r"(?i)(\b(?:authorization|cookie|set-cookie)\s*[:=]\s*)[^\r\n]+"
    r"|((?:[\w-]*(?:api_key|access_key|token|password|secret|session)[\w-]*)"
    r"[\"']?\s*[:=]\s*[\"']?)[^\s,;\"'}]+"
)


def failure_kind(error: BaseException) -> str:
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(reason, TimeoutError) or getattr(reason, "errno", None) == errno.ETIMEDOUT:
        return "timeout"
    if isinstance(reason, socket.gaierror):
        return "dns"
    if isinstance(reason, ssl.SSLError):
        return "tls"
    if isinstance(reason, (ConnectionError, http.client.RemoteDisconnected)):
        return "connection"
    if isinstance(reason, http.client.IncompleteRead):
        return "incomplete_response"
    return "network"


def http_failure_kind(status: int) -> str:
    if status in (401, 403):
        return "authentication"
    if status == 408 or status == 504:
        return "timeout"
    if status == 429:
        return "rate_limit"
    return "http"


class Diagnostics:
    def __init__(self, path: str | None = None) -> None:
        self.path = Path(path).expanduser() if path else None
        self.stream = None
        self.secrets: set[str] = set()

    def remember(self, *values: str) -> None:
        self.secrets.update(value for value in values if value)

    def safe(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {key: self.safe(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.safe(item) for item in value]
        if isinstance(value, str):
            for secret in sorted(self.secrets, key=len, reverse=True):
                value = value.replace(secret, "***")
            value = _CREDENTIAL.sub(lambda match: (match[1] or match[2]) + "***", value)
        return value

    def open(self) -> None:
        if self.path is None:
            return
        flags = (os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NONBLOCK
                 | getattr(os, "O_NOFOLLOW", 0))
        fd = os.open(self.path, flags, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError("diagnostic log must be a regular file")
            os.fchmod(fd, 0o600)
            self.stream = os.fdopen(fd, "a", encoding="utf-8")
        except BaseException:
            os.close(fd)
            raise

    def record(self, event: str, **fields: Any) -> None:
        if self.stream is None:
            return
        record = self.safe({"timestamp": datetime.now(timezone.utc).isoformat(), "event": event, **fields})
        try:
            self.stream.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
            self.stream.flush()
        except OSError:
            # Logging must not turn a completed write into a retryable failure.
            print("[arcbench] diagnostic log write failed; logging disabled", file=sys.stderr, flush=True)
            self.close()

    def close(self) -> None:
        if self.stream is not None:
            try:
                self.stream.close()
            except OSError:
                pass
            self.stream = None


active: ContextVar[Diagnostics | None] = ContextVar("arcbench_diagnostics", default=None)
