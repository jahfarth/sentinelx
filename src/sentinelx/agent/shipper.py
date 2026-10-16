"""Log shipper: tail files with rotation handling, batch, POST to the API.

Configuration (YAML):

.. code-block:: yaml

    api_url: http://localhost:8000
    batch_size: 100
    batch_interval_s: 5
    files:
      - path: /var/log/auth.log
        source: auth
      - path: /var/log/nginx/access.log
        source: nginx
"""

import logging
import os
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import yaml

log = logging.getLogger(__name__)


@dataclass
class FileSpec:
    """One tailed file: its path and the normalizer source name."""

    path: str
    source: str


@dataclass
class AgentConfig:
    """Shipper configuration loaded from YAML."""

    api_url: str
    batch_size: int = 100
    batch_interval_s: float = 5.0
    host: str = field(default_factory=socket.gethostname)
    files: list[FileSpec] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, path: str | Path) -> "AgentConfig":
        """Load configuration from a YAML file."""
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        files = [FileSpec(path=f["path"], source=f["source"]) for f in raw.get("files", [])]
        return cls(
            api_url=raw["api_url"],
            batch_size=int(raw.get("batch_size", 100)),
            batch_interval_s=float(raw.get("batch_interval_s", 5.0)),
            host=raw.get("host", socket.gethostname()),
            files=files,
        )


class FileTailer:
    """Tail a file with ``tail -F`` semantics.

    Detects rotation (inode change) and truncation (size shrink) and reopens
    the file so no lines are missed or duplicated across rotations. Starts
    reading from the beginning of the file.
    """

    def __init__(self, path: str | Path) -> None:
        """Open *path* for tailing; a missing file is retried on read."""
        self._path = Path(path)
        self._fh = None
        self._inode: int | None = None
        self._pos = 0
        try:
            self._open()
        except FileNotFoundError:
            log.warning("tail target %s does not exist yet; will retry", self._path)

    def _open(self) -> None:
        if self._fh is not None:
            self._fh.close()
        self._fh = open(self._path, encoding="utf-8", errors="replace")
        self._inode = os.fstat(self._fh.fileno()).st_ino
        self._pos = 0

    def _needs_reopen(self) -> bool:
        try:
            st = self._path.stat()
        except FileNotFoundError:
            return False
        if self._inode is not None and st.st_ino != self._inode:
            log.info(
                "rotation detected for %s (inode %s -> %s)", self._path, self._inode, st.st_ino
            )
            return True
        if st.st_size < self._pos:
            log.info("truncation detected for %s", self._path)
            return True
        return False

    def read_new(self) -> list[str]:
        """Return lines appended since the last call."""
        if self._fh is None:
            try:
                self._open()
            except FileNotFoundError:
                return []
        if self._needs_reopen():
            try:
                self._open()
            except FileNotFoundError:
                return []
        assert self._fh is not None
        self._fh.seek(self._pos)
        lines = self._fh.readlines()
        self._pos = self._fh.tell()
        return [line.rstrip("\n") for line in lines]

    def close(self) -> None:
        """Close the underlying file handle."""
        if self._fh is not None:
            self._fh.close()
            self._fh = None


class Shipper:
    """Batch tailed lines and POST them to the SentinelX ingest endpoint."""

    def __init__(self, config: AgentConfig) -> None:
        """Store *config*; no I/O happens until :meth:`run`."""
        self.config = config

    def send_batch(
        self,
        host: str,
        source: str,
        lines: list[str],
        max_retries: int = 5,
        backoff_base: float = 1.0,
    ) -> bool:
        """POST one batch; retry with exponential backoff on failure.

        Returns ``True`` when the API accepted the batch, ``False`` after
        *max_retries* failed attempts.
        """
        url = self.config.api_url.rstrip("/") + "/api/v1/ingest"
        payload = {"host": host, "source": source, "lines": lines}
        for attempt in range(max_retries + 1):
            try:
                response = httpx.post(url, json=payload, timeout=10.0)
                response.raise_for_status()
                return True
            except Exception as exc:
                if attempt >= max_retries:
                    log.error("dropping batch of %d lines after %d attempts: %s",
                              len(lines), attempt + 1, exc)
                    return False
                delay = backoff_base * (2**attempt)
                log.warning("ingest POST failed (attempt %d/%d): %s; retrying in %.1fs",
                            attempt + 1, max_retries + 1, exc, delay)
                time.sleep(delay)
        return False

    def run(self, max_cycles: int | None = None) -> None:
        """Tail all configured files and ship batches until interrupted.

        *max_cycles* limits the poll loop (used by tests); ``None`` runs
        forever until SIGINT/SIGTERM.
        """
        tailers = [(spec, FileTailer(spec.path)) for spec in self.config.files]
        buffers: dict[tuple[str, str], list[str]] = {}
        last_flush = time.monotonic()
        cycles = 0
        try:
            while max_cycles is None or cycles < max_cycles:
                for spec, tailer in tailers:
                    key = (self.config.host, spec.source)
                    new_lines = tailer.read_new()
                    if new_lines:
                        buffers.setdefault(key, []).extend(new_lines)
                now = time.monotonic()
                interval_elapsed = (now - last_flush) >= self.config.batch_interval_s
                for key in list(buffers):
                    buf = buffers[key]
                    if len(buf) >= self.config.batch_size or (interval_elapsed and buf):
                        host, source = key
                        if self.send_batch(host, source, buf):
                            buffers[key] = []
                        else:
                            log.error("keeping %d unsent lines for %s/%s", len(buf), host, source)
                            buffers[key] = []
                if interval_elapsed:
                    last_flush = now
                cycles += 1
                if max_cycles is None:
                    time.sleep(0.5)
        except KeyboardInterrupt:
            log.info("shipper interrupted")
        finally:
            for _, tailer in tailers:
                tailer.close()
