"""Agent tests: tailer rotation/truncation, config loading, shipper batching/retry."""

from pathlib import Path

import httpx

from sentinelx.agent.shipper import AgentConfig, FileSpec, FileTailer, Shipper


class _FakeResponse:
    def raise_for_status(self) -> None:
        return None


def test_tailer_reads_appends(tmp_path):
    path = tmp_path / "app.log"
    path.write_text("a1\na2\n")
    tailer = FileTailer(path)
    try:
        assert tailer.read_new() == ["a1", "a2"]
        assert tailer.read_new() == []
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("a3\n")
        assert tailer.read_new() == ["a3"]
    finally:
        tailer.close()


def test_tailer_handles_rotation(tmp_path):
    path = tmp_path / "app.log"
    path.write_text("a1\na2\n")
    tailer = FileTailer(path)
    try:
        assert tailer.read_new() == ["a1", "a2"]
        path.rename(tmp_path / "app.log.1")  # logrotate-style rotation
        path.write_text("b1\n")
        assert tailer.read_new() == ["b1"]
    finally:
        tailer.close()


def test_tailer_handles_truncation(tmp_path):
    path = tmp_path / "app.log"
    path.write_text("a1\na2\n")
    tailer = FileTailer(path)
    try:
        assert tailer.read_new() == ["a1", "a2"]
        path.write_text("c1\n")  # same inode, smaller -> truncation
        assert tailer.read_new() == ["c1"]
    finally:
        tailer.close()


def test_tailer_missing_file_recovers(tmp_path):
    path = tmp_path / "late.log"
    tailer = FileTailer(path)
    try:
        assert tailer.read_new() == []
        path.write_text("hello\n")
        assert tailer.read_new() == ["hello"]
    finally:
        tailer.close()


def test_config_from_yaml(tmp_path):
    cfg = tmp_path / "agent.yml"
    cfg.write_text(
        "api_url: http://x:8000\n"
        "batch_size: 50\n"
        "batch_interval_s: 2.5\n"
        "host: myhost\n"
        "files:\n"
        "  - path: /var/log/auth.log\n"
        "    source: auth\n"
    )
    config = AgentConfig.from_yaml(cfg)
    assert config.api_url == "http://x:8000"
    assert config.batch_size == 50
    assert config.batch_interval_s == 2.5
    assert config.host == "myhost"
    assert config.files == [FileSpec(path="/var/log/auth.log", source="auth")]


def test_send_batch_retries_then_succeeds(monkeypatch):
    calls = []

    def fake_post(url, json=None, timeout=None):
        calls.append((url, json))
        if len(calls) < 3:
            raise httpx.ConnectError("boom")
        return _FakeResponse()

    monkeypatch.setattr(httpx, "post", fake_post)
    shipper = Shipper(AgentConfig(api_url="http://x:8000"))
    assert shipper.send_batch("h", "auth", ["l1"], backoff_base=0.001) is True
    assert len(calls) == 3
    assert calls[0][0] == "http://x:8000/api/v1/ingest"
    assert calls[0][1] == {"host": "h", "source": "auth", "lines": ["l1"]}


def test_send_batch_gives_up(monkeypatch):
    calls = []

    def always_fail(url, json=None, timeout=None):
        calls.append(url)
        raise httpx.ConnectError("down")

    monkeypatch.setattr(httpx, "post", always_fail)
    shipper = Shipper(AgentConfig(api_url="http://x:8000"))
    assert shipper.send_batch("h", "auth", ["l1"], max_retries=2, backoff_base=0.001) is False
    assert len(calls) == 3  # initial attempt + 2 retries


def test_run_batches_and_posts(tmp_path, monkeypatch):
    log_file = tmp_path / "auth.log"
    log_file.write_text("line1\nline2\nline3\n")
    posted = []

    def fake_post(url, json=None, timeout=None):
        posted.append(json)
        return _FakeResponse()

    monkeypatch.setattr(httpx, "post", fake_post)
    config = AgentConfig(
        api_url="http://x:8000",
        batch_size=2,
        batch_interval_s=3600,
        host="h",
        files=[FileSpec(path=str(log_file), source="auth")],
    )
    Shipper(config).run(max_cycles=1)
    assert len(posted) == 1
    assert posted[0] == {"host": "h", "source": "auth", "lines": ["line1", "line2", "line3"]}


def test_main_entrypoint_missing_config():
    # argparse --config is required; the module must at least parse args.
    import os
    import subprocess
    import sys

    repo_root = Path(__file__).resolve().parents[1]
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "PYTHONPATH": str(repo_root / "src")}
    proc = subprocess.run(
        [sys.executable, "-m", "sentinelx.agent"],
        capture_output=True,
        text=True,
        cwd=repo_root,
        env=env,
    )
    assert proc.returncode == 2  # argparse error: --config missing
    assert "--config" in proc.stderr
