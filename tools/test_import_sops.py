"""Tests for tools/import-sops.py — run with `python3 -m pytest tools/`."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
IMPORT = HERE / "import-sops.py"


def _run(args: list[str], *, expect_rc: int = 0) -> tuple[int, str, str]:
    proc = subprocess.run(
        [sys.executable, str(IMPORT), *args],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == expect_rc, f"rc={proc.returncode} stderr={proc.stderr}"
    return proc.returncode, proc.stdout, proc.stderr


def test_json_input_extracts_encrypted_scalars(tmp_path):
    src = tmp_path / "in.sops.json"
    src.write_text(
        '{"db": {"password": "ENC[AES256_GCM,data:abc123=,iv:xyz=,tag:t=,type:str]", '
        '"host": "db.example.com"}, '
        '"sops": {"kms": [], "mac": "ENC[AES256_GCM,data:mac=,type:str]", "version": "3.9.0"}}',
        encoding="utf-8",
    )
    rc, out, err = _run([str(src)])
    assert "ENCRYPTED sops:db.password" in out
    assert "DATA abc123=" in out
    assert "END sops:db.password" in out
    assert "sops:sops.mac" not in out
    assert "db.host = 'db.example.com'" in out
    assert "scalar is not SOPS-encrypted" in err


def test_yaml_input_requires_pyyaml_or_falls_back(tmp_path):
    src = tmp_path / "in.sops.yaml"
    src.write_text(
        'pw: ENC[AES256_GCM,data:abc,type:str]\n', encoding="utf-8"
    )
    try:
        import yaml  # type: ignore[import-not-found]  # noqa: F401
    except ImportError:
        rc, out, err = _run([str(src)], expect_rc=2)
        assert "PyYAML" in err
        return
    rc, out, _ = _run([str(src)])
    assert "ENCRYPTED sops:pw" in out
    assert "DATA abc" in out


def test_output_to_file(tmp_path):
    src = tmp_path / "in.sops.json"
    src.write_text(
        '{"a": "ENC[AES256_GCM,data:foo=,iv:x=,type:str]"}', encoding="utf-8"
    )
    dst = tmp_path / "out.ept"
    _run([str(src), "-o", str(dst)])
    text = dst.read_text(encoding="utf-8")
    assert "ENCRYPTED sops:a" in text
    assert "DATA foo=" in text


def test_missing_file_errors():
    proc = subprocess.run(
        [sys.executable, str(IMPORT), "/nonexistent/file.sops.json"],
        capture_output=True, text=True,
    )
    assert proc.returncode != 0
    assert "input not found" in proc.stderr.lower() or "no such file" in proc.stderr.lower()


def test_unsupported_extension(tmp_path):
    src = tmp_path / "in.txt"
    src.write_text("hello", encoding="utf-8")
    _run([str(src)], expect_rc=2)
