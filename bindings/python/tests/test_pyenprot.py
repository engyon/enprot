"""Tests for pyenprot.

These tests need libenprot built and discoverable. Either:

- Build it from the repo root: `cargo build --release --workspace`
- Set `ENPROT_LIB=/path/to/libenprot.so`

Run with: `pytest bindings/python/tests/`
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

import pyenprot


REPO_ROOT = Path(__file__).resolve().parents[3]
SAMPLE = REPO_ROOT / "sample" / "simple.txt"


def test_version_matches_crate():
    v = pyenprot.version()
    assert re.match(r"^\d+\.\d+\.\d+", v), f"unexpected version: {v}"


def test_process_rejects_missing_keys():
    with pytest.raises(pyenprot.EnprotError) as exc:
        pyenprot.process({"foo": "bar"})
    assert exc.value.code == pyenprot.ENPROT_ERR_INVALID


def test_process_missing_file_is_io_error(tmp_path):
    cfg = {"operation": "encrypt", "file": str(tmp_path / "nope.txt"), "words": {"SECRET": "pw"}}
    with pytest.raises(pyenprot.EnprotError) as exc:
        pyenprot.process(cfg)
    assert exc.value.code in {
        pyenprot.ENPROT_ERR_IO,
        pyenprot.ENPROT_ERR_INVALID,
        pyenprot.ENPROT_ERR_PARSE,
    }


def test_encrypt_helper_builds_config(monkeypatch, tmp_path):
    """encrypt() must hand a well-formed config dict to process()."""
    seen = {}

    def fake_process(cfg):
        seen.update(cfg)

    monkeypatch.setattr(pyenprot, "process", fake_process)
    pyenprot.encrypt(
        tmp_path / "f.txt",
        words={"SECRET": "pw"},
        cipher="aes-256-siv",
        casdir=tmp_path / ".cas",
        policy="nist",
    )
    assert seen["operation"] == "encrypt"
    assert seen["file"].endswith("f.txt")
    assert seen["words"] == {"SECRET": "pw"}
    assert seen["cipher"] == "aes-256-siv"
    assert seen["policy"] == "nist"


def test_store_and_fetch_helpers(monkeypatch, tmp_path):
    calls = []

    def fake_process(cfg):
        calls.append(cfg["operation"])

    monkeypatch.setattr(pyenprot, "process", fake_process)
    pyenprot.store(tmp_path / "f.txt", words={"X": "y"}, casdir=".cas")
    pyenprot.fetch(tmp_path / "f.txt", words={"X": "y"}, casdir=".cas")
    assert calls == ["store", "fetch"]


@pytest.mark.skipif(
    not os.environ.get("ENPROT_LIB") and not (REPO_ROOT / "target" / "release").exists(),
    reason="libenprot not built; run `cargo build --release --workspace`",
)
def test_encrypt_decrypt_round_trip(tmp_path):
    """End-to-end: a real file is encrypted then decrypted back to original."""
    file = tmp_path / "round.ept"
    original = (
        "hello, this is a test file\n"
        "// <( BEGIN SECRET )>\n"
        "hunter2\n"
        "// <( END SECRET )>\n"
        "more text after\n"
    )
    file.write_text(original)

    pyenprot.encrypt(file, words={"SECRET": "hunter2"})

    encrypted = file.read_text()
    assert "ENCRYPTED SECRET" in encrypted, f"no ENCRYPTED block in:\n{encrypted}"
    assert "DATA " in encrypted, f"no DATA line in:\n{encrypted}"
    assert "hunter2" not in encrypted, f"plaintext leaked:\n{encrypted}"
    # Text outside the block is preserved.
    assert "hello, this is a test file" in encrypted
    assert "more text after" in encrypted

    pyenprot.decrypt(file, words={"SECRET": "hunter2"})
    decrypted = file.read_text()
    assert decrypted == original, f"round-trip not byte-equal:\n{decrypted}"


@pytest.mark.skipif(
    not os.environ.get("ENPROT_LIB") and not (REPO_ROOT / "target" / "release").exists(),
    reason="libenprot not built",
)
def test_store_fetch_round_trip(tmp_path):
    """End-to-end: store strips plaintext to CAS, fetch restores it."""
    file = tmp_path / "stored.ept"
    cas = tmp_path / "cas"
    cas.mkdir()
    original = (
        "// <( BEGIN SECRET )>\n"
        "top-secret\n"
        "// <( END SECRET )>\n"
    )
    file.write_text(original)

    pyenprot.store(file, words={"SECRET": "ignored"}, casdir=cas)
    stored = file.read_text()
    assert "STORED SECRET" in stored
    assert "top-secret" not in stored
    assert any(cas.iterdir()), "CAS directory is empty"

    pyenprot.fetch(file, words={"SECRET": "ignored"}, casdir=cas)
    fetched = file.read_text()
    assert fetched == original


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
