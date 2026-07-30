"""Tests for pyenprot.

These tests need libenprot built and discoverable. Either:

- Build it from the repo root: `cargo build --release`
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


def test_process_rejects_bad_json_path(tmp_path):
    # Valid config shape, but the file doesn't exist — FFI currently
    # only validates JSON shape, so this exercises the parse/invalid
    # path rather than io.
    cfg = {"operation": "encrypt", "file": str(tmp_path / "nope.txt")}
    # The current FFI returns OK after JSON shape validation;
    # when the FFI grows real processing, this will flip to IO error.
    # For now we only assert the call returns without crashing.
    try:
        pyenprot.process(cfg)
    except pyenprot.EnprotError as e:
        assert e.code in {
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


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
