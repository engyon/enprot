"""pyenprot — Python bindings for the enprot C FFI.

Loads ``libenprot`` (built as a cdylib from the enprot Rust crate)
and exposes a Pythonic API for encrypting, decrypting, storing, and
fetching Engyon Protected Text segments.

The shared library is discovered in this order:

1. ``$ENPROT_LIB`` env var (absolute path to ``libenprot.so`` /
   ``libenprot.dylib`` / ``enprot.dll``).
2. The directory two levels above this file
   (``target/release`` after ``cargo build --release``).
3. System library search path (``ctypes.util.find_library``).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
import platform
import sys
from pathlib import Path
from typing import Any, Mapping

__all__ = [
    "EnprotError",
    "version",
    "process",
    "encrypt",
    "decrypt",
    "store",
    "fetch",
]

__version__ = "0.1.0"

ENPROT_OK = 0
ENPROT_ERR_PARSE = 1
ENPROT_ERR_CRYPTO = 2
ENPROT_ERR_IO = 3
ENPROT_ERR_INVALID = 4

_ERROR_NAMES = {
    ENPROT_ERR_PARSE: "parse",
    ENPROT_ERR_CRYPTO: "crypto",
    ENPROT_ERR_IO: "io",
    ENPROT_ERR_INVALID: "invalid",
}


class EnprotError(Exception):
    """Raised when enprot returns a non-OK status code."""

    def __init__(self, code: int, message: str) -> None:
        self.code = code
        self.category = _ERROR_NAMES.get(code, "unknown")
        super().__init__(f"[enprot {self.category}] {message}")


class _EnprotResult(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_int),
        ("error", ctypes.c_void_p),
    ]


def _lib_name() -> str:
    system = platform.system()
    if system == "Windows":
        return "enprot.dll"
    if system == "Darwin":
        return "libenprot.dylib"
    return "libenprot.so"


def _find_library() -> ctypes.CDLL:
    candidates: list[Path] = []

    env = os.environ.get("ENPROT_LIB")
    if env:
        candidates.append(Path(env))

    here = Path(__file__).resolve().parent
    repo_root = here.parents[2]
    candidates.append(repo_root / "target" / "release" / _lib_name())
    candidates.append(repo_root / "target" / "debug" / _lib_name())

    for c in candidates:
        if c.is_file():
            return ctypes.CDLL(str(c))

    found = ctypes.util.find_library("enprot")
    if found:
        return ctypes.CDLL(found)

    searched = ", ".join(str(c) for c in candidates)
    raise ImportError(
        f"could not locate {_lib_name()}. Set ENPROT_LIB or build the "
        f"enprot crate with `cargo build --release` (cdylib). Searched: {searched}"
    )


_lib = _find_library()

_lib.enprot_process.restype = _EnprotResult
_lib.enprot_process.argtypes = [ctypes.c_char_p]
_lib.enprot_version.restype = ctypes.c_char_p
_lib.enprot_version.argtypes = []
_lib.enprot_free_error.restype = None
_lib.enprot_free_error.argtypes = [ctypes.c_void_p]


def version() -> str:
    """Return the enprot crate version string (e.g. ``'0.5.11'``)."""
    return ctypes.cast(_lib.enprot_version(), ctypes.c_char_p).value.decode("utf-8")


def process(config: Mapping[str, Any]) -> None:
    """Invoke ``enprot_process`` with a JSON config dict.

    Raises ``EnprotError`` on any non-OK status. The ``config`` mapping
    must include ``operation`` and ``file`` keys; other keys mirror the
    CLI options (``words``, ``cipher``, ``casdir``, ``policy``, …).
    """
    payload = json.dumps(config).encode("utf-8")
    result = _lib.enprot_process(payload)
    if result.code != ENPROT_OK:
        msg = "(no message)"
        if result.error:
            try:
                raw = ctypes.cast(result.error, ctypes.c_char_p).value
                msg = raw.decode("utf-8") if raw else msg
            finally:
                _lib.enprot_free_error(result.error)
        raise EnprotError(result.code, msg)


def _run(operation: str, file: str | os.PathLike[str], **kwargs: Any) -> None:
    config: dict[str, Any] = {"operation": operation, "file": str(file)}
    config.update(kwargs)
    process(config)


def encrypt(
    file: str | os.PathLike[str],
    *,
    words: Mapping[str, str] | None = None,
    cipher: str | None = None,
    casdir: str | os.PathLike[str] | None = None,
    policy: str | None = None,
) -> None:
    """Encrypt ``ENCRYPTED`` segments in *file* in place."""
    _run(
        "encrypt",
        file,
        words=dict(words) if words else None,
        cipher=cipher,
        casdir=str(casdir) if casdir is not None else None,
        policy=policy,
    )


def decrypt(
    file: str | os.PathLike[str],
    *,
    words: Mapping[str, str] | None = None,
    casdir: str | os.PathLike[str] | None = None,
    policy: str | None = None,
) -> None:
    """Decrypt ``ENCRYPTED`` segments in *file* in place."""
    _run(
        "decrypt",
        file,
        words=dict(words) if words else None,
        casdir=str(casdir) if casdir is not None else None,
        policy=policy,
    )


def store(
    file: str | os.PathLike[str],
    *,
    words: Mapping[str, str] | None = None,
    casdir: str | os.PathLike[str] | None = None,
) -> None:
    """Replace ``STORED`` segments in *file* with CAS pointers."""
    _run(
        "store",
        file,
        words=dict(words) if words else None,
        casdir=str(casdir) if casdir is not None else None,
    )


def fetch(
    file: str | os.PathLike[str],
    *,
    words: Mapping[str, str] | None = None,
    casdir: str | os.PathLike[str] | None = None,
) -> None:
    """Restore ``STORED`` segments in *file* from CAS pointers."""
    _run(
        "fetch",
        file,
        words=dict(words) if words else None,
        casdir=str(casdir) if casdir is not None else None,
    )
