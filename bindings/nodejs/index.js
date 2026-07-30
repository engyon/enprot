// @engyon/enprot — Node.js bindings for the enprot C FFI.
//
// Loads libenprot.{so,dylib,dll} (built from the enprot Rust crate as a
// cdylib) and exposes a small synchronous API for encrypt, decrypt,
// store, fetch, plus version() and process() (raw JSON config).
//
// Library discovery order:
//   1. process.env.ENPROT_LIB (absolute path to the shared library)
//   2. <repo-root>/target/release/  (after cargo build --release)
//   3. <repo-root>/target/debug/
//   4. system library search path (koffi's name-based lookup)

"use strict";

const path = require("node:path");
const fs = require("node:fs");
const { platform } = require("node:os");
// Node's global `process` is shadowed below by the exported `process()`
// function (the FFI call). Grab it via require() so library discovery
// can still read env vars.
const nodeProcess = require("node:process");

let koffi;
try {
  koffi = require("koffi");
} catch (e) {
  throw new Error(
    "@engyon/enprot requires the 'koffi' package. Run `npm install` in the package directory."
  );
}

const ENPROT_OK = 0;
const ENPROT_ERR_PARSE = 1;
const ENPROT_ERR_CRYPTO = 2;
const ENPROT_ERR_IO = 3;
const ENPROT_ERR_INVALID = 4;

const ERROR_CATEGORY = {
  [ENPROT_ERR_PARSE]: "parse",
  [ENPROT_ERR_CRYPTO]: "crypto",
  [ENPROT_ERR_IO]: "io",
  [ENPROT_ERR_INVALID]: "invalid",
};

class EnprotError extends Error {
  constructor(code, message) {
    super(`[enprot ${ERROR_CATEGORY[code] || "unknown"}] ${message}`);
    this.name = "EnprotError";
    this.code = code;
    this.category = ERROR_CATEGORY[code] || "unknown";
  }
}

function libName() {
  switch (platform()) {
    case "win32":
      return "enprot.dll";
    case "darwin":
      return "libenprot.dylib";
    default:
      return "libenprot.so";
  }
}

function findLibrary() {
  const candidates = [];

  if (nodeProcess.env.ENPROT_LIB) {
    candidates.push(nodeProcess.env.ENPROT_LIB);
  }

  // Walk up from this file looking for a target/ directory. The package
  // ships at <repo>/bindings/nodejs/index.js, so the repo root is two
  // levels up.
  const repoRoot = path.resolve(__dirname, "..", "..");
  candidates.push(path.join(repoRoot, "target", "release", libName()));
  candidates.push(path.join(repoRoot, "target", "debug", libName()));

  for (const c of candidates) {
    if (fs.existsSync(c)) {
      return c;
    }
  }

  // Fall back to system search by short name ("enprot").
  try {
    return koffi.locate("enprot");
  } catch {
    throw new EnprotError(
      ENPROT_ERR_INVALID,
      `could not locate ${libName()}. Set ENPROT_LIB or build the enprot crate with \`cargo build --release\` (cdylib). Searched: ${candidates.join(", ")}`
    );
  }
}

const lib = koffi.load(findLibrary());

const EnprotResult = koffi.struct("EnprotResult", {
  code: "int32",
  error: "void *",
});

const enprot_process = lib.func("enprot_process", EnprotResult, ["str"]);
const enprot_version = lib.func("enprot_version", "str", []);
const enprot_free_error = lib.func("enprot_free_error", "void", ["void *"]);

function processImpl(config) {
  if (config === null || typeof config !== "object" || Array.isArray(config)) {
    throw new TypeError("config must be a plain object");
  }
  const payload = JSON.stringify(config);
  const result = enprot_process(payload);
  if (result.code !== ENPROT_OK) {
    let msg = "(no message)";
    if (result.error) {
      try {
        const buf = koffi.decode(result.error, "char[2048]");
        if (buf) msg = Buffer.from(buf).toString("utf8").split("\0")[0];
      } finally {
        enprot_free_error(result.error);
      }
    }
    throw new EnprotError(result.code, msg);
  }
}

function versionImpl() {
  return enprot_version() || "";
}

function run(operation, file, opts = {}) {
  const config = { operation, file: String(file), ...opts };
  for (const k of Object.keys(config)) {
    if (config[k] === undefined || config[k] === null) delete config[k];
  }
  // Call through `api.process` so tests can monkeypatch it.
  api.process(config);
}

const api = {
  EnprotError,
  ENPROT_OK,
  ENPROT_ERR_PARSE,
  ENPROT_ERR_CRYPTO,
  ENPROT_ERR_IO,
  ENPROT_ERR_INVALID,
  version: versionImpl,
  process: processImpl,
  encrypt(file, opts = {}) {
    run("encrypt", file, opts);
  },
  decrypt(file, opts = {}) {
    run("decrypt", file, opts);
  },
  store(file, opts = {}) {
    run("store", file, opts);
  },
  fetch(file, opts = {}) {
    run("fetch", file, opts);
  },
};

module.exports = api;
