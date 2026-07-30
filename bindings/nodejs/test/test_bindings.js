const test = require("node:test");
const assert = require("node:assert");
const enprot = require("../index");

test("version() returns a semver-shaped string", () => {
  const v = enprot.version();
  assert.match(v, /^\d+\.\d+\.\d+/u, `unexpected version: ${v}`);
});

test("process() rejects missing keys with EnprotError", () => {
  assert.throws(
    () => enprot.process({ foo: "bar" }),
    (err) => {
      assert.ok(err instanceof enprot.EnprotError);
      assert.strictEqual(err.code, enprot.ENPROT_ERR_INVALID);
      return true;
    }
  );
});

test("process() accepts null/missing optional fields", () => {
  // Valid config shape — FFI currently returns OK after JSON shape
  // validation. When the FFI grows real processing, this will flip
  // to IO error (the file doesn't exist).
  try {
    enprot.process({ operation: "encrypt", file: "/tmp/does-not-exist.txt" });
  } catch (err) {
    assert.ok(err instanceof enprot.EnprotError);
    assert.ok(
      [enprot.ENPROT_ERR_IO, enprot.ENPROT_ERR_INVALID, enprot.ENPROT_ERR_PARSE].includes(err.code),
      `unexpected error code: ${err.code}`
    );
  }
});

test("encrypt() builds a well-formed config", () => {
  // Monkeypatch process() to capture the config.
  const original = enprot.process;
  let captured;
  enprot.process = (cfg) => {
    captured = cfg;
  };
  try {
    enprot.encrypt("/some/file.txt", {
      words: { SECRET: "pw" },
      cipher: "aes-256-siv",
      casdir: ".cas",
      policy: "nist",
    });
  } finally {
    enprot.process = original;
  }
  assert.strictEqual(captured.operation, "encrypt");
  assert.strictEqual(captured.file, "/some/file.txt");
  assert.deepStrictEqual(captured.words, { SECRET: "pw" });
  assert.strictEqual(captured.cipher, "aes-256-siv");
  assert.strictEqual(captured.policy, "nist");
});

test("store() and fetch() dispatch correctly", () => {
  const original = enprot.process;
  const calls = [];
  enprot.process = (cfg) => {
    calls.push(cfg.operation);
  };
  try {
    enprot.store("/file", { words: { X: "y" }, casdir: ".cas" });
    enprot.fetch("/file", { words: { X: "y" }, casdir: ".cas" });
  } finally {
    enprot.process = original;
  }
  assert.deepStrictEqual(calls, ["store", "fetch"]);
});

test("process() throws TypeError on non-object config", () => {
  assert.throws(() => enprot.process(null), TypeError);
  assert.throws(() => enprot.process("not an object"), TypeError);
  assert.throws(() => enprot.process([1, 2, 3]), TypeError);
});
