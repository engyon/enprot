# frozen_string_literal: true
require_relative "../lib/enprot"
require "minitest/autorun"

# Most tests monkey-patch Enprot.process to capture the config
# without needing the FFI loaded.
class EnprotProcessTest < Minitest::Test
  def setup
    @_original_process = Enprot.method(:process)
  end

  def teardown
    Enprot.define_singleton_method(:process, &@_original_process)
  end

  def capture_config
    captured = nil
    Enprot.define_singleton_method(:process) do |cfg|
      captured = cfg
    end
    yield
    captured
  end

  def test_encrypt_builds_correct_config
    cfg = capture_config do
      Enprot.encrypt("/some/file.txt",
                     words: { "SECRET" => "pw" },
                     cipher: "aes-256-siv",
                     casdir: ".cas",
                     policy: "nist")
    end
    assert_equal "encrypt", cfg["operation"]
    assert_equal "/some/file.txt", cfg["file"]
    assert_equal({ "SECRET" => "pw" }, cfg["words"])
    assert_equal "aes-256-siv", cfg["cipher"]
    assert_equal ".cas", cfg["casdir"]
    assert_equal "nist", cfg["policy"]
  end

  def test_decrypt_omits_cipher
    cfg = capture_config do
      Enprot.decrypt("/file", words: { "X" => "y" })
    end
    assert_equal "decrypt", cfg["operation"]
    refute cfg.key?("cipher"), "cipher should be omitted when nil"
    refute cfg.key?("casdir"), "casdir should be omitted when nil"
    refute cfg.key?("policy"), "policy should be omitted when nil"
  end

  def test_store_and_fetch_dispatch
    ops = []
    capture_config do
      Enprot.store("/file", words: { "X" => "y" }, casdir: ".cas")
    end
    cfg_store = capture_config { Enprot.store("/file", casdir: ".cas") }
    cfg_fetch = capture_config { Enprot.fetch("/file", casdir: ".cas") }
    assert_equal "store", cfg_store["operation"]
    assert_equal "fetch", cfg_fetch["operation"]
  end

  def test_process_rejects_non_hash
    assert_raises(ArgumentError) { Enprot.process("not a hash") }
    assert_raises(ArgumentError) { Enprot.process(nil) }
    assert_raises(ArgumentError) { Enprot.process([1, 2, 3]) }
  end
end

# Skipped unless libenprot is on disk (CI without the Rust build
# should not fail the Ruby suite).
class EnprotFfiLiveTest < Minitest::Test
  def setup
    skip "set ENPROT_LIB or build libenprot to enable" unless lib_available?
  end

  def test_version_returns_semver
    v = Enprot.version
    assert_match(/\A\d+\.\d+\.\d+/, v)
  end

  def test_process_rejects_missing_keys
    err = assert_raises(Enprot::EnprotError) { Enprot.process("foo" => "bar") }
    assert_equal Enprot::ERR_INVALID, err.code
    assert_equal "invalid", err.category
  end

  private

  def lib_available?
    return true if ENV["ENPROT_LIB"] && File.exist?(ENV["ENPROT_LIB"])
    repo_root = File.expand_path("../../..", __dir__)
    %w[release debug].any? do |profile|
      libname = case RbConfig::CONFIG["host_os"]
                when /darwin/ then "libenprot.dylib"
                when /mswin|mingw|windows/ then "enprot.dll"
                else "libenprot.so"
                end
      File.exist?(File.join(repo_root, "target", profile, libname))
    end
  end
end
