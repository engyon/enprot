# frozen_string_literal: true

require "ffi"
require "json"

# Enprot is the top-level namespace for the Ruby bindings to the
# enprot C FFI (libenprot.{so,dylib,dll}).
#
# The shared library is built from the enprot Rust crate:
#
#   cargo build --release
#   # → target/release/libenprot.{so,dylib,dll}
#
# Quick start:
#
#   require "enprot"
#   Enprot.encrypt("config.toml", words: { "SECRET" => "pw" }, casdir: ".cas")
#
module Enprot
  extend FFI::Library

  # Result codes — must match include/enprot.h.
  OK          = 0
  ERR_PARSE   = 1
  ERR_CRYPTO  = 2
  ERR_IO      = 3
  ERR_INVALID = 4

  ERROR_CATEGORY = {
    OK => "ok",
    ERR_PARSE => "parse",
    ERR_CRYPTO => "crypto",
    ERR_IO => "io",
    ERR_INVALID => "invalid",
  }.freeze

  # Mirror the enprot_result_t C struct.
  class EnprotResult < FFI::Struct
    layout :code, :int,
           :error, :pointer
  end

  class << self
    # Locate and load libenprot. Tries the following in order:
    # 1. ENV["ENPROT_LIB"] (absolute path)
    # 2. <repo-root>/target/release/libenprot.{so,dylib,dll}
    # 3. <repo-root>/target/debug/...
    # 4. ffi_find_library via the system loader
    def load_library!
      @load_library ||= begin
        candidates = []

        if ENV["ENPROT_LIB"] && File.exist?(ENV["ENPROT_LIB"])
          candidates << ENV["ENPROT_LIB"]
        end

        libname = case RbConfig::CONFIG["host_os"]
                  when /darwin/ then "libenprot.dylib"
                  when /mswin|mingw|windows/ then "enprot.dll"
                  else "libenprot.so"
                  end

        # bindings/ruby/lib/enprot.rb → repo root = ../../../
        repo_root = File.expand_path("../../..", __dir__)
        %w[release debug].each do |profile|
          path = File.join(repo_root, "target", profile, libname)
          candidates << path if File.exist?(path)
        end

        loaded = candidates.first
        if loaded.nil?
          # Last resort: rely on FFI's name-based lookup.
          begin
            ffi_lib "enprot"
            return
          rescue LoadError
            raise EnprotError,
                  "could not locate #{libname}. Set ENPROT_LIB or run `cargo build --release` from the repo root."
          end
        end

        ffi_lib loaded
      end
    end

    # Once the library is located, attach the FFI functions.
    def attach_ffi!
      load_library!
      attach_function :enprot_process, [:string], EnprotResult.by_value
      attach_function :enprot_version, [], :pointer
      attach_function :enprot_free_error, [:pointer], :void
    end

    # Return the enprot crate version string (e.g. "0.5.11").
    # @return [String]
    def version
      ensure_ffi!
      ptr = enprot_version
      return "" if ptr.null?
      ptr.read_string
    end

    # Invoke enprot_process with a raw config hash.
    # @param config [Hash{String=>Object}]
    # @raise [EnprotError] on any non-OK status.
    def process(config)
      raise ArgumentError, "config must be a Hash" unless config.is_a?(Hash)

      ensure_ffi!
      payload = JSON.generate(config)
      result = enprot_process(payload)
      return if result[:code] == OK

      msg = "(no message)"
      err_ptr = result[:error]
      unless err_ptr.null?
        begin
          msg = err_ptr.read_string
        ensure
          enprot_free_error(err_ptr)
        end
      end

      raise EnprotError.new(result[:code], msg)
    end

    # Encrypt ENCRYPTED segments in place.
    # @param file [String] path to the file to encrypt.
    # @param words [Hash{String=>String}, nil] WORD=password pairs.
    # @param cipher [String, nil] cipher algorithm.
    # @param casdir [String, nil] CAS directory.
    # @param policy [String, nil] crypto policy ('default' or 'nist').
    def encrypt(file, words: nil, cipher: nil, casdir: nil, policy: nil)
      run("encrypt", file, words: words, cipher: cipher, casdir: casdir, policy: policy)
    end

    def decrypt(file, words: nil, cipher: nil, casdir: nil, policy: nil)
      run("decrypt", file, words: words, cipher: cipher, casdir: casdir, policy: policy)
    end

    def store(file, words: nil, casdir: nil, policy: nil)
      run("store", file, words: words, casdir: casdir, policy: policy)
    end

    def fetch(file, words: nil, casdir: nil, policy: nil)
      run("fetch", file, words: words, casdir: casdir, policy: policy)
    end

    private

    def ensure_ffi!
      @ffi_attached ||= begin
        attach_ffi!
        true
      end
    end

    def run(operation, file, words: nil, cipher: nil, casdir: nil, policy: nil)
      config = { "operation" => operation, "file" => file.to_s }
      config["words"] = words if words && !words.empty?
      config["cipher"] = cipher if cipher
      config["casdir"] = casdir if casdir
      config["policy"] = policy if policy
      process(config)
    end
  end

  # Raised when enprot_process returns a non-OK status.
  class EnprotError < StandardError
    attr_reader :code, :category

    def initialize(code, message)
      @code = code
      @category = ERROR_CATEGORY.fetch(code, "unknown")
      super("[enprot #{@category}] #{message}")
    end
  end
end
