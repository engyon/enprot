# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name          = "enprot"
  spec.version       = "0.1.0"
  spec.summary       = "Ruby bindings for enprot — Engyon Protected Text"
  spec.description   = "Ruby (ffi-gem) bindings for the enprot C FFI. Encrypt, decrypt, store, and fetch EPT segments from Ruby."
  spec.authors       = ["Ribose Inc."]
  spec.email         = ["open.source@ribose.com"]
  spec.homepage      = "https://github.com/engyon/enprot"
  spec.license       = "BSD-2-Clause"
  spec.required_ruby_version = ">= 2.7"

  spec.files = Dir["lib/**/*.rb", "README.md", "LICENSE"]
  spec.require_paths = ["lib"]

  spec.add_dependency "ffi", "~> 1.16"

  spec.metadata = {
    "homepage_uri" => spec.homepage,
    "source_code_uri" => "https://github.com/engyon/enprot/tree/main/bindings/ruby",
    "bug_tracker_uri" => "https://github.com/engyon/enprot/issues",
  }
end
