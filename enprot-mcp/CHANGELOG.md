# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/engyon/enprot/compare/enprot-mcp-v0.1.0...enprot-mcp-v0.1.1) - 2026-08-26

### Other

- release

## [0.1.0](https://github.com/engyon/enprot/releases/tag/enprot-mcp-v0.1.0) - 2026-08-25

### Added

- *(mcp)* enprot-mcp server for AI agent integration (TODO 57)

### Other

- *(mcp)* build the enprot binary for the e2e suite — -p enprot-mcp never builds it (not a cargo dependency); and fail e2e hard on JSON-RPC error responses instead of silently asserting on null results.
