# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-09

### Added
- **Core Platform & Verification Engine**:
  - Deterministic 4-step completion gate (`verify_project`) orchestrating Ruff, Semgrep AST, ESLint, and Pytest.
  - Hardcoded secret scanner (`UNI-SEC-001`) with secret value masking and non-leaking reports.
  - Multi-layer stack detection across 5 primary stacks (`react`, `react-native`, `node-express`, `fastapi`, `spring-boot`, `python-ml`).
  - Dynamic manifest fingerprinting and cache auto-refresh.
  - Rule selector with priority ranking (severity, tier, specificity) and context budget management.
  - Typer-based CLI (`init`, `context`, `standards`, `verify`, `doctor`, `lint-standards`, `approve`, `revoke-approval`, `serve`, `eval`, `install`, `uninstall`).

- **Security & Subprocess Sandbox Core (SEC-01C)**:
  - Multi-dimensional `SandboxCapabilityReport` and fail-closed dispatching engine.
  - `WorkspaceStagingManager` with fresh inode allocation, hardlink decoupling, symlink traversal prevention, and FIFO blocking.
  - `SterileGitExecutor` restricting Git commands to Tier 1 read-only metadata queries with sterile environment overrides.
  - `CommandTrustManager` enforcing SHA-256 approval hashing, environment sanitization, and shell metacharacter rejection.
  - `PathGuard` filesystem barrier preventing directory traversal, `.git` modification, and credential exposure.
  - `<untrusted_project_data>` XML fence neutralization against prompt injection.

- **Enterprise Coding Standards (ECC) Knowledge Subsystem**:
  - Pinned offline snapshot of Everything Claude Code (v2.2.3 @ commit `c05b2d6`) with 10 cryptographic invariants verified offline.
  - 85+ curated native YAML standards across architecture, security, API design, testing, and observability.
  - 6-tier precedence hierarchy with inviolable security governance (project configs cannot disable Tier 1 Security or Tier 3 Core Contract).
  - Task-aware multi-stack knowledge retrieval and cross-stack noise exclusion.

- **Google Antigravity Host Integration**:
  - Full-featured MCP server implementing tools (`initialize_project`, `get_project_context`, `get_standards`, `get_workflow`, `get_rule`, `verify_project`), resources, and prompts over real stdio.
  - Strict JSON-RPC stdout purity and stderr diagnostic routing.
  - Antigravity adapter with one-command idempotent installation, configuration injection (`GEMINI.md`), and byte-for-byte uninstallation.

- **AI Agent Evaluation Harness**:
  - Layer 4 comparative evaluation harness benchmarking AI agents running *with Sarthi* vs *without Sarthi*.
  - Cost and token budget tracking with hard spending ceilings for Claude, GPT-4o, and Gemini models.

- **Documentation & Test Suite**:
  - 180 passing automated test cases across Unit, Integration, and E2E suites.
  - CI matrix testing across Ubuntu, Windows, and macOS on Python 3.11, 3.12, and 3.13.
  - Comprehensive documentation: `README.md`, `ARCHITECTURE.md`, `FEATURES.md`, and `TESTING.md`.
