# Sarthi

> **Production engineering standards for AI coding agents.**
> Connect once. Your agent plans, writes and verifies code against real engineering standards, from the first line.

**Status:** pre-alpha, design phase (v0.1 in progress) · **License:** MIT · **Python:** 3.11+ · **First-class client:** Google Antigravity · **Others:** via MCP (Cursor, Claude Code, VS Code, Codex) in later releases

> Sarthi is a working name. Check GitHub, PyPI and trademark availability before publishing.

---

## Table of contents

1. [What Sarthi is (and is not)](#1-what-sarthi-is-and-is-not)
2. [The core thesis](#2-the-core-thesis)
3. [How "automatic" actually works](#3-how-automatic-actually-works)
4. [System architecture](#4-system-architecture)
5. [Design principles](#5-design-principles)
6. [Standards model](#6-standards-model-the-actual-product)
7. [Low-level design](#7-low-level-design)
8. [MCP interface contract](#8-mcp-interface-contract)
9. [The verify loop](#9-the-verify-loop)
10. [Antigravity adapter](#10-antigravity-adapter)
11. [CLI reference](#11-cli-reference)
12. [Repository structure](#12-repository-structure)
13. [Security model](#13-security-model)
14. [Testing and evaluation](#14-testing-and-evaluation)
15. [Roadmap and milestones](#15-roadmap-and-milestones)
16. [Open-source launch plan](#16-open-source-launch-plan)
17. [Risks and open questions](#17-risks-and-open-questions)
18. [Credits and licensing](#18-credits-and-licensing)

---

## 1. What Sarthi is (and is not)

**Sarthi is** a local-first system that makes AI coding agents generate production-grade code by default. It does this by:

1. **Detecting** your project's stack and conventions.
2. **Delivering** the right engineering standards to the agent at the right time, within a strict context budget.
3. **Guiding** the agent through a plan, implement, verify workflow.
4. **Verifying** the generated code with deterministic tools (Ruff, Semgrep, linters, tests) and feeding failures back to the agent.

**Sarthi is not:**

- A code-review product (like CodeRabbit). Verification exists to close the generation loop, not to comment on pull requests.
- A coding agent. The IDE's agent writes code. Sarthi supplies the engineering discipline.
- A prompt collection. Standards are structured, versioned, selectable and, where possible, machine-checkable.
- A hosted service. Everything runs locally over stdio. No API keys, no cloud.

---

## 2. The core thesis

Agents write demo-quality code by default because nothing forces production concerns into the loop. Three things change that, in order of impact:

| Lever | What it does | Guarantee |
|---|---|---|
| **Always-loaded instructions** | A small set of hard rules in the agent's context every session | Strong influence, no guarantee |
| **On-demand standards** | Detailed, stack-specific guidance retrieved for the current task | Better inputs, no guarantee |
| **Deterministic verification** | Linters, Semgrep rules and tests run on the output; failures go back to the agent | **The only real guarantee** |

Sarthi's bet: **the combination of a small always-on core, task-specific retrieval and a mandatory verify loop beats either prompts alone or review after the fact.** This is a hypothesis, and [Section 14](#14-testing-and-evaluation) defines how we test it publicly.

Why MCP and not just rule files? Rule files are static. MCP lets Sarthi **detect the stack dynamically**, **load only relevant rules** (a React task never receives Spring Boot rules), **run verification tools**, and keep one source of truth across IDEs.

---

## 3. How "automatic" actually works

The goal is "set up once in Antigravity, works forever." An MCP server alone cannot inject itself into every model request: the client decides when tools are called. Sarthi therefore uses **three delivery channels**, all installed by one command (`sarthi install antigravity`):

| Channel | Mechanism | Role |
|---|---|---|
| **A. MCP server instructions** | The MCP `initialize` response includes an `instructions` string. Compliant clients may add it to the agent's system context at session start. | Primary "MCP-only" path. Contains the ≤ 2,000-token **Core Contract** plus a directive to call `initialize_project` first. |
| **B. Global rule file** | The installer writes a short rule/instruction file into Antigravity's **global** (user-level) rules location, so it applies to every workspace without per-project copying. | Fallback if channel A is not honored. Contains the same Core Contract. |
| **C. Verify loop** | Agent is instructed to run `verify_project` before declaring completion; CI and optional git hooks run the same checks. | Enforcement. Works even if A and B are ignored, because failures are objective. |

> **Verify in Milestone 0 (do not assume):**
> 1. Does Antigravity surface the MCP `instructions` field to the model?
> 2. Where exactly is the global rules file, and what format does it use?
> 3. Which Antigravity hooks or lifecycle events exist that could trigger verification automatically?
>
> The design degrades gracefully: if (1) fails, (2) carries the contract; if both are weak, (3) still catches violations.

### The Core Contract

A fixed block of about 20 rules, always loaded, written as short imperatives. Example shape:

```
SARTHI CORE CONTRACT v1
1. At session start, call sarthi.initialize_project (once per session).
2. Before non-trivial work, call sarthi.get_workflow(task_type) and follow it.
3. Before writing code in a layer, call sarthi.get_standards(task, layers).
4. Never hardcode secrets; read configuration from environment.
5. Validate all external input at the boundary.
6. Keep business logic out of controllers/route handlers/components.
7. Every behavior change ships with tests.
8. Before declaring done, call sarthi.verify_project and fix all failures at severity >= high.
...
```

The Core Contract is hard-capped by a **context budget** ([Section 7.4](#74-context-budget-manager)) so it never dilutes agent attention.

---

## 4. System architecture

```
┌──────────────────────────────────────────────────────────────┐
│  AI CODING CLIENT   Antigravity (v0.1) · Cursor · Claude Code │
│                     VS Code · Codex (later)                   │
└───────────────┬──────────────────────────────┬───────────────┘
                │ stdio (MCP)                   │ files written by installer
                ▼                               ▼
┌───────────────────────────────┐   ┌──────────────────────────┐
│  MCP INTERFACE (thin)          │   │  CLIENT ADAPTERS          │
│  tools · resources · prompts   │   │  antigravity/ (v0.1)      │
│  server `instructions`         │   │  cursor/ claude/ ... (later)
└───────────────┬───────────────┘   └─────────────┬────────────┘
                │ calls                            │ calls
                ▼                                  ▼
┌──────────────────────────────────────────────────────────────┐
│  SARTHI CORE  (pure Python, no MCP or IDE imports)         │
│                                                              │
│  StackDetector   ContextBuilder   RuleSelector               │
│  WorkflowEngine  BudgetManager    Verifier (+ runners)       │
│  ConfigLoader    PathGuard        Reporter                   │
└───────────────┬──────────────────────────────┬───────────────┘
                │ reads                         │ executes (allowlisted)
                ▼                               ▼
┌───────────────────────────────┐   ┌──────────────────────────┐
│  STANDARDS LIBRARY             │   │  VERIFICATION TOOLS       │
│  YAML rules · MD workflows     │   │  ruff · semgrep · pytest  │
│  layers: universal, security,  │   │  eslint · tsc · mvn/gradle│
│  testing, react, fastapi, ...  │   │  (project-local installs) │
└───────────────────────────────┘   └──────────────────────────┘
```

**Rule of the architecture:** the MCP layer and the CLI are both thin wrappers over `sarthi.core`. If you delete the MCP layer, `sarthi verify .` must still work.

---

## 5. Design principles

1. **Standards are data, not code.** Contributors add a YAML file, not Python.
2. **Verifiable beats aspirational.** Every rule declares how it is verified (a Semgrep rule, a lint rule, a test pattern or an explicit checklist item). Rules with no verifier are tagged `guidance` and carry lower weight.
3. **Small context, high adherence.** Budget the tokens. Retrieve, don't dump.
4. **Deterministic core.** No LLM calls inside Sarthi. Same input gives the same output.
5. **Read-only by default.** Analysis never writes. Command execution is allowlisted, bounded to the project root and time-limited.
6. **Client-neutral core, client-specific adapters.**
7. **Explainable.** Every rule delivered or violated has an ID, rationale and example.
8. **Measurable.** If we cannot show an A/B improvement, we do not ship the claim.

---

## 6. Standards model (the actual product)

The quality of this library *is* the product. Generic advice ("validate input") is already in the model's head. Value comes from **specific, opinionated, checkable** rules with good and bad examples.

### 6.1 Composable layers

Stacks are **compositions of layers**, not monolithic profiles. This avoids a combinatorial explosion of `react-fastapi`, `react-node` and so on.

| Layer kind | v0.1 layers |
|---|---|
| Cross-cutting | `universal`, `security`, `testing`, `api-design`, `observability` |
| Frontend | `react`, `react-native` |
| Backend | `node-express`, `fastapi`, `spring-boot` |
| Data / ML | `python-ml` |
| Database (v0.2) | `postgres`, `mongodb` |

A **profile** is a named composition in `standards/profiles/*.yaml`:

```yaml
# standards/profiles/react-fastapi.yaml
id: react-fastapi
layers: [universal, security, testing, api-design, react, fastapi]
```

Shipped profiles in v0.1: `react-node`, `react-fastapi`, `java-springboot`, `python-ml`, `react-native`.

### 6.2 Depth tiers (answering "all five stacks, shallower rules")

Covering five stacks in v0.1 is ambitious, so depth is explicit and honest:

| Tier | Meaning | v0.1 target per stack |
|---|---|---|
| **core** | Always-on, in the Core Contract (cross-cutting only) | ~20 rules total |
| **standard** | Retrieved on demand for a relevant task | ≥ 12 rules per stack layer |
| **reference** | Longer patterns, examples, templates | Added post-v0.1 |

**Quality bar per stack layer for v0.1:** at least 12 rules, of which **at least 5 are machine-verifiable**. A stack that does not meet the bar ships labeled `experimental` in the docs.

#### Layer Quality & Stability Status in v0.1

*(Dynamically generated via `python scripts/count_rules.py` and validated by `sarthi lint-standards --summary`)*

| Layer / Stack | Total Rules | Machine Verifiers | Status in v0.1 |
|---|---|---|---|
| `universal` | 4 | 2 (1 Secrets, 1 Ruff) | **Cross-cutting** |
| `security` | 3 | 1 (Semgrep) | **Cross-cutting** |
| `testing` | 2 | 0 (guidance / checklist) | **Cross-cutting** |
| `api-design` | 2 | 0 (guidance / checklist) | **Cross-cutting** |
| `observability` | 1 | 0 (guidance / checklist) | **Cross-cutting** |
| `react` | 12 | 6 (ESLint) | **Stable** |
| `fastapi` | 13 | 3 (1 Semgrep, 2 Ruff) | **Experimental** (missing 2 verifiers) |
| `node-express` | 12 | 2 (ESLint) | **Experimental** (missing 3 verifiers) |
| `react-native` | 12 | 2 (ESLint) | **Experimental** (missing 3 verifiers) |
| `spring-boot` | 12 | 0 (guidance / checklist) | **Experimental** (missing 5 verifiers) |
| `python-ml` | 12 | 1 (Ruff) | **Experimental** (missing 4 verifiers) |

### 6.3 Rule schema

```yaml
# standards/fastapi/layering.yaml
- id: FAPI-ARCH-001
  title: Route handlers must not contain business logic or DB access
  layer: fastapi
  category: architecture        # architecture|security|testing|api|data|perf|ops
  severity: high                # critical|high|medium|low
  tier: standard                # core|standard|reference
  applies_when:                 # selection predicates (AND)
    layers: [fastapi]
    tasks: [feature, refactor, new-project]
  rule: >
    Route handlers parse input, call a service function, and map the result
    to a response. Business logic lives in `services/`; persistence in
    `repositories/`.
  rationale: >
    Keeps logic testable without HTTP, prevents duplicated queries.
  good: |
    @router.post("/users")
    async def create(body: UserCreate, svc: UserService = Depends(get_user_service)):
        return await svc.create(body)
  bad: |
    @router.post("/users")
    async def create(body: UserCreate, db: Session = Depends(get_db)):
        db.add(User(**body.dict())); db.commit()
  verify:
    type: semgrep               # semgrep|ruff|eslint|command|pytest-marker|checklist
    ref: verifiers/semgrep/fastapi-no-db-in-routes.yaml
  tags: [layering, testability]
  since: 0.1.0
```

Validated by Pydantic at load time. Invalid rules fail `sarthi lint-standards` (and CI).

### 6.4 Workflows

Workflows are Markdown with YAML front matter, one per task type: `new-project`, `feature`, `bugfix`, `refactor`. Each defines steps the agent must follow and **which MCP calls belong at which step**.

```markdown
---
id: feature
requires_tools: [get_standards, verify_project]
---
## 1. Plan
State the change, affected layers, and files. Call get_standards(task, layers).
## 2. Design check
Confirm the change respects the architecture rules returned.
## 3. Implement
Smallest coherent change. Tests alongside code.
## 4. Verify
Call verify_project(scope="changed"). Fix every failure ≥ high. Re-run until clean.
## 5. Report
Summarize what changed, what was verified, what remains.
```

---

## 7. Low-level design

All modules live in `src/sarthi/core/` and import nothing from `sarthi.mcp` or `sarthi.adapters`.

### 7.1 StackDetector

**Input:** project root. **Output:** `StackProfile`.

```python
class StackProfile(BaseModel):
    root: Path
    layers: list[DetectedLayer]       # e.g. react@18.x, fastapi@0.11x
    languages: list[str]
    package_managers: list[str]
    test_frameworks: list[str]
    confidence: dict[str, float]      # per-layer 0..1
    evidence: dict[str, list[str]]    # file/dependency that triggered each layer
    suggested_profile: str | None
```

**Detection signals (pluggable `Detector` classes, one per layer):**

| Layer | Signals |
|---|---|
| react | `package.json` has `react`; `.jsx/.tsx` files |
| react-native | `react-native` or `expo` dependency; `app.json`/`metro.config.js` |
| node-express | `express`/`fastify`/`nestjs` in dependencies; `server.(js|ts)` |
| fastapi | `fastapi` in `pyproject.toml`/`requirements*.txt`; `FastAPI(` in source |
| spring-boot | `spring-boot-starter` in `pom.xml`/`build.gradle` |
| python-ml | `torch`, `tensorflow`, `scikit-learn`, notebooks, `mlflow` |

Rules: monorepo-aware (scan up to depth N, skip `node_modules`, `.venv`, `.git`, build dirs), output includes **evidence** so the agent and user can see why. Low confidence (< 0.6) triggers a "confirm with user" flag instead of guessing. User override in `.sarthi/project.yaml` always wins.

### 7.2 ConfigLoader

Reads `.sarthi/project.yaml`, merged over defaults.

```yaml
# .sarthi/project.yaml
version: 1
project:
  name: my-app
profile: react-fastapi            # optional; auto-detected if omitted
layers:
  add: [observability]
  remove: []
generation:
  require_plan: true
  require_tests: true
verify:
  fail_on: high                   # critical|high|medium|low
  commands:                       # project-defined, allowlisted extras
    test: "pytest -q"
    lint: "ruff check ."
rules:
  disable: []                     # rule IDs, require a reason below
  overrides:
    - id: FAPI-ARCH-001
      severity: medium
      reason: "Legacy module, migrating in Q3"
```

Note: `permissions` is deliberately **not** a Sarthi setting. The IDE owns permissions; Sarthi only bounds its own execution.

### 7.3 RuleSelector

Selection pipeline:

1. Resolve layers (detected ∪ config.add − config.remove).
2. Filter rules where `applies_when.layers ⊆ active layers` and the task type matches.
3. Apply user overrides/disables.
4. Rank by `severity`, then `tier`, then specificity (more specific layer wins on conflicts).
5. Hand ranked list to the BudgetManager.

**Conflict resolution:** if two rules from different layers conflict, the more specific layer (`fastapi` over `universal`) wins; conflicts are declared via `supersedes: [rule_ids]` in the schema and checked by `lint-standards`.

### 7.4 Context budget manager

Prevents rule dumps from reducing adherence.

| Payload | Token budget (default) |
|---|---|
| Core Contract (always-on) | ≤ 2,000 |
| `initialize_project` response | ≤ 1,500 |
| `get_standards` response | ≤ 3,000, 15 rules max |
| `get_workflow` response | ≤ 1,200 |

Over-budget results are truncated by rank and include a `truncated: true` field plus "ask for more via `get_rule(id)` or narrower `layers`." Token estimate uses a cheap approximation (chars / 4) in v0.1; a real tokenizer is optional later.

### 7.5 ContextBuilder and persistence

Writes derived state to `.sarthi/` (git-ignored except `project.yaml`):

```
.sarthi/
├── project.yaml          # user-owned, committed
└── cache/
    ├── stack.json        # last detection result
    ├── fingerprint.json  # hashes of manifest files
    └── context.md        # rendered context for humans
```

**Refresh logic:** `fingerprint.json` stores hashes of manifests (`package.json`, `pyproject.toml`, `pom.xml`, lockfiles, `project.yaml`). `get_project_context` compares the current hashes; on mismatch it re-detects and bumps `context_version`. This answers "keep context consistent": versioned and cheap to check, with no daemon.

### 7.6 WorkflowEngine

Loads workflow Markdown, validates `requires_tools`, and returns the workflow **rendered with the active layers** (for example, the "Verify" step lists the actual commands for this project).

### 7.7 Verifier

See [Section 9](#9-the-verify-loop).

### 7.8 PathGuard

Every filesystem access in core goes through `PathGuard`:

- Resolve to a real path (follow symlinks), require it inside the declared project root.
- Deny `..` escapes, absolute paths outside root, and symlinks leaving root.
- Deny reading known secret files by default (`.env`, `*.pem`, `id_rsa*`) unless explicitly allowed.
- Cap file read size.

---

## 8. MCP interface contract

**Transport:** stdio. **SDK:** official MCP Python SDK (pin the version; verify the current API in Milestone 0, since the SDK is evolving). **Server `instructions`:** the Core Contract.

### 8.1 Tools (v0.1: six)

| Tool | Input | Output (summary) |
|---|---|---|
| `initialize_project` | `root: str`, `force: bool=false` | `StackProfile`, active layers, `context_version`, Core Contract summary, next-step hint |
| `get_project_context` | `root: str` | Cached context + staleness check; auto-refreshes if manifests changed |
| `get_standards` | `root`, `task: str`, `task_type?`, `layers?`, `max_rules?` | Ranked rules (id, title, severity, rule, good/bad, verify ref) within budget; `truncated` flag |
| `get_workflow` | `root`, `task_type: feature\|bugfix\|refactor\|new-project` | Rendered workflow with project-specific commands |
| `get_rule` | `rule_id: str` | Full rule: rationale, examples, verifier |
| `verify_project` | `root`, `scope: changed\|all`, `checks?: [...]` | Structured `VerifyReport` ([Section 9](#9-the-verify-loop)) |

All tools: `root` is validated by PathGuard; outputs are JSON-serializable Pydantic models; errors are structured (`code`, `message`, `hint`), never stack traces.

### 8.2 Resources

| URI | Content |
|---|---|
| `sarthi://contract` | The Core Contract |
| `sarthi://standards/{layer}` | All rules for a layer |
| `sarthi://workflows/{task_type}` | Workflow template |
| `sarthi://project/context` | Current project context |

### 8.3 Prompts

Reusable prompt templates (`new-feature`, `fix-bug`) that wrap the workflow, so users can trigger them manually from the IDE.

### 8.4 Prompt-injection hygiene

Sarthi returns content derived from project files (e.g., project names, file paths, rule override reasons, finding messages). Output is **data, not instructions**:
- Project-sourced strings are fenced with `<untrusted_project_data>...</untrusted_project_data>`.
- Any untrusted strings containing attempts to break out of fences (such as closing tag variants `</untrusted_project_data>`) have those sequences neutralized case-insensitively and whitespace-tolerantly (`[untrusted_project_data tag neutralized]`).
- Project text is excluded from trusted MCP fields.

---

## 9. The verify loop

This is the enforcement backbone. The agent writes code, Sarthi verifies, failures flow back, the agent fixes, and the cycle repeats until clean.

```
agent writes code
      │
      ▼
verify_project(scope="changed")
      │
      ├── detect changed files (git diff / mtime fallback)
      ├── select verifiers from active layers + project config
      ├── run runners (allowlisted, timeout, in project root)
      └── normalize findings → VerifyReport
      │
      ▼
 failures ≥ fail_on?  ── yes ──► agent fixes ──► verify again (max N rounds)
      │ no
      ▼
   done
```

### 9.1 Runners

| Runner | Used for | Classification | Notes |
|---|---|---|---|
| `secrets` | Hardcoded secret detection | **Required** | Built-in regex scanner in v0.1; runs in-process |
| `ruff` | Python lint/format/security subset | **Required** | Project-local or virtualenv `ruff`; batches files and enforces `--force-exclude` |
| `eslint` | JavaScript & TypeScript static linting | **Required** | Project-local `node_modules/.bin/eslint` or `npx eslint` (`tsc` planned) |
| `tests` | Project test execution | **Required** | Executes allowlisted test suites (`pytest`, `npm test`, etc.) only after interactive user approval |
| `semgrep` | Custom YAML rules + community packs | **Optional** | Rules in `standards/verifiers/semgrep/`; missing tool produces a warning without failing or marking incomplete |
| `checklist` | Non-automatable rules | **Optional** | Returns at most 8 items ranked by severity and relevance to changed files |

Runners implement the `Runner` protocol:

```python
class Runner(Protocol):
    name: str
    required: bool
    def available(self, ctx: RunContext) -> bool: ...
    def run(self, ctx: RunContext, files: list[Path]) -> list[Finding]: ...
```

Missing **required** tools or unapproved test suites degrade verification status to `incomplete`; missing **optional** tools (`semgrep` on Windows) emit diagnostic warnings in the report without blocking completion.
By default in a git repository, verification scope defaults to `git diff --name-only HEAD` plus untracked files; non-git directories are capped at 500 files with a 60-second wall-clock budget.

### 9.2 Report schema

```json
{
  "status": "failed",
  "context_version": 4,
  "summary": {"critical": 0, "high": 2, "medium": 1, "low": 0},
  "findings": [
    {
      "rule_id": "FAPI-SEC-004",
      "severity": "high",
      "file": "backend/auth.py",
      "line": 42,
      "message": "SQL built via string concatenation",
      "recommendation": "Use parameterized queries via SQLAlchemy bound parameters.",
      "verifier": "semgrep",
      "fix_hint": "See get_rule('FAPI-SEC-004') for a corrected example."
    }
  ],
  "checklist": [
    {"rule_id": "UNI-TEST-002", "prompt": "Confirm new endpoints have integration tests."}
  ],
  "skipped": [{"check": "eslint", "reason": "not installed"}],
  "next_action": "Fix 2 high findings, then call verify_project again."
}
```

`status` is one of `passed`, `failed`, `incomplete` (checks skipped). **`incomplete` never reports as passed.**

### 9.3 Triggering without relying on the agent

1. **Instruction channel:** the Core Contract tells the agent to verify before completion.
2. **CLI / git hook:** `sarthi verify` can run as a pre-commit hook.
3. **CI:** a GitHub Action runs the identical check on every PR (the same core code, so local and CI results match).
4. **Antigravity hooks:** wire in if the Milestone 0 audit confirms suitable lifecycle events.

---

## 10. Antigravity adapter

`sarthi install antigravity` (one command, idempotent, reversible):

1. Locates the Python environment and writes the **MCP server entry** into Antigravity's MCP config with the absolute path resolved automatically (no hand-editing paths).
2. Writes the **global rule file** containing the Core Contract.
3. Optionally scaffolds `.sarthi/project.yaml` in the current workspace.
4. Runs a self-test: starts the server, calls `initialize_project` on a fixture, and prints a pass/fail.
5. `sarthi uninstall antigravity` removes exactly what was added (tracked in a manifest).

The adapter implements a small interface so other clients follow the same pattern later:

```python
class ClientAdapter(Protocol):
    name: str
    def detect(self) -> bool: ...                 # is the client installed?
    def install(self, opts: InstallOpts) -> InstallResult: ...
    def uninstall(self) -> None: ...
    def doctor(self) -> list[Check]: ...
```

> **Milestone 0 deliverable:** `docs/antigravity-notes.md` recording the verified config paths, formats, and hook support, with links to official docs. Nothing in the adapter ships until verified.

---

## 11. CLI reference

Built with Typer. Same core functions as the MCP tools.

| Command | Purpose |
|---|---|
| `sarthi init [path]` | Detect stack, create `.sarthi/project.yaml`, build context |
| `sarthi context [path]` | Print the current project context |
| `sarthi standards [path] --task "..."` | Print standards the agent would receive |
| `sarthi verify [path] [--all] [--json] [--timeout N]` | Run the verify loop (defaults to git diff + untracked) |
| `sarthi approve [path]` | Interactively approve test command set for a project (requires real TTY) |
| `sarthi revoke-approval [path]` | Revoke approved test commands for a project |
| `sarthi install antigravity` | One-time client setup (with timestamped configuration backups) |
| `sarthi uninstall antigravity` | Remove what install added |
| `sarthi doctor` | Diagnose setup (Python, tools, client config) |
| `sarthi lint-standards [--summary]` | Validate standards library schema and print layer summary |
| `sarthi serve` | Start the MCP server over stdio |

---

## 12. Repository structure

```
sarthi/
├── src/sarthi/
│   ├── __init__.py
│   ├── cli.py                      # Typer app
│   ├── core/
│   │   ├── models.py               # Pydantic: Rule, StackProfile, Finding, VerifyReport
│   │   ├── config.py               # ConfigLoader
│   │   ├── stack_detector.py       # StackDetector (walks project files up to depth 6)
│   │   ├── detectors/              # modular detectors (planned post-v0.1)
│   │   ├── rules.py                # loader + RuleSelector
│   │   ├── budget.py               # BudgetManager
│   │   ├── context.py              # ContextBuilder, fingerprinting
│   │   ├── workflows.py            # WorkflowEngine
│   │   ├── pathguard.py            # PathGuard
│   │   ├── security.py             # prompt-injection fencing & sanitization
│   │   ├── standards_linter.py     # schema validation & summary table generator
│   │   └── verify/
│   │       ├── verifier.py         # orchestration
│   │       ├── reporter.py
│   │       ├── trust.py            # CommandTrustManager & command parsing allowlist
│   │       └── runners/
│   │           ├── base.py  ruff.py  semgrep.py
│   │           ├── eslint.py  tests.py  secrets.py  checklist.py
│   ├── mcp/
│   │   ├── server.py               # builds server, sets instructions
│   │   ├── tools.py                # thin wrappers over core
│   │   ├── resources.py
│   │   └── prompts.py
│   └── adapters/
│       ├── base.py                 # ClientAdapter protocol
│       └── antigravity/
│           ├── adapter.py          # AntigravityAdapter (includes inlined templates & backups)
│           └── templates/          # standalone external templates (planned)
│
├── standards/                      # data, not code
│   ├── contract.md                 # the Core Contract (source of truth)
│   ├── universal/  security/  testing/  api-design/  observability/
│   ├── react/  react-native/  node-express/  fastapi/  spring-boot/  python-ml/
│   ├── profiles/                   # compositions of layers
│   ├── workflows/                  # new-project, feature, bugfix, refactor (.md)
│   └── verifiers/
│       ├── semgrep/                # custom Semgrep rules & test fixtures
│       └── eslint/                 # shared ESLint snippets (planned)
│
├── tests/
│   ├── unit/                       # detectors, selector, budget, pathguard, trust, verify
│   ├── integration/                # real stdio transport, install round-trip
│   └── fixtures/                   # tiny sample projects per stack
│
├── evals/                          # A/B benchmark (planned post-v0.1)
│   ├── prompts/                    # the standard task set (planned)
│   ├── rubric.yaml                 # measurable criteria (planned)
│   ├── run_eval.py                 # (planned)
│   └── results/                    # published, reproducible (planned)
│
├── docs/
│   ├── AUDIT.md                    # verified audit report and evidence
│   ├── SECURITY.md                 # trust boundaries & runner classifications
│   ├── antigravity-notes.md        # verified Antigravity integration notes
│   ├── ARCHITECTURE.md             # (planned)
│   ├── RULE_AUTHORING.md           # (planned)
│   ├── ADAPTERS.md                 # (planned)
│   └── ROADMAP.md                  # (planned)
│
├── .github/
│   ├── workflows/ci.yml            # lint, test, lint-standards, semgrep verifiers
│   ├── ISSUE_TEMPLATE/             # (planned)
│   └── PULL_REQUEST_TEMPLATE.md    # (planned)
├── scripts/
│   ├── count_rules.py              # rule-count table generator
│   ├── benchmark_20k.py            # 20k file scalability benchmark
│   ├── clean_install_check.py      # clean environment verification script
│   ├── measure_startup.py          # cold startup benchmark
│   ├── run_stdio_loop.py           # stdio transport reliability test
│   ├── setup.ps1                   # (planned)
│   └── setup.sh                    # (planned)
├── pyproject.toml                  # uv-managed
├── README.md  CONTRIBUTING.md  CODE_OF_CONDUCT.md  SECURITY.md
├── CHANGELOG.md  LICENSE  NOTICE   # NOTICE credits ECC if any MIT code is reused
```

**Cleanup from earlier drafts:** the server lives at `src/sarthi/mcp/server.py` (one location, referenced by `sarthi serve`; clients never need a path to a script).

---

## 13. Security model

| Threat | Mitigation |
|---|---|
| Path traversal / reading outside project | `PathGuard` on every access; root pinned at init |
| Secret exfiltration into agent context | Deny-list for secret files; never return raw file contents; secret scan reports location, not value |
| Prompt injection via project content | Project-derived strings fenced as untrusted data; Sarthi output never contains instructions sourced from project files |
| Arbitrary command execution | Only allowlisted runners and commands from `project.yaml`; resolved binary checked against project root hijacking; interactive user approval via `sarthi approve` required on a real TTY for ANY test execution; no shell string interpolation (argv lists only); timeouts; cwd = project root |
| Malicious contributed rules/verifiers | Standards are data validated by schema; Semgrep verifiers reviewed in PR; no code execution from standards |
| Supply chain | Pinned dependencies, minimal dep set, `pip-audit` in CI, signed releases (later) |

Sarthi does **not** claim to control IDE permissions (file writes, terminal approval). Those belong to the client.

---

## 14. Testing and evaluation

### 14.1 Testing Sarthi itself

- **Unit:** each detector, selector ranking, budget truncation, PathGuard escapes, schema validation.
- **Integration:** launch the MCP server and call every tool through a real MCP client session; verify-loop run against fixtures with seeded violations.
- **Standards CI:** `sarthi lint-standards` validates every rule against the schema, checks verifier refs exist, and runs each Semgrep rule against its good/bad examples (the "bad" example must trigger it, the "good" must not).

### 14.2 The proof: A/B evaluation

*(Note: Automated agent A/B evaluation suite under `evals/` is planned post-v0.1; v0.1 establishes baseline verification through deterministic test suites and benchmark scripts under `scripts/`)*.

The README's claims must be backed by evidence. `evals/` defines **10+ standard tasks** (e.g., "add JWT auth with refresh tokens", "add a paginated list endpoint with filtering"), each run in the same agent **with and without** Sarthi, scored by automated rubric:

| Criterion | How measured |
|---|---|
| No hardcoded secrets | Secret scan |
| Input validated at boundary | Semgrep/AST check |
| Layering respected (no logic/DB in handlers) | Semgrep rule |
| Tests present and passing | Run test suite |
| Lint clean | Ruff/ESLint |
| Error handling on I/O paths | Rubric check |

Results (including negative ones) are published in `evals/results/`. **Release gate:** v0.1 ships its improvement claims only if the delta is measurable. Otherwise the README says what we actually found.

---

## 15. Roadmap and milestones

| Milestone | Deliverable | Exit criteria |
|---|---|---|
| **M0: Verify assumptions** (2-3 days) | `docs/antigravity-notes.md` | Confirmed: MCP config path/format, global rules location, whether `instructions` is surfaced, hook options, current MCP SDK API; name availability checked |
| **M1: Core** | models, config, detectors, PathGuard, context + fingerprint, CLI `init/context` | Detects all five stacks on fixtures; unit tests green |
| **M2: Standards library** | schema, `lint-standards`, Core Contract, universal + security + testing, ≥ 12 rules per stack layer | CI validates all rules; each stack meets the quality bar or is labeled experimental |
| **M3: MCP server** | six tools, resources, prompts, instructions | Works in MCP Inspector; integration tests pass |
| **M4: Verify loop** | runners, report, `sarthi verify`, Semgrep rules | Seeded-violation fixtures all caught; `incomplete` status behaves correctly |
| **M5: Antigravity adapter** | `install/uninstall/doctor` | One command on a clean machine gives a working setup; agent calls `initialize_project` unprompted in manual trials |
| **M6: Evaluation** | `evals/` runs, published results | A/B results documented honestly |
| **M7: Public release v0.1.0** | docs, demo, GitHub release, LinkedIn launch | [Section 16](#16-open-source-launch-plan) checklist complete |
| **v0.2+** | Cursor, Claude Code, VS Code, Codex adapters; GitHub Action; more layers (Postgres, MongoDB); PyPI | Driven by early user feedback |

**Sequencing rule:** do not start M(n+1) until M(n)'s exit criteria pass. Breadth (more stacks and IDEs) comes after the A/B result shows the approach works.

---

## 16. Open-source launch plan

### 16.1 Pre-launch checklist

- [ ] Name availability: GitHub org/repo, PyPI, domain, quick trademark search
- [ ] MIT `LICENSE`; `NOTICE` crediting Everything Claude Code if any portions are reused (keep their copyright notice on those portions)
- [ ] `README` quickstart that works in under 5 minutes on a clean machine (test on Windows, macOS, Linux)
- [ ] `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`
- [ ] Rule-authoring guide with a "add your first rule in 10 minutes" tutorial
- [ ] CI badges: tests, lint-standards, coverage
- [ ] Issue/PR templates; `good first issue` labels (new rules are ideal first contributions)
- [ ] Demo: 60-90 second video, same prompt with and without Sarthi, side-by-side
- [ ] A/B results table in the README

### 16.2 GitHub release

- Semantic versioning, `CHANGELOG.md`, tagged `v0.1.0`, GitHub Release with notes
- Repo topics: `mcp`, `ai-coding`, `antigravity`, `engineering-standards`, `developer-tools`
- Pin a "Roadmap" issue and a "Request a stack/IDE" discussion

### 16.3 LinkedIn launch

1. **Teaser (week before):** the problem ("AI code works in demos, fails in production") with one concrete example.
2. **Launch post:** before/after demo clip, the three-channel approach, link to repo, honest note that v0.1 is Antigravity-first.
3. **Technical deep-dive (week after):** why MCP alone isn't enough, and the verify loop.
4. **Results post:** the A/B numbers, including what did not improve.
5. **Call for contributors:** "add a rule for your stack."

Tone: specific, evidence-led, no hype. The A/B results are the credibility.

### 16.4 After launch

Cross-post to relevant communities (MCP and AI-coding communities, Hacker News "Show HN" once the quickstart is solid), triage issues weekly, and publish a monthly changelog. Let adopter requests decide which IDE adapter comes next.

---

## 17. Risks and open questions

| Risk / question | Plan |
|---|---|
| Antigravity may not surface MCP `instructions`, or global-rules details differ from assumptions | M0 verification; channels B and C as fallbacks |
| Five stacks at once spreads effort thin | Depth tiers; quality bar; `experimental` labeling; ship deepest stacks first |
| Standards overlap with what models already know | Prioritize specific, checkable, opinionated rules; measure via A/B |
| Agent ignores the verify step | CI/git-hook enforcement runs the same core regardless of agent behavior |
| MCP SDK API changes | Pin version; isolate in `sarthi/mcp/`; core is SDK-independent |
| Crowded space (rule collections, ECC, cursor-rules) | Differentiate on dynamic context, verification, and published evals |
| Solo-maintainer scope | Strict milestone gating; community-contributed rules via data-only PRs |

**Open questions to resolve in M0:** exact Antigravity paths and hook capabilities; whether verification can be triggered by a lifecycle event; Windows and macOS path differences for the installer.

---

## 18. Credits and licensing

Sarthi is released under the **MIT License**.

Everything Claude Code (ECC) is an MIT-licensed project used as a **research baseline** for how harness configuration (rules, skills, hooks, agents, MCP) can be organized. Sarthi's standards, rule schema, selection logic, MCP implementation and verify loop are independently authored. If any ECC content is reused verbatim, its copyright and license notice are retained in `NOTICE` for those portions.

---

*Sarthi: teach AI agents how to engineer software, not just how to format code.*
