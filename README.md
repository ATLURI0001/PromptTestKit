# PromptTestKit

**Evaluation infrastructure for prompt evolution—versioned test suites, assertion-driven scoring, and granular regression gates that turn behavioral changes into auditable release decisions.**

A Rust CLI and reusable library for automated prompt evaluations. Define prompt
versions, a dataset, assertions and quality gates. Run each version against the
same evaluation contract, inspect the reports, and fail CI when behavior regresses.

## What it delivers

- Versioned UTF-8 prompt templates with strict `{{variable}}` substitution.
- TOML suites and JSON datasets; unknown configuration fields are rejected.
- Offline fixture mode plus a live OpenAI-compatible Chat Completions adapter.
- Bounded concurrency, repeated samples, request timeouts and retry handling.
- Exact, contains, excludes, regex, JSON, JSON pointer and character-length checks.
- Pass rate, assertion score, p50/p95 latency, provider errors and optional token costs.
- Aggregate and per-case regression gates, with compatibility checks on saved runs.
- Self-contained HTML, Markdown, JSON and JUnit reports.
- Linux/Windows CI and integration tests that require no paid API access.

## Quick start

Install stable Rust using [rustup](https://rustup.rs/). On Windows, the MSVC
toolchain also needs the C++ build tools offered by the installer. From this folder:

```sh
cargo build --release
cargo test --all-targets
cargo run -- validate
cargo run -- run --version v1 --out runs/v1
cargo run -- run --version v2 --out runs/v2
cargo run -- compare --baseline runs/v1/run.json --candidate runs/v2/run.json --out runs/comparison
```

Open `runs/comparison/regression.html` in your browser. Both fixture versions
pass all checks. The fixture outputs are hand-authored examples: they verify the
pipeline, not the quality of a model or whether a prompt resists attacks.

See an intentional regression:

```sh
cargo run -- run --version broken --out runs/broken
cargo run -- compare --baseline runs/v1/run.json --candidate runs/broken/run.json --out runs/regression
```

Both commands intentionally exit with code **1** while still saving reports.
Run them separately in shells that stop after a nonzero status. The comparison
identifies specific cases, including an outage incorrectly marked normal.

To install the CLI or create a new standalone suite:

```sh
cargo install --path .
prompttestkit init my-evaluations
prompttestkit validate --suite my-evaluations/suite.toml
prompttestkit run --suite my-evaluations/suite.toml --version v1 --out runs/custom
```

## Live evaluations

`examples/api-suite.toml` uses the same dataset with real model calls. Choose a
model your account supports and set the full endpoint path for your provider.
The included model is an editable example, not a guarantee of availability.

PowerShell:

```powershell
$env:OPENAI_API_KEY = "your-api-key"
cargo run -- run --suite examples/api-suite.toml --version v1 --out runs/live-v1
cargo run -- run --suite examples/api-suite.toml --version v2 --out runs/live-v2
cargo run -- compare --baseline runs/live-v1/run.json --candidate runs/live-v2/run.json --out runs/live-comparison
```

Bash: `export OPENAI_API_KEY='your-api-key'` before the same Cargo commands.
Live runs incur your provider's charges. API keys stay in the process environment;
the suite and artifacts do not contain their values.

The adapter sends one user message with `model`, `temperature`, `max_tokens` and
`messages`. It expects `choices[0].message.content` as a string and optionally
`usage.prompt_tokens` and `usage.completion_tokens`. Models requiring a different
request format need an adapter change. Streaming, tool calls, multimodal inputs
and model-as-judge scoring are outside version 0.1.

## Suite configuration

```toml
name = "my-prompt-suite"
dataset = "dataset.json"

[prompts]
baseline = "prompts/baseline.txt"
candidate = "prompts/candidate.txt"

[provider]
kind = "chat_completions"
endpoint = "https://your-provider.example/v1/chat/completions"
model = "your-model"
api_key_env = "MODEL_API_KEY"
temperature = 0.0
max_tokens = 512
# Optional USD per one million tokens; use current provider prices.
# input_cost_per_million = 0.15
# output_cost_per_million = 0.60

[execution]
concurrency = 4
repeats = 3
timeout_seconds = 60
retries = 2

[gates]
min_pass_rate = 0.95
max_score_drop = 0.02
max_pass_rate_drop = 0.02
max_case_score_drop = 0.10
# Optional relative increases: 0.25 = 25%, not 25 percentage points.
# max_p95_latency_increase = 0.25
# max_cost_increase = 0.10
```

Paths resolve relative to the suite, independent of your current directory.
Fixture suites replace the provider with `kind = "fixture"` and a
`[provider.responses]` map from version to response JSON file. Each fixture file
maps every case ID to an output string. Every repetition reuses that same string.

## Dataset and assertions

```json
[
  {
    "id": "billing",
    "variables": {"message": "Please explain my invoice."},
    "assertions": [
      {"type": "json"},
      {"type": "json_pointer", "pointer": "/intent", "value": "billing"},
      {"type": "max_chars", "value": 200}
    ]
  }
]
```

| Type | Fields | Behavior |
|---|---|---|
| `exact` | `value` | Compare after trimming outer whitespace |
| `contains` | `value` | Case-sensitive substring |
| `not_contains` | `value` | Reject a case-sensitive substring |
| `regex` | `pattern` | Rust regex syntax, validated before execution |
| `json` | — | Entire output must parse as JSON, without code fences |
| `json_pointer` | `pointer`, `value` | Typed equality at an RFC 6901 pointer |
| `max_chars` | `value` | Maximum Unicode scalar count, not bytes or tokens |

Every case needs a unique nonempty ID and at least one assertion. A sample's
score is the fraction of assertions that pass. A sample passes only when all
assertions pass and the provider succeeds. Provider failures always score zero.
All cases and repetitions have equal weight, regardless of assertion count.

## Regression rules

`compare` uses the **candidate artifact's gates**. Review gate changes alongside
prompt changes. For a successful comparison:

1. Suite, evaluation-contract hash, provider identity and repetition count match.
2. Case coverage and assertion definitions match.
3. The candidate has no provider errors and meets its minimum pass rate.
4. Mean-score, pass-rate and each case's mean-score drop stay within their limits.
5. Optional p95-latency and total-cost increase limits pass.

Rate drops use absolute differences on a 0–1 scale. A limit of `0.02` allows a
two-percentage-point drop. Equal-to-limit changes pass, with a small floating-point
tolerance. Case gates prevent improvements elsewhere from hiding a local failure.

The contract hashes the dataset (including input variables and assertions),
provider configuration and execution settings. Prompt text and fixture responses
are excluded because those are the versions being compared. Each run separately
records its prompt SHA-256. Changing the dataset or model settings requires new,
compatible baseline and candidate runs.

This is deterministic threshold gating, **not statistical significance testing**.
Repeated model calls can still be correlated, and temperature zero is not a
reproducibility guarantee. Use representative datasets, repeated runs and human
review. Fixture latency measures harness overhead and should not be used as a
model-performance benchmark. API latency includes retries and backoff but excludes
time waiting for a concurrency slot. p95 uses the nearest-rank method.

Costs are estimates based on configured prices and provider-reported tokens.
Missing usage or pricing remains `null`, never a fabricated zero. A cost gate
fails if either run's cost is unavailable. Pricing and token usage do not include
all provider-specific billing adjustments or the cost of unsuccessful attempts.

## Reports and exit codes

| File | Purpose |
|---|---|
| `run.json` | Versioned machine-readable samples, checks, errors and fingerprints |
| `report.html` | Standalone visual run report with expandable outputs |
| `report.md` | Compact run summary |
| `junit.xml` | Sample-level test results for CI consumers |
| `comparison.json` | Machine-readable comparison and violations |
| `regression.html` | Visual comparison with case-level deltas |
| `regression.md` | Shareable comparison summary |

Rebuild run reports with:

```sh
prompttestkit report --run runs/v1/run.json --out runs/rebuilt
```

Exit `0`: success; exit `1`: evaluation minimum/error gate or comparison failed;
exit `2`: invalid inputs, incompatible runs or an operational failure. Reports
are written before returning an evaluation/regression failure. A comparison
that cannot safely be made exits `2` instead of inventing a regression result.

HTTP 429, 5xx, connection failures and timeouts are retried up to the configured
retry count. Backoff starts at 250 ms and doubles. Other HTTP failures and
malformed successful responses are not retried. The request timeout applies per
attempt. `Retry-After` pacing and distributed rate limits are not implemented.

## Architecture

| Module | Responsibility |
|---|---|
| `config` | Typed configuration and dataset validation |
| `evaluate` | Template rendering and assertion execution |
| `provider` | Offline fixtures, HTTP transport, retries and token costs |
| `runner` | Concurrent execution, sample records and artifact validation |
| `regression` | Run compatibility and quality gates |
| `report` | Escaped HTML/XML, Markdown and JSON output |
| `main` | CLI commands and exit semantics |

The library API is available independently of the CLI. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for design tradeoffs and
[docs/TESTING.md](docs/TESTING.md) for validation and limitations.

## Dependencies and CI

The first successful Cargo build generates `Cargo.lock`; commit it for repeatable
CLI dependency resolution. After that, use `cargo test --locked --all-targets`
and add `--locked` to CI Cargo commands. No lockfile is fabricated in this package.

Suggested description: **Evaluation infrastructure for prompt evolution—versioned test suites, assertion-driven scoring, and granular regression gates that turn behavioral changes into auditable release decisions.**

Suggested topics: `rust`, `prompt-engineering`, `llm-evaluation`, `regression-testing`,
`testing-framework`, `cli`, `continuous-integration`, `generative-ai`.

The included GitHub Actions workflow runs offline tests and comparisons on Linux
and Windows, then uploads evaluation reports. It needs no API secrets. After
your first run, require the checks in your main-branch protection settings.
See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and [LICENSE](LICENSE).
