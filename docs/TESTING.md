# Validation

## Commands

```sh
cargo test --all-targets
cargo clippy --all-targets
cargo run -- validate
cargo run -- run --version v1 --out runs/v1
cargo run -- run --version v2 --out runs/v2
cargo run -- compare --baseline runs/v1/run.json --candidate runs/v2/run.json --out runs/comparison
```

Use `cargo fmt` before committing formatting changes. Once a generated
`Cargo.lock` is committed, prefer `--locked` for builds and CI.

## Test layers

| File | Coverage |
|---|---|
| `tests/evaluation.rs` | Single-pass templates, Unicode, all assertion types, strict JSON, escaping, dataset and configuration validation |
| `tests/pipeline.rs` | Passing and regressing runs, per-case gates, incompatible/tampered artifacts, report roundtrip, optional cost/latency gates, CLI init and exit codes |
| `tests/provider.rs` | Local HTTP retry after 429, authentication failure, error-body redaction, malformed response, usage accounting, missing credentials and fixture files |

Local HTTP tests bind an ephemeral loopback port. No model calls, external HTTP
services or paid credentials are required. Each test uses its own environment
variable name to avoid credential races. The CLI integration test executes the
actual Cargo-built binary in a temporary directory.

## Delivery environment

The source package was assembled in a Windows environment without `cargo` or
`rustc` available. Downloading a Rust toolchain was blocked by DNS resolution,
and WSL access was denied. Consequently **Rust compilation, Clippy and the Rust
test suite were not executed during initial delivery**. Do not treat this package
as having a green build until the included commands or GitHub Actions pass.

The package's Python verification script checks example TOML/JSON structure,
template variables, fixture coverage, expected offline scores and archive
contents. That is additional static validation, not a substitute for Rust tests.

## Expected offline behavior

- `v1`: 8 samples, 100% pass rate, mean score 1.0.
- `v2`: 8 samples, 100% pass rate, mean score 1.0.
- `broken`: 8 samples, 0% pass rate; partial checks can still pass.
- `v1 → v2`: pass.
- `v1 → broken`: fail with aggregate and case-level violations.
- Fixture token usage and cost: unavailable (`null`).

These are expected values derived from the fixtures. They are not a record of
running the Rust program. The generated `VALIDATION.json` identifies the static
checks actually performed on the delivered package.
