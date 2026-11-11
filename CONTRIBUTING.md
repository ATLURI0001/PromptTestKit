# Contributing

Use stable Rust. Keep changes focused and include a fixture or local HTTP test
for behavior changes. No live credentials or paid API calls are required in CI.

```sh
cargo test --all-targets
cargo clippy --all-targets
cargo fmt
```

For a new assertion, update the tagged enum in `src/config.rs`, the evaluator,
documentation and both positive and negative tests. For a provider, keep secrets
out of serialized artifacts and errors. For regression changes, test thresholds,
incompatible datasets, missing data and per-case failures.

Open a pull request with the expected behavior and actual validation performed.
Do not claim a fixture result measures model quality. Use synthetic or consented,
sanitized datasets; remove sensitive content before publishing run artifacts.
