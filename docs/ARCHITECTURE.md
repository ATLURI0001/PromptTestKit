# Architecture

## Evaluation lifecycle

1. Parse TOML into a strict tagged provider configuration.
2. Validate execution bounds, gates, endpoints, dataset IDs and assertion syntax.
3. Read all templates and check missing variables against every case.
4. In fixture mode, validate response coverage for every configured version.
5. Schedule case × repetition jobs with bounded asynchronous concurrency.
6. Render templates in one pass, invoke the provider and record elapsed time.
7. Evaluate assertions even when output is empty; provider errors override the
   sample score to zero and mark the sample failed.
8. Sort records by case ID and repetition, aggregate metrics, and write reports.
9. Compare compatible artifacts against the candidate's configured gates.

## Reliability and provenance

The client is reused across concurrent calls. Redirects are disabled. Every
attempt has a timeout, with at most eight retries configurable. A transport
failure becomes a result record so CI can inspect the failure. Authentication
errors fail immediately rather than consuming the retry budget.

Artifacts use schema version 1. When reading one, the runner validates unique
case/repetition pairs, complete repeat coverage, nonnegative finite timings and
costs, assertion results, score consistency and aggregate metrics. It recomputes
assertions from output instead of trusting stored booleans. Numeric summaries
allow only a small serialization tolerance.

Each artifact includes the suite configuration for review, including generation
and execution parameters. The API key value is never included; only the name of
the environment variable used to obtain it is retained.

The contract is SHA-256 of a canonical ordered serialization of the cases,
provider configuration and execution configuration. Variable and version maps
use BTreeMap for stable ordering. Dataset array order is significant: reordering
cases deliberately establishes a new contract. This hashes provenance inputs;
it does not sign the run or prevent a malicious actor editing every related
field. Store artifacts in a trusted CI environment for release decisions.

## Scoring tradeoffs

All assertions have equal weight within a sample; all samples have equal weight
in aggregate. Per-case comparisons average repeated scores. Assertion-count
weighting would make cases with more checks dominate evaluation; this project
chooses equal-case influence instead. A separate all-checks-pass rate prevents
a high partial score from obscuring failed cases.

Threshold gates are transparent and deterministic. No model judge, embeddings,
bootstrap significance test or dependency on a second inference service is
included. Add semantic checks only with their own validation dataset and clear
uncertainty reporting. More repetitions improve visibility but do not remove
dataset bias or model/provider drift.

## Extending the project

- Add assertion variants in config, evaluator, docs and positive/negative tests.
- Add providers behind the typed provider configuration and common completion
  record. Keep usage nullable; do not guess token counts from characters.
- Preserve report escaping and never embed model output as executable markup.
- Bump the artifact schema for incompatible changes and explicitly migrate or
  reject old artifacts.
- Version datasets in Git and review baseline changes alongside prompt diffs.

## Current operational limits

Suites and artifacts are held in memory. There is no persistent service, database,
distributed scheduler, output cache, streaming, hard global cost budget or
per-tenant authorization layer. Endpoint response bodies are also buffered;
only use trusted providers. Rate limiting is local concurrency plus bounded
retry backoff. Report writes are ordinary files, not transactional multi-file
commits. Use separate output directories for simultaneous runs.
