use crate::{config::{Case, Gates, Suite}, evaluate::{evaluate, render, Check}, provider::{Provider, Usage}};
use anyhow::{bail, Context, Result};
use futures::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::{BTreeMap, BTreeSet}, path::Path, time::{Instant, SystemTime, UNIX_EPOCH}};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    pub case_id: String,
    pub repeat: usize,
    pub output: String,
    pub checks: Vec<Check>,
    pub score: f64,
    pub passed: bool,
    pub error: Option<String>,
    pub latency_ms: f64,
    pub usage: Usage,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metrics {
    pub samples: usize,
    pub errors: usize,
    pub pass_rate: f64,
    pub mean_score: f64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub total_cost_usd: Option<f64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    pub schema_version: u32,
    pub suite: String,
    pub version: String,
    pub created_unix_seconds: u64,
    pub prompt_sha256: String,
    pub contract_sha256: String,
    pub provider: String,
    pub repeats: usize,
    /// Configuration provenance; contains environment variable names, never keys.
    pub configuration: Suite,
    pub gates: Gates,
    pub metrics: Metrics,
    pub results: Vec<Sample>,
}
pub fn digest(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
pub async fn run(suite: &Suite, cases: &[Case], root: &Path, version: &str) -> Result<Run> {
    let template = std::fs::read_to_string(root.join(suite.prompts.get(version).context("unknown prompt version")?))?;
    let provider = Provider::new(&suite.provider, &suite.execution, root, version)?;
    let jobs = cases.iter().flat_map(|c| (0..suite.execution.repeats).map(move |r| (c, r)));
    let mut results: Vec<Sample> = stream::iter(jobs).map(|(case, repeat)| {
        let provider = &provider;
        let template = &template;
        async move {
            let prompt = render(template, &case.variables)?;
            let start = Instant::now();
            let result = provider.complete(&case.id, &prompt).await;
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
            let (output, usage, error) = match result {
                Ok(c) => (c.text, c.usage, None),
                Err(e) => (String::new(), Usage::default(), Some(e.to_string())),
            };
            let checks = evaluate(&output, &case.assertions);
            let score = if error.is_some() { 0.0 } else { checks.iter().filter(|c| c.passed).count() as f64 / checks.len() as f64 };
            let passed = error.is_none() && checks.iter().all(|c| c.passed);
            Ok::<_, anyhow::Error>(Sample { case_id: case.id.clone(), repeat, output, checks, score, passed, error, latency_ms, usage })
        }
    }).buffer_unordered(suite.execution.concurrency).collect::<Vec<_>>().await.into_iter().collect::<Result<_>>()?;
    results.sort_by(|a,b| (&a.case_id, a.repeat).cmp(&(&b.case_id, b.repeat)));
    // Contract excludes prompt text/fixture responses (the treatment), but includes
    // the evaluation data and generation settings (controlled variables).
    let provider_contract = match &suite.provider {
        crate::config::ProviderConfig::Fixture { .. } => serde_json::json!({"kind":"fixture"}),
        config => serde_json::to_value(config)?,
    };
    let contract = serde_json::to_vec(&(cases, provider_contract, &suite.execution))?;
    let provider_name = match &suite.provider {
        crate::config::ProviderConfig::Fixture { .. } => "fixture (offline; latency is harness overhead)".into(),
        crate::config::ProviderConfig::ChatCompletions { model, .. } => format!("chat_completions:{model}"),
    };
    Ok(Run { schema_version: 1, suite: suite.name.clone(), version: version.into(), created_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(), prompt_sha256: digest(template.as_bytes()), contract_sha256: digest(&contract), provider: provider_name, repeats: suite.execution.repeats, configuration: suite.clone(), gates: suite.gates.clone(), metrics: summarize(&results), results })
}
pub fn summarize(results: &[Sample]) -> Metrics {
    let n = results.len();
    let mut times: Vec<f64> = results.iter().map(|r| r.latency_ms).collect();
    times.sort_by(f64::total_cmp);
    let percentile = |q: f64| if times.is_empty() { 0.0 } else { times[((q * n as f64).ceil() as usize).saturating_sub(1)] };
    Metrics { samples: n, errors: results.iter().filter(|s| s.error.is_some()).count(), pass_rate: if n == 0 {0.0} else { results.iter().filter(|s| s.passed).count() as f64 / n as f64 }, mean_score: if n == 0 {0.0} else { results.iter().map(|s| s.score).sum::<f64>() / n as f64 }, p50_latency_ms: percentile(0.5), p95_latency_ms: percentile(0.95), total_cost_usd: results.iter().map(|r| r.usage.cost_usd).collect::<Option<Vec<_>>>().map(|v| v.iter().sum()) }
}
pub fn validate_run(run: &Run) -> Result<()> {
    run.gates.validate()?;
    run.configuration.validate()?;
    if run.configuration.name != run.suite || run.configuration.execution.repeats != run.repeats || !run.configuration.prompts.contains_key(&run.version) { bail!("run configuration does not match metadata"); }
    if run.schema_version != 1 || run.results.is_empty() || run.repeats == 0 { bail!("unsupported or empty run artifact"); }
    let mut seen = BTreeSet::new();
    let mut cases: BTreeMap<&str, (usize, String)> = BTreeMap::new();
    for s in &run.results {
        if s.case_id.is_empty() || s.repeat >= run.repeats || !seen.insert((&s.case_id,s.repeat)) || s.checks.is_empty() { bail!("invalid or duplicate sample"); }
        if !s.latency_ms.is_finite() || s.latency_ms < 0.0 || !s.score.is_finite() || !(0.0..=1.0).contains(&s.score) || s.usage.cost_usd.is_some_and(|v| !v.is_finite() || v < 0.0) { bail!("invalid sample metrics"); }
        let assertions: Vec<_> = s.checks.iter().map(|c| &c.assertion).collect();
        let encoded = serde_json::to_string(&assertions)?;
        let entry = cases.entry(&s.case_id).or_insert((0, encoded.clone()));
        if entry.1 != encoded { bail!("inconsistent repeated assertions"); }
        entry.0 += 1;
        let expected = evaluate(&s.output, &assertions.into_iter().cloned().collect::<Vec<_>>());
        let score = if s.error.is_some() {0.0} else {expected.iter().filter(|c| c.passed).count() as f64 / expected.len() as f64};
        if (s.score-score).abs() > 1e-9 || s.passed != (s.error.is_none() && expected.iter().all(|c| c.passed)) || s.checks.iter().zip(&expected).any(|(a,b)| a.passed != b.passed) { bail!("inconsistent sample scoring"); }
    }
    if cases.values().any(|(n,_)| *n != run.repeats) { bail!("incomplete case repetitions"); }
    // Reports never trust externally edited aggregate metrics.
    let recomputed = summarize(&run.results);
    let near = |a: f64,b: f64| a.is_finite() && b.is_finite() && (a-b).abs() <= 1e-9 * a.abs().max(b.abs()).max(1.0);
    let cost_matches = match (recomputed.total_cost_usd,run.metrics.total_cost_usd) { (Some(a),Some(b)) => near(a,b), (None,None) => true, _ => false };
    if recomputed.samples != run.metrics.samples || recomputed.errors != run.metrics.errors || !near(recomputed.mean_score,run.metrics.mean_score) || !near(recomputed.pass_rate,run.metrics.pass_rate) || !near(recomputed.p50_latency_ms,run.metrics.p50_latency_ms) || !near(recomputed.p95_latency_ms,run.metrics.p95_latency_ms) || !cost_matches { bail!("aggregate metrics do not match samples"); }
    Ok(())
}
pub fn read_run(path: &Path) -> Result<Run> {
    let r: Run = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    validate_run(&r)?;
    Ok(r)
}
