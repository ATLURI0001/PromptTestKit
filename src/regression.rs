use crate::runner::{validate_run, Run};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseDelta { pub case_id: String, pub baseline_score: f64, pub candidate_score: f64, pub delta: f64 }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comparison {
    pub baseline: String,
    pub candidate: String,
    pub passed: bool,
    pub violations: Vec<String>,
    pub score_delta: f64,
    pub pass_rate_delta: f64,
    pub cases: Vec<CaseDelta>,
}
pub fn compare(base: &Run, candidate: &Run) -> Result<Comparison> {
    validate_run(base)?; validate_run(candidate)?;
    if base.suite != candidate.suite || base.contract_sha256 != candidate.contract_sha256 || base.repeats != candidate.repeats || base.provider != candidate.provider { bail!("incompatible runs: dataset, assertions, provider settings and repetitions must match"); }
    let scores = |run: &Run| {
        let mut m: BTreeMap<String, (f64, usize, String)> = BTreeMap::new();
        for s in &run.results {
            let signature = serde_json::to_string(&s.checks.iter().map(|c| &c.assertion).collect::<Vec<_>>()).unwrap_or_default();
            let e = m.entry(s.case_id.clone()).or_insert((0.0,0,signature)); e.0 += s.score; e.1 += 1;
        } m
    };
    let b = scores(base); let c = scores(candidate);
    if b.keys().collect::<Vec<_>>() != c.keys().collect::<Vec<_>>() || b.iter().any(|(k,v)| c[k].2 != v.2) { bail!("incompatible case coverage or assertions"); }
    let g = &candidate.gates;
    let mut violations = Vec::new();
    let mut gate = |condition: bool, reason: String| { if condition { violations.push(reason); } };
    gate(candidate.metrics.errors > 0, format!("{} provider error(s)", candidate.metrics.errors));
    gate(candidate.metrics.pass_rate + 1e-9 < g.min_pass_rate, format!("pass rate {:.3} below {:.3}", candidate.metrics.pass_rate,g.min_pass_rate));
    let score_delta = candidate.metrics.mean_score - base.metrics.mean_score;
    let pass_rate_delta = candidate.metrics.pass_rate - base.metrics.pass_rate;
    gate(-score_delta > g.max_score_drop + 1e-9, format!("mean score dropped {:.3}", -score_delta));
    gate(-pass_rate_delta > g.max_pass_rate_drop + 1e-9, format!("pass rate dropped {:.3}", -pass_rate_delta));
    let cases: Vec<_> = b.iter().map(|(id,(sum,n,_))| {
        let baseline_score = sum / *n as f64;
        let candidate_score = c[id].0 / c[id].1 as f64;
        gate(baseline_score-candidate_score > g.max_case_score_drop + 1e-9, format!("case {id}: score dropped {:.3}", baseline_score-candidate_score));
        CaseDelta { case_id: id.clone(), baseline_score, candidate_score, delta: candidate_score-baseline_score }
    }).collect();
    if let Some(limit) = g.max_p95_latency_increase {
        gate(candidate.metrics.p95_latency_ms > base.metrics.p95_latency_ms * (1.0 + limit) + 1e-9, "p95 latency exceeded relative increase limit".into());
    }
    if let Some(limit) = g.max_cost_increase {
        match (base.metrics.total_cost_usd, candidate.metrics.total_cost_usd) {
            (Some(b),Some(c)) => gate(c > b * (1.0+limit) + 1e-12, "cost exceeded relative increase limit".into()),
            _ => gate(true, "cost gate cannot be evaluated: token usage unavailable".into()),
        }
    }
    Ok(Comparison { baseline: base.version.clone(), candidate: candidate.version.clone(), passed: violations.is_empty(), violations, score_delta, pass_rate_delta, cases })
}
