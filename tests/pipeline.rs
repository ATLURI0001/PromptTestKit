use prompttestkit::{config, regression::compare, report, runner::{self, Run}};
use std::{path::Path, process::Command};

async fn sample(version: &str) -> Run {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/suite.toml");
    let (s,c,r) = config::load(&path).unwrap();
    runner::run(&s,&c,&r,version).await.unwrap()
}
#[tokio::test]
async fn offline_pipeline_detects_regression_and_roundtrips() {
    let base = sample("v1").await;
    let good = sample("v2").await;
    let bad = sample("broken").await;
    assert_eq!(base.metrics.samples,8);
    assert_eq!(base.metrics.pass_rate,1.0);
    assert_eq!(base.metrics.total_cost_usd,None);
    assert!(compare(&base,&good).unwrap().passed);
    let regression = compare(&base,&bad).unwrap();
    assert!(!regression.passed);
    assert!(regression.violations.iter().any(|v| v.contains("outage")));
    let temp = tempfile::tempdir().unwrap();
    report::write_run(&base,temp.path()).unwrap();
    let restored = runner::read_run(&temp.path().join("run.json")).unwrap();
    assert_eq!(restored.prompt_sha256,base.prompt_sha256);
    for file in ["run.json","report.html","report.md","junit.xml"] { assert!(temp.path().join(file).is_file()); }
    report::write_comparison(&regression,&temp.path().join("compare")).unwrap();
    assert!(temp.path().join("compare/regression.html").is_file());
}
#[tokio::test]
async fn per_case_gates_catch_masked_regression() {
    let base = sample("v1").await;
    let mut bad = sample("broken").await;
    bad.gates.min_pass_rate = 0.0;
    bad.gates.max_score_drop = 1.0;
    bad.gates.max_pass_rate_drop = 1.0;
    assert!(compare(&base,&bad).unwrap().violations.iter().all(|v| v.starts_with("case ")));
    assert!(!compare(&base,&bad).unwrap().passed);
}
#[tokio::test]
async fn incompatible_and_tampered_artifacts_are_rejected() {
    let base = sample("v1").await;
    let mut candidate = base.clone();
    candidate.contract_sha256 = "different".into();
    assert!(compare(&base,&candidate).is_err());
    candidate = base.clone(); candidate.results.pop();
    assert!(runner::validate_run(&candidate).is_err());
    candidate = base.clone(); candidate.metrics.mean_score = 0.2;
    assert!(runner::validate_run(&candidate).is_err());
    candidate = base.clone(); candidate.results[0].checks[0].passed = false;
    assert!(runner::validate_run(&candidate).is_err());
}
#[tokio::test]
async fn optional_cost_and_latency_gates() {
    let base = sample("v1").await;
    let mut candidate = base.clone();
    candidate.gates.max_cost_increase = Some(0.1);
    assert!(!compare(&base,&candidate).unwrap().passed);
    candidate.gates.max_cost_increase = None;
    candidate.gates.max_p95_latency_increase = Some(0.1);
    for s in &mut candidate.results { s.latency_ms += 1000.0; }
    candidate.metrics = runner::summarize(&candidate.results);
    assert!(!compare(&base,&candidate).unwrap().passed);
}
#[tokio::test]
async fn html_and_xml_do_not_embed_raw_model_markup() {
    let mut r = sample("v1").await;
    r.results[0].output = "<script>alert('x')</script>".into();
    let assertions = r.results[0].checks.iter().map(|c| c.assertion.clone()).collect::<Vec<_>>();
    r.results[0].checks = prompttestkit::evaluate::evaluate(&r.results[0].output,&assertions);
    r.results[0].score = r.results[0].checks.iter().filter(|c| c.passed).count() as f64 / assertions.len() as f64;
    r.results[0].passed = false;
    r.metrics = runner::summarize(&r.results);
    let temp = tempfile::tempdir().unwrap();
    report::write_run(&r,temp.path()).unwrap();
    for f in ["report.html","junit.xml"] {
        let text = std::fs::read_to_string(temp.path().join(f)).unwrap();
        assert!(!text.contains("<script>"));
    }
}
#[test]
fn cli_exit_codes_and_init() {
    let temp = tempfile::tempdir().unwrap();
    let binary = env!("CARGO_BIN_EXE_prompttestkit");
    let suite_dir = temp.path().join("demo");
    let status = Command::new(binary).arg("init").arg(&suite_dir).status().unwrap();
    assert!(status.success());
    assert_eq!(Command::new(binary).arg("init").arg(&suite_dir).status().unwrap().code(),Some(2));
    let suite = suite_dir.join("suite.toml");
    assert!(Command::new(binary).arg("validate").arg("--suite").arg(&suite).status().unwrap().success());
    for (version,code) in [("v1",0),("v2",0),("broken",1)] {
        let status = Command::new(binary).arg("run").arg("--suite").arg(&suite).arg("--version").arg(version).arg("--out").arg(temp.path().join(version)).status().unwrap();
        assert_eq!(status.code(),Some(code));
    }
    for (version,code) in [("v2",0),("broken",1)] {
        assert_eq!(Command::new(binary).arg("compare").arg("--baseline").arg(temp.path().join("v1/run.json")).arg("--candidate").arg(temp.path().join(version).join("run.json")).arg("--out").arg(temp.path().join(format!("comparison-{version}"))).status().unwrap().code(),Some(code));
    }
}
