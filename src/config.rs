use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::{BTreeMap, BTreeSet}, fs, path::{Path, PathBuf}};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suite {
    pub name: String,
    pub dataset: String,
    pub prompts: BTreeMap<String, String>,
    pub provider: ProviderConfig,
    #[serde(default)]
    pub execution: Execution,
    #[serde(default)]
    pub gates: Gates,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderConfig {
    Fixture { responses: BTreeMap<String, String> },
    ChatCompletions {
        endpoint: String,
        model: String,
        #[serde(default = "key_env")]
        api_key_env: String,
        #[serde(default)]
        temperature: f64,
        #[serde(default = "max_tokens")]
        max_tokens: u32,
        #[serde(default)]
        input_cost_per_million: Option<f64>,
        #[serde(default)]
        output_cost_per_million: Option<f64>,
    },
}
fn key_env() -> String { "OPENAI_API_KEY".into() }
fn max_tokens() -> u32 { 512 }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Execution { pub concurrency: usize, pub repeats: usize, pub timeout_seconds: u64, pub retries: u32 }
impl Default for Execution {
    fn default() -> Self { Self { concurrency: 4, repeats: 1, timeout_seconds: 60, retries: 2 } }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Gates {
    pub min_pass_rate: f64,
    pub max_score_drop: f64,
    pub max_pass_rate_drop: f64,
    pub max_case_score_drop: f64,
    pub max_p95_latency_increase: Option<f64>,
    pub max_cost_increase: Option<f64>,
}
impl Default for Gates {
    fn default() -> Self { Self { min_pass_rate: 1.0, max_score_drop: 0.0, max_pass_rate_drop: 0.0, max_case_score_drop: 0.0, max_p95_latency_increase: None, max_cost_increase: None } }
}
impl Gates {
    pub fn validate(&self) -> Result<()> {
        for n in [self.min_pass_rate, self.max_score_drop, self.max_pass_rate_drop, self.max_case_score_drop] {
            if !n.is_finite() || !(0.0..=1.0).contains(&n) { bail!("rate gates must be finite values in [0,1]"); }
        }
        for n in [self.max_p95_latency_increase, self.max_cost_increase].into_iter().flatten() {
            if !n.is_finite() || n < 0.0 { bail!("relative increase gates must be finite and nonnegative"); }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub id: String,
    pub variables: BTreeMap<String, String>,
    pub assertions: Vec<Assertion>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Assertion {
    Exact { value: String },
    Contains { value: String },
    NotContains { value: String },
    Regex { pattern: String },
    Json,
    JsonPointer { pointer: String, value: serde_json::Value },
    MaxChars { value: usize },
}

pub fn load(path: &Path) -> Result<(Suite, Vec<Case>, PathBuf)> {
    let suite: Suite = toml::from_str(&fs::read_to_string(path).context("read suite")?).context("parse suite TOML")?;
    suite.validate()?;
    let root = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let cases: Vec<Case> = serde_json::from_str(&fs::read_to_string(root.join(&suite.dataset)).context("read dataset")?).context("parse dataset JSON")?;
    validate_cases(&cases)?;
    for prompt in suite.prompts.values() {
        let template = fs::read_to_string(root.join(prompt)).context("read prompt template")?;
        for case in &cases { crate::evaluate::render(&template, &case.variables).with_context(|| format!("case {}", case.id))?; }
    }
    if let ProviderConfig::Fixture { responses } = &suite.provider {
        for version in suite.prompts.keys() {
            let file = responses.get(version).context("fixture missing prompt version")?;
            let fixtures: BTreeMap<String, String> = serde_json::from_str(&fs::read_to_string(root.join(file))?)?;
            for case in &cases { if !fixtures.contains_key(&case.id) { bail!("fixture {version} missing case {}", case.id); } }
        }
    }
    Ok((suite, cases, root))
}
pub fn validate_cases(cases: &[Case]) -> Result<()> {
    if cases.is_empty() { bail!("dataset must not be empty"); }
    let mut ids = BTreeSet::new();
    for c in cases {
        if c.id.trim().is_empty() || !ids.insert(&c.id) { bail!("case IDs must be unique and nonempty"); }
        if c.assertions.is_empty() { bail!("case {} needs assertions", c.id); }
        for a in &c.assertions {
            if let Assertion::Regex { pattern } = a { regex::Regex::new(pattern).context("invalid assertion regex")?; }
            if let Assertion::JsonPointer { pointer, .. } = a {
                if !pointer.is_empty() && !pointer.starts_with('/') { bail!("JSON pointer must be empty or start with /"); }
            }
        }
    }
    Ok(())
}
impl Suite {
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() || self.prompts.is_empty() { bail!("name and prompts required"); }
        let e = &self.execution;
        if !(1..=128).contains(&e.concurrency) || !(1..=100).contains(&e.repeats) || !(1..=3600).contains(&e.timeout_seconds) || e.retries > 8 { bail!("execution bounds: concurrency 1..128, repeats 1..100, timeout 1..3600, retries 0..8"); }
        self.gates.validate()?;
        if let ProviderConfig::ChatCompletions { endpoint, temperature, max_tokens, input_cost_per_million, output_cost_per_million, .. } = &self.provider {
            let url = reqwest::Url::parse(endpoint)?;
            if !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() { bail!("endpoint must not contain credentials, query or fragment"); }
            let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
            if url.scheme() != "https" && !(url.scheme() == "http" && local) { bail!("endpoint requires HTTPS (HTTP permitted only for localhost)"); }
            if !temperature.is_finite() || !(0.0..=2.0).contains(temperature) || *max_tokens == 0 { bail!("invalid generation parameters"); }
            for p in [input_cost_per_million, output_cost_per_million].into_iter().flatten() { if !p.is_finite() || *p < 0.0 { bail!("invalid token pricing"); } }
        }
        Ok(())
    }
}
