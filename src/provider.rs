use crate::config::{Execution, ProviderConfig};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path, time::Duration};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Usage { pub input_tokens: Option<u64>, pub output_tokens: Option<u64>, pub cost_usd: Option<f64> }
pub struct Completion { pub text: String, pub usage: Usage }
#[derive(Clone)]
pub struct Provider {
    config: ProviderConfig,
    fixtures: BTreeMap<String, String>,
    client: reqwest::Client,
    key: Option<String>,
    execution: Execution,
}
impl Provider {
    pub fn new(config: &ProviderConfig, execution: &Execution, root: &Path, version: &str) -> Result<Self> {
        let mut fixtures = BTreeMap::new();
        let mut key = None;
        match config {
            ProviderConfig::Fixture { responses } => {
                let file = responses.get(version).context("missing version fixture")?;
                fixtures = serde_json::from_str(&std::fs::read_to_string(root.join(file))?)?;
            }
            ProviderConfig::ChatCompletions { api_key_env, .. } => {
                let value = std::env::var(api_key_env).with_context(|| format!("set environment variable {api_key_env}"))?;
                if value.trim().is_empty() { bail!("API key environment variable is empty"); }
                key = Some(value);
            }
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(execution.timeout_seconds))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self { config: config.clone(), fixtures, client, key, execution: execution.clone() })
    }

    /// Per-attempt deadlines plus bounded retries. Error bodies and URLs are not logged.
    pub async fn complete(&self, case: &str, prompt: &str) -> Result<Completion> {
        match &self.config {
            ProviderConfig::Fixture { .. } => Ok(Completion {
                text: self.fixtures.get(case).context("fixture case missing")?.clone(),
                usage: Usage::default(),
            }),
            ProviderConfig::ChatCompletions { endpoint, model, temperature, max_tokens, input_cost_per_million, output_cost_per_million, .. } => {
                for attempt in 0..=self.execution.retries {
                    let result = self.client.post(endpoint)
                        .bearer_auth(self.key.as_deref().unwrap_or_default())
                        .json(&serde_json::json!({
                            "model": model, "temperature": temperature, "max_tokens": max_tokens,
                            "messages": [{"role":"user", "content":prompt}]
                        })).send().await;
                    let response = match result {
                        Ok(r) => r,
                        Err(e) => {
                            if attempt < self.execution.retries && (e.is_timeout() || e.is_connect()) {
                                backoff(attempt).await; continue;
                            }
                            bail!("provider transport failure (attempt {}): timeout={}", attempt + 1, e.is_timeout());
                        }
                    };
                    let status = response.status();
                    if !status.is_success() {
                        if attempt < self.execution.retries && (status.as_u16() == 429 || status.is_server_error()) {
                            backoff(attempt).await; continue;
                        }
                        bail!("provider HTTP {} after {} attempt(s)", status.as_u16(), attempt + 1);
                    }
                    let data: serde_json::Value = response.json().await.map_err(|_| anyhow::anyhow!("invalid provider JSON response"))?;
                    let text = data.pointer("/choices/0/message/content").and_then(|v| v.as_str()).context("provider response missing text content")?.to_owned();
                    let input = data.pointer("/usage/prompt_tokens").and_then(|v| v.as_u64());
                    let output = data.pointer("/usage/completion_tokens").and_then(|v| v.as_u64());
                    let cost = input.zip(output).zip(input_cost_per_million.zip(*output_cost_per_million)).map(|((i,o),(ip,op))| (i as f64 * ip + o as f64 * op) / 1_000_000.0);
                    return Ok(Completion { text, usage: Usage { input_tokens: input, output_tokens: output, cost_usd: cost } });
                }
                unreachable!("retry loop returns on final attempt")
            }
        }
    }
}
async fn backoff(attempt: u32) { tokio::time::sleep(Duration::from_millis(250 * (1u64 << attempt))).await; }
