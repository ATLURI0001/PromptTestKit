use crate::config::Assertion;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check { pub assertion: Assertion, pub passed: bool }

/// One-pass substitution: variable contents are never interpreted as templates.
pub fn render(template: &str, vars: &BTreeMap<String, String>) -> Result<String> {
    let mut rest = template;
    let mut out = String::new();
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let tail = &rest[start + 2..];
        let end = tail.find("}}").ok_or_else(|| anyhow::anyhow!("unclosed template variable"))?;
        let name = tail[..end].trim();
        if name.is_empty() { bail!("empty template variable"); }
        out.push_str(vars.get(name).ok_or_else(|| anyhow::anyhow!("missing variable {name}"))?);
        rest = &tail[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}
pub fn evaluate(output: &str, assertions: &[Assertion]) -> Vec<Check> {
    assertions.iter().map(|a| {
        let passed = match a {
            Assertion::Exact { value } => output.trim() == value.trim(),
            Assertion::Contains { value } => output.contains(value),
            Assertion::NotContains { value } => !output.contains(value),
            Assertion::Regex { pattern } => regex::Regex::new(pattern).is_ok_and(|r| r.is_match(output)),
            Assertion::Json => serde_json::from_str::<serde_json::Value>(output).is_ok(),
            Assertion::JsonPointer { pointer, value } => serde_json::from_str::<serde_json::Value>(output).is_ok_and(|v| v.pointer(pointer) == Some(value)),
            Assertion::MaxChars { value } => output.chars().count() <= *value,
        };
        Check { assertion: a.clone(), passed }
    }).collect()
}
