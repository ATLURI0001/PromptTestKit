use crate::{regression::Comparison, runner::{validate_run, Run}};
use anyhow::Result;
use std::{fmt::Write, fs, path::Path};

/// Escape untrusted model outputs before inserting them into HTML or XML.
pub fn escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars().filter(|c| *c == '\n' || *c == '\r' || *c == '\t' || (*c >= ' ' && *c != '\u{fffe}' && *c != '\u{ffff}')) {
        match c {
            '&' => out.push_str("&amp;"), '<' => out.push_str("&lt;"), '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"), '\'' => out.push_str("&#39;"), _ => out.push(c),
        }
    }
    out
}
pub fn write_run(run: &Run, dir: &Path) -> Result<()> {
    validate_run(run)?;
    fs::create_dir_all(dir)?;
    fs::write(dir.join("run.json"), serde_json::to_vec_pretty(run)?)?;
    let m = &run.metrics;
    let mut md = format!("# PromptTestKit — {} / {}\n\nProvider: {}\n\n| Metric | Value |\n|---|---:|\n| Samples | {} |\n| Pass rate | {:.2}% |\n| Mean score | {:.4} |\n| Provider errors | {} |\n| p50 latency | {:.2} ms |\n| p95 latency | {:.2} ms |\n| Cost USD | {} |\n\nPrompt SHA-256: `{}`\n\nContract SHA-256: `{}`\n\n| Case | Repeat | Score | Passed |\n|---|---:|---:|---|\n", inline(&run.suite), inline(&run.version), inline(&run.provider),m.samples,m.pass_rate*100.0,m.mean_score,m.errors,m.p50_latency_ms,m.p95_latency_ms,m.total_cost_usd.map_or("unavailable".into(),|v| format!("{v:.8}")),run.prompt_sha256,run.contract_sha256);
    let mut rows = String::new();
    let mut xml = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuite name=\"{}\" tests=\"{}\" failures=\"{}\" errors=\"{}\">\n", escape(&run.suite), m.samples, run.results.iter().filter(|s| !s.passed && s.error.is_none()).count(),m.errors);
    for s in &run.results {
        writeln!(md,"| {} | {} | {:.4} | {} |",inline(&s.case_id),s.repeat,s.score,s.passed)?;
        write!(rows,"<tr><td>{}</td><td>{}</td><td>{:.3}</td><td class=\"{}\">{}</td><td><details><summary>Output &amp; checks</summary><pre>{}</pre><pre>{}</pre>{}</details></td></tr>",escape(&s.case_id),s.repeat,s.score,if s.passed {"pass"} else {"fail"},if s.passed {"PASS"} else {"FAIL"},escape(&s.output),escape(&serde_json::to_string_pretty(&s.checks)?),escape(s.error.as_deref().unwrap_or("")))?;
        write!(xml,"<testcase classname=\"{}\" name=\"{}[{}]\" time=\"{:.6}\">",escape(&run.version),escape(&s.case_id),s.repeat,s.latency_ms/1000.0)?;
        if let Some(e) = &s.error { write!(xml,"<error message=\"provider error\">{}</error>",escape(e))?; }
        else if !s.passed { write!(xml,"<failure message=\"assertion failed\">{}</failure>",escape(&serde_json::to_string(&s.checks)?))?; }
        writeln!(xml,"</testcase>")?;
    }
    xml.push_str("</testsuite>\n");
    let body = format!("<h1>PromptTestKit</h1><p>{} / {} · {}</p><section><b>{:.1}% pass</b><b>{:.3} score</b><b>{} samples</b><b>{} errors</b></section><p>p50 {:.2} ms · p95 {:.2} ms · Cost USD: {}</p><p>Prompt fingerprint <code>{}</code></p><table><thead><tr><th>Case</th><th>Repeat</th><th>Score</th><th>Status</th><th>Details</th></tr></thead><tbody>{rows}</tbody></table>",escape(&run.suite),escape(&run.version),escape(&run.provider),m.pass_rate*100.0,m.mean_score,m.samples,m.errors,m.p50_latency_ms,m.p95_latency_ms,m.total_cost_usd.map_or("unavailable".into(),|v| format!("{v:.8}")),escape(&run.prompt_sha256));
    fs::write(dir.join("report.md"),md)?;
    fs::write(dir.join("report.html"),html(&body))?;
    fs::write(dir.join("junit.xml"),xml)?;
    Ok(())
}
fn inline(s: &str) -> String { escape(s).replace('|',"&#124;").replace(['\n','\r']," ") }
fn html(body: &str) -> String {
    format!("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\"><title>PromptTestKit report</title><style>body{{font:16px system-ui,sans-serif;background:#101621;color:#e5ecf6;max-width:1200px;margin:40px auto;padding:0 24px}}h1{{letter-spacing:-1px}}section{{display:flex;flex-wrap:wrap;gap:16px;margin:24px 0}}b{{padding:20px;background:#1c293a;border-radius:8px}}table{{border-collapse:collapse;width:100%;margin-top:24px}}td,th{{text-align:left;padding:14px;border-bottom:1px solid #334155;vertical-align:top}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;max-width:680px;font-size:13px}}code{{overflow-wrap:anywhere}}.pass{{color:#6ee7b7}}.fail{{color:#fda4af}}summary{{cursor:pointer}}</style></head><body>{body}</body></html>")
}
pub fn write_comparison(c: &Comparison, dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    fs::write(dir.join("comparison.json"),serde_json::to_vec_pretty(c)?)?;
    let status = if c.passed {"PASS"} else {"REGRESSION"};
    let mut md = format!("# PromptTestKit regression report: {status}\n\n{} → {}\n\nMean score delta: {:+.4}; pass-rate delta: {:+.4}\n\n",inline(&c.baseline),inline(&c.candidate),c.score_delta,c.pass_rate_delta);
    let mut body = format!("<h1>{status}</h1><p>{} → {}</p><p>Score delta {:+.4} · Pass-rate delta {:+.4}</p><ul>",escape(&c.baseline),escape(&c.candidate),c.score_delta,c.pass_rate_delta);
    for v in &c.violations { writeln!(md,"- {}",inline(v))?; write!(body,"<li>{}</li>",escape(v))?; }
    md.push_str("\n| Case | Baseline | Candidate | Delta |\n|---|---:|---:|---:|\n");
    body.push_str("</ul><table><tr><th>Case</th><th>Baseline</th><th>Candidate</th><th>Delta</th></tr>");
    for d in &c.cases {
        writeln!(md,"| {} | {:.4} | {:.4} | {:+.4} |",inline(&d.case_id),d.baseline_score,d.candidate_score,d.delta)?;
        write!(body,"<tr><td>{}</td><td>{:.4}</td><td>{:.4}</td><td>{:+.4}</td></tr>",escape(&d.case_id),d.baseline_score,d.candidate_score,d.delta)?;
    }
    body.push_str("</table>");
    fs::write(dir.join("regression.md"),md)?;
    fs::write(dir.join("regression.html"),html(&body))?;
    Ok(())
}
