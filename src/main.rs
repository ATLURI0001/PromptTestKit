use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use prompttestkit::{config, regression, report, runner};
use std::{fs, path::{Path, PathBuf}, process::ExitCode};

#[derive(Parser)]
#[command(version, about = "Evaluation infrastructure for prompt evolution—versioned test suites, assertion-driven scoring, and granular regression gates that turn behavioral changes into auditable release decisions.")]
struct Cli { #[command(subcommand)] command: Command }
#[derive(Subcommand)]
enum Command {
    /// Create a standalone offline example suite in a new directory.
    Init { #[arg(default_value = "prompttestkit-demo")] directory: PathBuf },
    /// Validate suite, templates, assertions and fixture coverage without API calls.
    Validate { #[arg(short, long, default_value = "examples/suite.toml")] suite: PathBuf },
    /// Execute one version; write reports even when assertions fail.
    Run {
        #[arg(short, long, default_value = "examples/suite.toml")] suite: PathBuf,
        #[arg(short, long)] version: String,
        #[arg(short, long)] out: PathBuf,
    },
    /// Compare saved runs and fail CI on regressions. Uses candidate gates.
    Compare {
        #[arg(long)] baseline: PathBuf,
        #[arg(long)] candidate: PathBuf,
        #[arg(short, long)] out: PathBuf,
    },
    /// Regenerate HTML, Markdown and JUnit reports from a saved run.
    Report { #[arg(long)] run: PathBuf, #[arg(short, long)] out: PathBuf },
}
#[tokio::main]
async fn main() -> ExitCode {
    match execute(Cli::parse()).await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => { eprintln!("error: {e:#}"); ExitCode::from(2) }
    }
}
async fn execute(cli: Cli) -> Result<bool> {
    match cli.command {
        Command::Init { directory } => {
            if directory.exists() { bail!("destination already exists; choose a new directory"); }
            fs::create_dir_all(directory.join("prompts"))?;
            fs::create_dir_all(directory.join("fixtures"))?;
            for (name,contents) in [
                ("suite.toml",include_str!("../examples/suite.toml")),
                ("dataset.json",include_str!("../examples/dataset.json")),
                ("prompts/v1.txt",include_str!("../examples/prompts/v1.txt")),
                ("prompts/v2.txt",include_str!("../examples/prompts/v2.txt")),
                ("prompts/broken.txt",include_str!("../examples/prompts/broken.txt")),
                ("fixtures/v1.json",include_str!("../examples/fixtures/v1.json")),
                ("fixtures/v2.json",include_str!("../examples/fixtures/v2.json")),
                ("fixtures/broken.json",include_str!("../examples/fixtures/broken.json")),
            ] { fs::write(directory.join(name),contents)?; }
            println!("Created {}",directory.display()); Ok(true)
        }
        Command::Validate { suite } => {
            let (s,c,_) = config::load(&suite)?;
            println!("Valid: {} · {} cases · {} versions",s.name,c.len(),s.prompts.len()); Ok(true)
        }
        Command::Run { suite, version, out } => {
            let (s,c,root) = config::load(&suite)?;
            protect_output(&out,&[&suite, &root.join(&s.dataset)], &s, &root)?;
            let r = runner::run(&s,&c,&root,&version).await?;
            report::write_run(&r,&out)?;
            println!("{}: {:.1}% pass, {:.3} score, {} errors → {}",version,r.metrics.pass_rate*100.0,r.metrics.mean_score,r.metrics.errors,out.display());
            Ok(r.metrics.errors == 0 && r.metrics.pass_rate + 1e-9 >= s.gates.min_pass_rate)
        }
        Command::Compare { baseline, candidate, out } => {
            prevent_artifact_overwrite(&out,&[&baseline,&candidate])?;
            let c = regression::compare(&runner::read_run(&baseline)?,&runner::read_run(&candidate)?)?;
            report::write_comparison(&c,&out)?;
            println!("{} → {}: {}",c.baseline,c.candidate,if c.passed {"PASS"} else {"REGRESSION"});
            for v in &c.violations { println!("  - {v}"); }
            Ok(c.passed)
        }
        Command::Report { run, out } => {
            prevent_artifact_overwrite(&out,&[&run])?;
            report::write_run(&runner::read_run(&run)?,&out)?; println!("Reports: {}",out.display()); Ok(true)
        }
    }
}
fn prevent_artifact_overwrite(out: &Path, inputs: &[&Path]) -> Result<()> {
    for name in ["run.json","report.md","report.html","junit.xml","comparison.json","regression.md","regression.html"] {
        let target = out.join(name);
        if target.exists() {
            let target = target.canonicalize()?;
            for input in inputs { if input.canonicalize()? == target { bail!("output would overwrite an input file"); } }
        }
    }
    Ok(())
}
fn protect_output(out: &Path, inputs: &[&Path], suite: &config::Suite, root: &Path) -> Result<()> {
    let mut paths = inputs.iter().map(|p| p.to_path_buf()).collect::<Vec<_>>();
    paths.extend(suite.prompts.values().map(|p| root.join(p)));
    if let config::ProviderConfig::Fixture { responses } = &suite.provider { paths.extend(responses.values().map(|p| root.join(p))); }
    prevent_artifact_overwrite(out,&paths.iter().map(PathBuf::as_path).collect::<Vec<_>>())
}
