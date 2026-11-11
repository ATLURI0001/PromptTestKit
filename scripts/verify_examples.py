"""Static package checks; this does NOT compile or execute the Rust program."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]


def check(output: str, assertion: dict) -> bool:
    kind = assertion["type"]
    if kind == "exact":
        return output.strip() == assertion["value"].strip()
    if kind == "contains":
        return assertion["value"] in output
    if kind == "not_contains":
        return assertion["value"] not in output
    if kind == "max_chars":
        return len(output) <= assertion["value"]
    if kind == "regex":
        # Example patterns are in the common subset of Python and Rust regex.
        return re.search(assertion["pattern"], output) is not None
    try:
        value = json.loads(output)
    except json.JSONDecodeError:
        return False
    if kind == "json":
        return True
    if kind == "json_pointer":
        try:
            pointer = assertion["pointer"]
            for part in pointer.split("/")[1:] if pointer else []:
                part = part.replace("~1", "/").replace("~0", "~")
                value = value[int(part)] if isinstance(value, list) else value[part]
            return type(value) is type(assertion["value"]) and value == assertion["value"]
        except (KeyError, IndexError, ValueError, TypeError):
            return False
    raise AssertionError(f"Unknown assertion {kind}")


def main() -> None:
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    assert manifest["package"]["name"] == "prompttestkit"
    for source in (ROOT / "examples").rglob("*.json"):
        json.loads(source.read_text(encoding="utf-8"))
    for source in ROOT.rglob("*.toml"):
        tomllib.loads(source.read_text(encoding="utf-8"))
    suite = tomllib.loads((ROOT / "examples/suite.toml").read_text(encoding="utf-8"))
    cases = json.loads((ROOT / "examples" / suite["dataset"]).read_text(encoding="utf-8"))
    ids = {case["id"] for case in cases}
    assert len(ids) == len(cases) and all(ids)
    outcomes = {}
    for version, prompt_path in suite["prompts"].items():
        template = (ROOT / "examples" / prompt_path).read_text(encoding="utf-8")
        fixtures = json.loads((ROOT / "examples" / suite["provider"]["responses"][version]).read_text(encoding="utf-8"))
        assert ids <= fixtures.keys()
        results = []
        for case in cases:
            assert case["assertions"]
            for variable in re.findall(r"\{\{\s*(\w+)\s*\}\}", template):
                assert variable in case["variables"]
            checks = [check(fixtures[case["id"]], a) for a in case["assertions"]]
            results.append({"case": case["id"], "passed": all(checks), "score": sum(checks) / len(checks)})
        outcomes[version] = {"expected_samples": len(cases) * suite["execution"]["repeats"], "expected_pass_rate": sum(r["passed"] for r in results) / len(results), "expected_mean_score": sum(r["score"] for r in results) / len(results), "cases": results}
    assert outcomes["v1"]["expected_pass_rate"] == 1.0
    assert outcomes["v2"]["expected_pass_rate"] == 1.0
    assert outcomes["broken"]["expected_pass_rate"] == 0.0
    required = ["src/main.rs", "src/lib.rs", "src/config.rs", "src/evaluate.rs", "src/provider.rs", "src/runner.rs", "src/regression.rs", "src/report.rs", ".github/workflows/ci.yml", "README.md", "LICENSE", "tests/evaluation.rs", "tests/pipeline.rs", "tests/provider.rs"]
    assert all((ROOT / name).is_file() for name in required)
    test_count = sum(len(re.findall(r"#\[(?:tokio::)?test\]", path.read_text(encoding="utf-8"))) for path in (ROOT / "tests").glob("*.rs"))
    report = {"validation_kind": "static example and package checks (Python)", "performed_utc": datetime.now(timezone.utc).isoformat(), "status": "passed", "rust_build_executed": False, "rust_tests_executed": False, "rust_test_functions_present": test_count, "expected_fixture_results": outcomes, "notes": ["Fixture expectations are independently calculated, not Rust execution results.", "Cargo/rustc are unavailable in the delivery environment; CI must confirm the Rust build."], "source_sha256": {str(p.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT / "src").glob("*.rs"))}}
    destination = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "VALIDATION.json"
    destination.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"Static checks passed; {test_count} Rust tests present (not executed).")
    print(f"Expected fixture pass rates: { {v: r['expected_pass_rate'] for v, r in outcomes.items()} }")


if __name__ == "__main__":
    main()
