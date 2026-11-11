use prompttestkit::{config::{self, Assertion}, evaluate::{evaluate, render}, report::escape};
use std::{collections::BTreeMap, path::Path};

#[test]
fn templates_are_single_pass_and_unicode_safe() {
    let vars = BTreeMap::from([("message".into(),"తెలుగు {{missing}}".into())]);
    assert_eq!(render("Input: {{ message }}",&vars).unwrap(),"Input: తెలుగు {{missing}}");
    assert!(render("{{unknown}}",&vars).is_err());
    assert!(render("{{message",&vars).is_err());
    assert!(render("{{}}",&vars).is_err());
}
#[test]
fn assertion_types_and_strict_json() {
    let assertions = vec![
        Assertion::Exact {value:" hello ".into()},
        Assertion::Contains {value:"ell".into()},
        Assertion::NotContains {value:"secret".into()},
        Assertion::Regex {pattern:"^hello$".into()},
        Assertion::MaxChars {value:5},
    ];
    assert!(evaluate("hello",&assertions).iter().all(|c| c.passed));
    assert!(evaluate("é🦀",&[Assertion::MaxChars {value:2}])[0].passed);
    let json = vec![Assertion::Json,Assertion::JsonPointer {pointer:"/a/0".into(),value:serde_json::json!(42)}];
    assert!(evaluate("{\"a\":[42]}",&json).iter().all(|c| c.passed));
    assert!(!evaluate("```json\n{}\n```",&json)[0].passed);
    assert!(!evaluate("{}",&json)[1].passed);
    assert!(!evaluate("{\"a\":[\"42\"]}",&json)[1].passed);
}
#[test]
fn reports_escape_untrusted_text() {
    assert_eq!(escape("<script>\"a&b\"</script>\0"),"&lt;script&gt;&quot;a&amp;b&quot;&lt;/script&gt;");
}
#[test]
fn example_suites_validate() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    for name in ["suite.toml","api-suite.toml"] {
        let (_,cases,_) = config::load(&root.join(name)).unwrap();
        assert_eq!(cases.len(),4);
    }
}
#[test]
fn rejects_empty_duplicate_cases_and_bad_regex() {
    assert!(config::validate_cases(&[]).is_err());
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/suite.toml");
    let (_,mut cases,_) = config::load(&root).unwrap();
    cases.push(cases[0].clone());
    assert!(config::validate_cases(&cases).is_err());
    cases.pop();
    cases[0].assertions = vec![Assertion::Regex {pattern:"[".into()}];
    assert!(config::validate_cases(&cases).is_err());
}
#[test]
fn rejects_invalid_execution_gates_and_insecure_endpoints() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/api-suite.toml");
    let (mut suite,_,_) = config::load(&root).unwrap();
    suite.execution.concurrency = 0;
    assert!(suite.validate().is_err());
    suite.execution.concurrency = 1;
    suite.gates.min_pass_rate = f64::NAN;
    assert!(suite.validate().is_err());
    suite.gates.min_pass_rate = 1.0;
    if let config::ProviderConfig::ChatCompletions {endpoint,..} = &mut suite.provider { *endpoint = "http://example.com/v1/chat/completions".into(); }
    assert!(suite.validate().is_err());
    if let config::ProviderConfig::ChatCompletions {endpoint,..} = &mut suite.provider { *endpoint = "https://user:password@example.com/".into(); }
    assert!(suite.validate().is_err());
}
