use prompttestkit::{config::{Execution,ProviderConfig}, provider::Provider};
use std::{collections::BTreeMap, path::Path};
use tokio::{io::{AsyncReadExt,AsyncWriteExt},net::TcpListener};

async fn server(replies: Vec<(u16,&'static str)>) -> (String,tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1/chat/completions",listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for (code,body) in replies {
            let (mut socket,_) = tokio::time::timeout(std::time::Duration::from_secs(5),listener.accept()).await.unwrap().unwrap();
            let mut buffer = Vec::new();
            loop {
                let mut chunk = [0u8;4096];
                let n = socket.read(&mut chunk).await.unwrap();
                if n == 0 { break; }
                buffer.extend_from_slice(&chunk[..n]);
                if let Some(index) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&buffer[..index]).to_lowercase();
                    let len = headers.lines().find_map(|l| l.strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok())).unwrap_or(0);
                    if buffer.len() >= index+4+len { break; }
                }
            }
            requests.push(String::from_utf8_lossy(&buffer).into_owned());
            let response = format!("HTTP/1.1 {code} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len());
            socket.write_all(response.as_bytes()).await.unwrap();
        }
        requests
    });
    (endpoint,task)
}
fn config(endpoint: String,key_env: &str) -> ProviderConfig {
    ProviderConfig::ChatCompletions {endpoint,model:"test-model".into(),api_key_env:key_env.into(),temperature:0.0,max_tokens:32,input_cost_per_million:Some(1.0),output_cost_per_million:Some(2.0)}
}
const SUCCESS: &str = r#"{"choices":[{"message":{"content":"hello"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}"#;

#[tokio::test]
async fn http_retries_rate_limits_and_tracks_usage() {
    let (endpoint,task) = server(vec![(429,"{}"),(200,SUCCESS)]).await;
    std::env::set_var("PROMPTTESTKIT_TEST_RETRY_KEY","test-key");
    let p = Provider::new(&config(endpoint,"PROMPTTESTKIT_TEST_RETRY_KEY"),&Execution {retries:1,..Execution::default()},Path::new("."),"v1").unwrap();
    let completion = p.complete("case","test input").await.unwrap();
    assert_eq!(completion.text,"hello");
    assert!((completion.usage.cost_usd.unwrap()-0.00002).abs() < 1e-12);
    let requests = task.await.unwrap();
    assert_eq!(requests.len(),2);
    assert!(requests[0].contains("test input"));
    assert!(requests[0].to_lowercase().contains("authorization: bearer test-key"));
}
#[tokio::test]
async fn auth_errors_are_not_retried_or_leaked() {
    let (endpoint,task) = server(vec![(401,"secret-body-DO-NOT-LOG")]).await;
    std::env::set_var("PROMPTTESTKIT_TEST_AUTH_KEY","secret-key-DO-NOT-LOG");
    let p = Provider::new(&config(endpoint,"PROMPTTESTKIT_TEST_AUTH_KEY"),&Execution::default(),Path::new("."),"v1").unwrap();
    let error = p.complete("case","input").await.err().unwrap().to_string();
    assert!(error.contains("401"));
    assert!(error.contains("1 attempt"));
    assert!(!error.contains("DO-NOT-LOG"));
    assert_eq!(task.await.unwrap().len(),1);
}
#[tokio::test]
async fn malformed_success_is_a_failure() {
    let (endpoint,task) = server(vec![(200,"{\"choices\":[]}")]).await;
    std::env::set_var("PROMPTTESTKIT_TEST_SHAPE_KEY","test-key");
    let p = Provider::new(&config(endpoint,"PROMPTTESTKIT_TEST_SHAPE_KEY"),&Execution::default(),Path::new("."),"v1").unwrap();
    assert!(p.complete("case","input").await.is_err());
    task.await.unwrap();
}
#[test]
fn missing_credentials_fail_before_network() {
    let p = Provider::new(&config("http://127.0.0.1:1/".into(),"PROMPTTESTKIT_TEST_MISSING_KEY_89217"),&Execution::default(),Path::new("."),"v1");
    assert!(p.is_err());
}
#[tokio::test]
async fn missing_usage_is_not_zero_cost() {
    let (endpoint,task) = server(vec![(200,r#"{"choices":[{"message":{"content":"hello"}}]}"#)]).await;
    std::env::set_var("PROMPTTESTKIT_TEST_USAGE_KEY","test-key");
    let p = Provider::new(&config(endpoint,"PROMPTTESTKIT_TEST_USAGE_KEY"),&Execution::default(),Path::new("."),"v1").unwrap();
    assert_eq!(p.complete("case","input").await.unwrap().usage.cost_usd,None);
    task.await.unwrap();
}
#[test]
fn fixture_provider_rejects_missing_files() {
    let cfg = ProviderConfig::Fixture {responses:BTreeMap::from([("v1".into(),"does-not-exist-89217.json".into())])};
    assert!(Provider::new(&cfg,&Execution::default(),Path::new("."),"v1").is_err());
}

#[tokio::test]
async fn server_errors_exhaust_bounded_retry_budget() {
    let (endpoint,task) = server(vec![(503,"private diagnostic"),(503,"private diagnostic")]).await;
    std::env::set_var("PROMPTTESTKIT_TEST_EXHAUST_KEY","test-key");
    let p = Provider::new(&config(endpoint,"PROMPTTESTKIT_TEST_EXHAUST_KEY"),&Execution {retries:1,..Execution::default()},Path::new("."),"v1").unwrap();
    let error = p.complete("case","input").await.err().unwrap().to_string();
    assert!(error.contains("2 attempt"));
    assert!(!error.contains("private diagnostic"));
    assert_eq!(task.await.unwrap().len(),2);
}

#[tokio::test]
async fn runner_records_provider_errors_instead_of_aborting() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/suite.toml");
    let (mut suite,mut cases,root) = prompttestkit::config::load(&path).unwrap();
    cases.truncate(1);
    let (endpoint,task) = server(vec![(401,"private diagnostic")]).await;
    std::env::set_var("PROMPTTESTKIT_TEST_RUN_ERROR_KEY","test-key");
    suite.provider = config(endpoint,"PROMPTTESTKIT_TEST_RUN_ERROR_KEY");
    suite.execution.repeats = 1;
    let run = prompttestkit::runner::run(&suite,&cases,&root,"v1").await.unwrap();
    assert_eq!(run.metrics.errors,1);
    assert_eq!(run.results[0].score,0.0);
    assert!(!run.results[0].passed);
    prompttestkit::runner::validate_run(&run).unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn per_attempt_timeout_is_enforced() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1/chat/completions",listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (socket,_) = listener.accept().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        drop(socket);
    });
    std::env::set_var("PROMPTTESTKIT_TEST_TIMEOUT_KEY","test-key");
    let p = Provider::new(&config(endpoint,"PROMPTTESTKIT_TEST_TIMEOUT_KEY"),&Execution {timeout_seconds:1,retries:0,..Execution::default()},Path::new("."),"v1").unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(4),p.complete("case","input")).await.unwrap();
    assert!(result.err().unwrap().to_string().contains("timeout=true"));
    task.await.unwrap();
}
