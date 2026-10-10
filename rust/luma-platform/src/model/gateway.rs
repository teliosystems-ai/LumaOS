//! Runtime work executes in the existing leased supervisor, not in the broker.
use super::*;
use crate::resource_manager::requests::gateway::{
    self as wire, ChatMessage, Message, Output, Permit, Status,
};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

pub(super) struct Driver {
    ready: bool,
    key: String,
    startup_until: u64,
}
impl Driver {
    pub(super) fn new(state: &Path) -> Result<Self> {
        let key = activation_bytes(&state.join("model-auth/api-key"), 64)?
            .ok_or("gateway runtime key absent")?;
        if key.len() != 64 || !key.iter().all(u8::is_ascii_hexdigit) {
            return Err("gateway runtime key invalid".into());
        }
        Ok(Self {
            ready: false,
            key: String::from_utf8(key)?,
            startup_until: crate::resource_manager::now()?
                .checked_add(1_800_000)
                .ok_or("gateway startup deadline overflow")?,
        })
    }
    pub(super) fn tick(
        &mut self,
        profile: &Profile,
        lease: &crate::resource_manager::WorkerLease,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        check()?;
        if !self.ready {
            if crate::resource_manager::now()? >= self.startup_until {
                return Err("gateway runtime startup deadline expired".into());
            }
            let until = crate::resource_manager::now()?
                .checked_add(1000)
                .ok_or("readiness deadline overflow")?
                .min(self.startup_until);
            match http("GET", "/v1/models", None, &self.key, until, &mut check) {
                Ok((200, raw)) => {
                    #[derive(Deserialize)]
                    struct Models {
                        data: Vec<Model>,
                    }
                    #[derive(Deserialize)]
                    struct Model {
                        id: String,
                    }
                    let models: Models = runtime_json(&raw)?;
                    if models.data.len() != 1 || models.data[0].id != profile.id {
                        return Err("gateway runtime alias differs".into());
                    }
                    match exchange(Message::Ready {
                        worker: lease.token().clone(),
                    })? {
                        Status::Ready { worker } if &worker == lease.token() => self.ready = true,
                        _ => return Err("gateway readiness reply differs".into()),
                    }
                }
                Ok((503, _)) => return Ok(()),
                Err(error)
                    if error.downcast_ref::<std::io::Error>().map_or(false, |e| {
                        matches!(
                            e.kind(),
                            std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::TimedOut
                        )
                    }) =>
                {
                    return Ok(())
                }
                _ => return Err("gateway runtime readiness failed".into()),
            }
        }
        match exchange(Message::Claim {
            worker: lease.token().clone(),
        })? {
            Status::Idle {} => Ok(()),
            Status::Job { messages, receipt } => {
                let operation = self.run(profile, lease.token(), messages, &receipt, &mut check);
                if operation.is_err() {
                    let _ = exchange(Message::Cancel {
                        nonce: receipt.nonce,
                        worker: receipt.worker,
                    });
                }
                operation
            }
            _ => Err("gateway claim reply differs".into()),
        }
    }
    fn run(
        &self,
        profile: &Profile,
        worker: &crate::resources::Token,
        mut messages: Vec<ChatMessage>,
        receipt: &Permit,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        self.run_with(
            profile,
            worker,
            &mut messages,
            receipt,
            check,
            &mut exchange,
        )
    }
    fn run_with(
        &self,
        profile: &Profile,
        worker: &crate::resources::Token,
        messages: &mut Vec<ChatMessage>,
        receipt: &Permit,
        check: &mut impl FnMut() -> Result<()>,
        exchange: &mut impl FnMut(Message) -> Result<Status>,
    ) -> Result<()> {
        wire::messages_valid(messages)?;
        if receipt.kind != "permit"
            || receipt.phase != "preparing"
            || &receipt.worker != worker
            || receipt.profile != profile.id
            || receipt.input_digest != wire::input_digest(messages)?
            || receipt.context_tokens != 2048
            || !(1..=128).contains(&receipt.max_output_tokens)
            || receipt.slot_released
            || receipt.worker_resources_released
            || receipt.prompt_tokens.is_some()
            || receipt.output_tokens.is_some()
            || receipt.token_digest.is_some()
            || receipt.result_digest.is_some()
            || messages.is_empty()
            || messages.len() > 16
            || messages.last().unwrap().role != "user"
        {
            return Err("gateway preparing receipt differs".into());
        }
        messages.last_mut().unwrap().content.push_str(" /no_think");
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Template {
            prompt: String,
        }
        let template: Template = post(
            "/apply-template",
            &serde_json::json!({"messages":messages,"chat_template_kwargs":{"enable_thinking":false}}),
            &self.key,
            receipt.request_deadline,
            check,
        )?;
        if template.prompt.is_empty() {
            return Err("gateway template absent".into());
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Tokens {
            tokens: Vec<i32>,
        }
        let tokens: Tokens = post(
            "/tokenize",
            &serde_json::json!({"content":template.prompt,"add_special":true,"parse_special":true,"with_pieces":false}),
            &self.key,
            receipt.request_deadline,
            check,
        )?;
        if tokens.tokens.is_empty()
            || tokens.tokens.len() > 2048
            || tokens.tokens.iter().any(|t| *t < 0)
            || tokens.tokens.len() as u64 + receipt.max_output_tokens > receipt.context_tokens
        {
            return Err("gateway rendered context exceeds reservation".into());
        }
        let count = tokens.tokens.len() as u64;
        let digest = bundle::hex(&Sha256::digest(serde_json::to_vec(&tokens.tokens)?));
        let mut admitted = receipt.clone();
        admitted.phase = "admitted".into();
        admitted.prompt_tokens = Some(count);
        admitted.token_digest = Some(digest.clone());
        permit(
            exchange(Message::Admit {
                nonce: receipt.nonce.clone(),
                worker: worker.clone(),
                prompt_tokens: count,
                token_digest: digest,
            })?,
            &admitted,
        )?;
        let completion: Completion = post(
            "/completion",
            &serde_json::json!({"prompt":tokens.tokens,"n_predict":receipt.max_output_tokens,
            "temperature":0.7,"stream":false,"cache_prompt":false,"n_cmpl":1,"id_slot":0,"return_tokens":false}),
            &self.key,
            receipt.request_deadline,
            check,
        )?;
        let output = completion.validate(&profile.id, count, receipt.max_output_tokens)?;
        let mut finished = admitted;
        finished.phase = "completed".into();
        finished.output_tokens = Some(output.output_tokens);
        finished.result_digest = Some(wire::output_digest(&output)?);
        finished.slot_released = true;
        permit(
            exchange(Message::Finish {
                nonce: receipt.nonce.clone(),
                worker: worker.clone(),
                output,
            })?,
            &finished,
        )
    }
}
fn exchange(message: Message) -> Result<Status> {
    crate::service::gateway_exchange(&wire::worker_request(message)?)
}
fn permit(status: Status, expected: &Permit) -> Result<()> {
    match status {
        Status::Permit { receipt } if &receipt == expected => Ok(()),
        _ => Err("gateway phase acknowledgement differs".into()),
    }
}

#[derive(Deserialize)]
struct Timings {
    cache_n: u64,
    prompt_n: u64,
    predicted_n: u64,
}
#[derive(Deserialize)]
struct Completion {
    content: String,
    model: String,
    stop: bool,
    stop_type: String,
    truncated: bool,
    tokens_evaluated: u64,
    tokens_predicted: u64,
    tokens_cached: u64,
    timings: Timings,
}
impl Completion {
    fn validate(self, model: &str, prompt: u64, maximum: u64) -> Result<Output> {
        if self.model != model
            || !self.stop
            || !matches!(self.stop_type.as_str(), "eos" | "limit" | "word")
            || self.truncated
            || self.tokens_evaluated != prompt
            || self.tokens_predicted == 0
            || self.tokens_predicted > maximum
            || self.tokens_cached > prompt + maximum
            || self.timings.cache_n != 0
            || self.timings.prompt_n != prompt
            || self.timings.predicted_n != self.tokens_predicted
            || self.content.trim().is_empty()
            || self.content.len() > 8192
        {
            return Err("gateway runtime completion exceeds admitted contract".into());
        }
        Ok(Output {
            text: self.content,
            prompt_tokens: prompt,
            output_tokens: self.tokens_predicted,
        })
    }
}
fn post<T: serde::de::DeserializeOwned>(
    path: &str,
    payload: &serde_json::Value,
    key: &str,
    until: u64,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<T> {
    let (status, raw) = http("POST", path, Some(payload), key, until, check)?;
    if status != 200 {
        return Err("gateway runtime POST refused".into());
    }
    runtime_json(&raw)
}
fn runtime_json<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T> {
    // Runtime-supplied values may contain prompt text. Keep parse diagnostics
    // out of the supervisor journal rather than persisting private content.
    serde_json::from_slice(raw).map_err(|_| "gateway runtime JSON refused".into())
}
fn remaining(until: u64, check: &mut impl FnMut() -> Result<()>) -> Result<Duration> {
    check()?;
    let left = until
        .checked_sub(crate::resource_manager::now()?)
        .filter(|v| *v > 0)
        .ok_or("gateway whole request deadline expired")?;
    Ok(Duration::from_millis(left.min(200)))
}
fn http(
    method: &str,
    path: &str,
    payload: Option<&serde_json::Value>,
    key: &str,
    until: u64,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<(u16, Vec<u8>)> {
    if !matches!(
        (method, path),
        ("GET", "/v1/models")
            | ("POST", "/apply-template")
            | ("POST", "/tokenize")
            | ("POST", "/completion")
    ) || key.len() != 64
        || !key.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("unsupported fixed gateway HTTP authority".into());
    }
    let body = payload
        .map(serde_json::to_vec)
        .transpose()?
        .unwrap_or_default();
    if body.len() > 128 * 1024 {
        return Err("gateway HTTP input exceeds bound".into());
    }
    let mut frame=format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:8081\r\nAuthorization: Bearer {key}\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).into_bytes();
    frame.extend(body);
    let address: SocketAddr = "127.0.0.1:8081".parse()?;
    let mut stream = TcpStream::connect_timeout(&address, remaining(until, check)?)?;
    let mut sent = 0;
    while sent < frame.len() {
        stream.set_write_timeout(Some(remaining(until, check)?))?;
        match stream.write(&frame[sent..]) {
            Ok(0) => return Err("gateway HTTP write ended".into()),
            Ok(count) => sent += count,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(error) => return Err(error.into()),
        }
    }
    let mut raw = Vec::new();
    let mut expected = None;
    let mut parsed = None;
    loop {
        stream.set_read_timeout(Some(remaining(until, check)?))?;
        let mut block = [0u8; 4096];
        match stream.read(&mut block) {
            Ok(0) => return Err("gateway HTTP body truncated".into()),
            Ok(count) => raw.extend_from_slice(&block[..count]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(error) => return Err(error.into()),
        }
        if parsed.is_none() {
            if let Some(end) = raw.windows(4).position(|p| p == b"\r\n\r\n") {
                if end > 8192 {
                    return Err("gateway HTTP headers oversized".into());
                }
                let (status, length) = headers(&raw[..end])?;
                expected = Some(end + 4 + length);
                parsed = Some((status, end + 4));
            } else if raw.len() > 8192 {
                return Err("gateway HTTP headers oversized".into());
            }
        }
        if let Some(total) = expected {
            if raw.len() > total {
                return Err("gateway HTTP framing has trailing data".into());
            }
            if raw.len() == total {
                remaining(until, check)?;
                let (status, begin) = parsed.unwrap();
                return Ok((status, raw[begin..].to_vec()));
            }
        }
    }
}
fn headers(raw: &[u8]) -> Result<(u16, usize)> {
    let text = std::str::from_utf8(raw)?;
    let mut lines = text.split("\r\n");
    let status = lines.next().ok_or("missing HTTP status")?;
    let fields: Vec<_> = status.split(' ').collect();
    if fields.len() < 3 || fields[0] != "HTTP/1.1" || !matches!(fields[1], "200" | "503") {
        return Err("gateway HTTP status/redirect refused".into());
    }
    let mut values = std::collections::BTreeMap::new();
    for line in lines {
        let (key, value) = line.split_once(':').ok_or("invalid HTTP header")?;
        if key.is_empty()
            || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || values
                .insert(key.to_ascii_lowercase(), value.trim())
                .is_some()
        {
            return Err("ambiguous gateway HTTP headers".into());
        }
    }
    if values.contains_key("transfer-encoding")
        || values.contains_key("content-encoding")
        || values.get("content-type").map_or(true, |v| {
            !matches!(*v, "application/json" | "application/json; charset=utf-8")
        })
    {
        return Err("gateway HTTP encoding refused".into());
    }
    let length = values.get("content-length").ok_or("missing HTTP length")?;
    let number: usize = length.parse()?;
    if number == 0 || number > 128 * 1024 || number.to_string() != *length {
        return Err("gateway HTTP length exceeds bound".into());
    }
    Ok((fields[1].parse()?, number))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_runtime_reply_errors_never_echo_private_values_or_field_names() {
        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Number {
            value: u64,
        }
        assert_eq!(runtime_json::<Number>(br#"{"value":1}"#).unwrap().value, 1);
        for raw in [
            br#"{"value":"private-runtime-value"}"#.as_slice(),
            br#"{"private-runtime-field":1}"#,
            b"private-runtime-body",
            br#"{"value":1,"value":2}"#,
        ] {
            assert_eq!(
                runtime_json::<Number>(raw).unwrap_err().to_string(),
                "gateway runtime JSON refused"
            );
        }
    }
    #[test]
    fn http_headers_refuse_redirects_encodings_duplicates_and_unbounded_bodies() {
        let good = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2";
        assert_eq!(headers(good).unwrap(), (200, 2));
        for raw in ["HTTP/1.1 302 Found\r\nContent-Type: application/json\r\nContent-Length: 2",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\ncontent-length: 2",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nTransfer-Encoding: chunked",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 02",
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2"] {assert!(headers(raw.as_bytes()).is_err());}
    }
    #[test]
    fn completion_counts_identity_cache_and_result_bounds_are_checked() {
        let good = serde_json::json!({"content":"hello","model":"fixture","stop":true,"stop_type":"eos","truncated":false,
            "tokens_evaluated":8,"tokens_predicted":1,"tokens_cached":9,"timings":{"cache_n":0,"prompt_n":8,"predicted_n":1}});
        let completion: Completion = serde_json::from_value(good.clone()).unwrap();
        assert_eq!(
            completion.validate("fixture", 8, 16).unwrap().output_tokens,
            1
        );
        for (field, bad) in [
            ("model", serde_json::json!("other")),
            ("tokens_predicted", serde_json::json!(17)),
            ("truncated", serde_json::json!(true)),
            ("tokens_cached", serde_json::json!(25)),
            ("content", serde_json::json!("x".repeat(8193))),
        ] {
            let mut value = good.clone();
            value[field] = bad;
            let completion: Completion = serde_json::from_value(value).unwrap();
            assert!(completion.validate("fixture", 8, 16).is_err());
        }
    }

    #[test]
    fn runtime_pipeline_binds_exact_tokens_and_never_executes_before_admission_ack() {
        use std::net::TcpListener;
        // The HTTP parser and runtime driver execute on real bounded TCP.
        // The broker exchange below is a synthetic authority, not a passing
        // installed UID/cgroup/PIDFD or real-model qualification claim.
        for fault in ["none", "admission-ack", "context", "completion", "fence"] {
            let profile = profile("qwen3-1-7b-q4-k-m").unwrap();
            let worker = crate::resources::Token {
                lease_id: "a".repeat(32),
                generation: 1,
                manager_epoch: "b".repeat(32),
            };
            let mut messages = vec![ChatMessage {
                role: "user".into(),
                content: "hello".into(),
            }];
            let until = crate::resource_manager::now().unwrap() + 4000;
            let receipt = Permit {
                kind: "permit".into(),
                nonce: "c".repeat(32),
                worker: worker.clone(),
                phase: "preparing".into(),
                profile: profile.id.clone(),
                input_digest: wire::input_digest(&messages).unwrap(),
                max_output_tokens: 16,
                context_tokens: 2048,
                request_deadline: until,
                prompt_tokens: None,
                token_digest: None,
                output_tokens: None,
                result_digest: None,
                slot_released: false,
                worker_resources_released: false,
                product: None,
            };
            let listener = TcpListener::bind("127.0.0.1:8081").unwrap();
            listener.set_nonblocking(true).unwrap();
            let alias = profile.id.clone();
            let server = std::thread::spawn(move || {
                let paths = if fault == "fence" {
                    vec![]
                } else if matches!(fault, "context" | "admission-ack") {
                    vec!["/apply-template", "/tokenize"]
                } else {
                    vec!["/apply-template", "/tokenize", "/completion"]
                };
                for path in &paths {
                    let mut stream = loop {
                        match listener.accept() {
                            Ok((stream, _)) => break stream,
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                assert!(
                                    crate::resource_manager::now().unwrap() < until,
                                    "missing fixture HTTP operation {path}"
                                );
                                std::thread::sleep(Duration::from_millis(5));
                            }
                            Err(error) => panic!("fixture accept: {error}"),
                        }
                    };
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut raw = Vec::new();
                    let (end, length) = loop {
                        let mut block = [0u8; 1024];
                        let count = stream.read(&mut block).unwrap();
                        assert!(count > 0);
                        raw.extend_from_slice(&block[..count]);
                        if let Some(end) = raw.windows(4).position(|p| p == b"\r\n\r\n") {
                            let text = std::str::from_utf8(&raw[..end]).unwrap();
                            assert!(text.starts_with(&format!("POST {path} HTTP/1.1\r\n")));
                            assert!(
                                text.contains(&format!("Authorization: Bearer {}", "a".repeat(64)))
                            );
                            let length = text
                                .lines()
                                .find_map(|line| line.strip_prefix("Content-Length: "))
                                .unwrap()
                                .trim()
                                .parse::<usize>()
                                .unwrap();
                            if raw.len() >= end + 4 + length {
                                break (end + 4, length);
                            }
                        }
                        assert!(raw.len() < 128 * 1024);
                    };
                    let body: serde_json::Value =
                        serde_json::from_slice(&raw[end..end + length]).unwrap();
                    let response = match *path {
                        "/apply-template" => {
                            assert_eq!(body["messages"][0]["content"], "hello /no_think");
                            assert_eq!(body["chat_template_kwargs"]["enable_thinking"], false);
                            serde_json::json!({"prompt":"rendered"})
                        }
                        "/tokenize" => {
                            assert_eq!(body["content"], "rendered");
                            if fault == "context" {
                                serde_json::json!({"tokens":vec![1;2048]})
                            } else {
                                serde_json::json!({"tokens":[1,2,3]})
                            }
                        }
                        "/completion" => {
                            assert_eq!(body["prompt"], serde_json::json!([1, 2, 3]));
                            assert_eq!(body["n_predict"], 16);
                            assert_eq!(body["cache_prompt"], false);
                            assert_eq!(body["stream"], false);
                            serde_json::json!({"content":"hello","model":alias,"stop":true,"stop_type":"eos","truncated":false,
                                "tokens_evaluated":3,"tokens_predicted":if fault=="completion" {17}else{2},"tokens_cached":5,
                                "timings":{"cache_n":0,"prompt_n":3,"predicted_n":2}})
                        }
                        _ => unreachable!(),
                    };
                    let bytes = serde_json::to_vec(&response).unwrap();
                    write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",bytes.len()).unwrap();
                    for chunk in bytes.chunks(3) {
                        stream.write_all(chunk).unwrap();
                    }
                }
                paths.len()
            });
            let mut operations = Vec::new();
            let mut admitted = receipt.clone();
            let mut exchange = |message| -> Result<Status> {
                match message {
                    Message::Admit {
                        nonce,
                        worker: observed,
                        prompt_tokens,
                        token_digest,
                    } => {
                        operations.push("admit");
                        assert_eq!(nonce, receipt.nonce);
                        assert_eq!(observed, worker);
                        assert_eq!(prompt_tokens, 3);
                        assert_eq!(token_digest, bundle::hex(&Sha256::digest(b"[1,2,3]")));
                        admitted.phase = "admitted".into();
                        admitted.prompt_tokens = Some(3);
                        admitted.token_digest = Some(token_digest);
                        let mut reply = admitted.clone();
                        if fault == "admission-ack" {
                            reply.worker.generation += 1;
                        }
                        Ok(Status::Permit { receipt: reply })
                    }
                    Message::Finish {
                        nonce,
                        worker: observed,
                        output,
                    } => {
                        operations.push("finish");
                        assert_eq!(nonce, receipt.nonce);
                        assert_eq!(observed, worker);
                        assert_eq!(
                            output,
                            Output {
                                text: "hello".into(),
                                prompt_tokens: 3,
                                output_tokens: 2
                            }
                        );
                        let mut reply = admitted.clone();
                        reply.phase = "completed".into();
                        reply.output_tokens = Some(2);
                        reply.result_digest = Some(wire::output_digest(&output)?);
                        reply.slot_released = true;
                        Ok(Status::Permit { receipt: reply })
                    }
                    _ => Err("unexpected fixture broker operation".into()),
                }
            };
            let driver = Driver {
                ready: true,
                key: "a".repeat(64),
                startup_until: until,
            };
            let result = driver.run_with(
                &profile,
                &worker,
                &mut messages,
                &receipt,
                &mut || {
                    if fault == "fence" {
                        Err("injected local lease loss".into())
                    } else {
                        Ok(())
                    }
                },
                &mut exchange,
            );
            let executed = server.join().unwrap();
            if fault == "none" {
                result.unwrap();
                assert_eq!(operations, vec!["admit", "finish"]);
                assert_eq!(executed, 3);
            } else {
                assert!(result.is_err(), "fault {fault}");
                assert!(!operations.contains(&"finish"));
            }
        }
    }
}
