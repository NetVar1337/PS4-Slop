use crate::Result;
use crate::broker::{load_token, valid_client_identity};
use anyhow::{anyhow, bail};
use serde_json::{Value, json};
use std::io::Read;
use std::path::Path;
use std::time::Duration;

pub const MAX_RESPONSE: usize = 8_388_608;
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(150);

#[derive(Clone)]
pub struct BrokerClient {
    endpoint: String,
    token: String,
    client: String,
    http: reqwest::blocking::Client,
    expected_profile: Option<String>,
}

pub fn validate_broker_url(url: &str) -> Result<String> {
    let rejected = || anyhow!("Broker URL must be http://127.0.0.1:PORT, without credentials or paths");
    let parsed = reqwest::Url::parse(url).map_err(|_| rejected())?;
    let clean = parsed.scheme() == "http" && parsed.host_str() == Some("127.0.0.1")
        && matches!(parsed.path(), "" | "/") && parsed.query().is_none() && parsed.fragment().is_none()
        && parsed.username().is_empty() && parsed.password().is_none();
    if !clean {
        return Err(rejected());
    }
    let port = parsed.port_or_known_default().ok_or_else(rejected)?;
    Ok(format!("http://127.0.0.1:{port}/rpc"))
}

impl BrokerClient {
    pub fn new(url: &str, token_path: &Path, client: &str, expected_profile: Option<String>) -> Result<Self> {
        let endpoint = validate_broker_url(url)?;
        let token = load_token(token_path, false)?;
        Self::connect(endpoint, token, client, expected_profile)
    }

    fn connect(endpoint: String, token: String, client: &str, expected_profile: Option<String>) -> Result<Self> {
        let client = if client.is_empty() {
            format!("client-{}", uuid::Uuid::new_v4().simple())
        } else {
            client.to_string()
        };
        if !valid_client_identity(&client) {
            bail!("Invalid broker client identity");
        }
        let http = reqwest::blocking::Client::builder().no_proxy().timeout(REQUEST_TIMEOUT)
            .connect_timeout(Duration::from_secs(3)).redirect(reqwest::redirect::Policy::none()).build()?;
        let mut connected = Self { endpoint, token, client, http, expected_profile };
        let state = connected.state()?;
        let fingerprint = state.get("profile_sha256").and_then(Value::as_str)
            .ok_or_else(|| anyhow!("Broker state lacks a profile fingerprint"))?;
        connected.expected_profile = Some(fingerprint.to_string());
        Ok(connected)
    }

    pub fn with_identity(&self, client: &str) -> Result<Self> {
        Self::connect(self.endpoint.clone(), self.token.clone(), client, self.expected_profile.clone())
    }

    pub fn client_id(&self) -> &str {
        &self.client
    }

    pub fn expected_profile(&self) -> Option<&str> {
        self.expected_profile.as_deref()
    }

    pub fn request(&self, operation: &str, arguments: Value) -> Result<Value> {
        if !arguments.is_object() {
            bail!("Broker request arguments must be an object");
        }
        let envelope = json!({"operation": operation, "arguments": arguments, "profile_sha256": self.expected_profile});
        let response = self.http.post(&self.endpoint)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("X-PS4-Client", &self.client)
            .header("Content-Type", "application/json")
            .body(serde_json::to_vec(&envelope)?)
            .send()
            .map_err(|error| anyhow!("Broker connection failed; do not retry mutations automatically: {error}"))?;
        let status = response.status();
        let mut content = Vec::new();
        response.take(MAX_RESPONSE as u64 + 1).read_to_end(&mut content)
            .map_err(|error| anyhow!("Broker connection failed; do not retry mutations automatically: {error}"))?;
        if !status.is_success() {
            let message = serde_json::from_slice::<Value>(&content).ok()
                .and_then(|body| body.get("error").and_then(Value::as_str).map(str::to_string))
                .unwrap_or_else(|| format!("HTTP Error {}", status.as_u16()));
            bail!(message);
        }
        if content.len() > MAX_RESPONSE {
            bail!("Broker response exceeds 8 MiB");
        }
        let mut body: Value = serde_json::from_slice(&content)?;
        match body.get_mut("result") {
            Some(result) => Ok(result.take()),
            None => bail!("Broker response lacks a result"),
        }
    }

    pub fn call(&self, name: &str, args: Value) -> Result<Value> {
        self.request("call", json!({"name": name, "arguments": args}))
    }

    pub fn state(&self) -> Result<Value> {
        self.request("state", json!({}))
    }

    pub fn events(&self, cursor: u64, limit: usize) -> Result<Value> {
        self.request("events", json!({"cursor": cursor, "limit": limit}))
    }

    pub fn release(&self) -> Result<Value> {
        self.request("release", json!({}))
    }

    pub fn descriptions(&self) -> Result<Vec<Value>> {
        match self.request("tools", json!({}))? {
            Value::Array(items) => Ok(items),
            _ => bail!("Broker tool list must be an array"),
        }
    }
}

pub struct RemoteRegistry {
    pub client: BrokerClient,
    cursor: u64,
    descriptions: Vec<Value>,
}

impl RemoteRegistry {
    pub fn new(client: BrokerClient) -> Result<Self> {
        let mut descriptions = client.descriptions()?;
        let empty = json!({"type": "object", "properties": {}, "additionalProperties": false});
        for (name, description) in [
            ("session_state", "Shared session controller, attached process and event health."),
            ("session_events", "Replay shared events from this MCP client's cursor; never drains other clients' events."),
            ("session_release", "Release this client's control lease only after detachment or a failed attach; does not recover the console."),
        ] {
            descriptions.push(json!({"name": name, "description": description, "inputSchema": empty}));
        }
        Ok(Self { client, cursor: 0, descriptions })
    }

    pub fn available(&self) -> Vec<Value> {
        self.descriptions.clone()
    }

    pub fn call(&mut self, name: &str, args: Value) -> Result<Value> {
        if matches!(name, "session_state" | "session_events" | "session_release") {
            if args.as_object().is_none_or(|fields| !fields.is_empty()) {
                bail!("Session observer tools take no arguments");
            }
            return match name {
                "session_state" => self.client.state(),
                "session_release" => self.client.release(),
                _ => {
                    let result = self.client.events(self.cursor, 6)?;
                    self.cursor = result.get("cursor").and_then(Value::as_u64)
                        .ok_or_else(|| anyhow!("Broker event page lacks a cursor"))?;
                    Ok(result)
                }
            };
        }
        self.client.call(name, args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_loopback_or_decorated_urls() {
        for url in ["http://192.168.1.1:8765", "https://127.0.0.1:8765", "http://user@127.0.0.1:8765",
                    "http://127.0.0.1:8765/other", "http://127.0.0.1:8765/?x=1", "http://127.0.0.1:8765/#frag",
                    "http://localhost:8765", "not a url"] {
            assert!(validate_broker_url(url).is_err(), "{url}");
        }
        assert_eq!(validate_broker_url("http://127.0.0.1:8765/").unwrap(), "http://127.0.0.1:8765/rpc");
        assert_eq!(validate_broker_url("http://127.0.0.1:8765").unwrap(), "http://127.0.0.1:8765/rpc");
    }

    #[test]
    fn construction_requires_a_valid_token_file() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.local");
        assert!(BrokerClient::new("http://127.0.0.1:1", &missing, "test", None).is_err());
        let invalid = directory.path().join("invalid.local");
        std::fs::write(&invalid, "not-a-token").unwrap();
        assert!(BrokerClient::new("http://127.0.0.1:1", &invalid, "test", None).is_err());
    }
}
