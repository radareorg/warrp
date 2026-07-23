//! Synchronous client for the public WARP server API.
//!
//! radare2 commands run on the core thread, so this client deliberately uses
//! blocking requests.  Callers should keep requests bounded and report progress
//! before invoking it.

use std::io::Read;
use std::time::Duration;

use base64::Engine;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::warp::signature::FunctionGUID;
use crate::warp::types::Target;

pub const DEFAULT_SERVER_URL: &str = "https://warp.binary.ninja";
pub const DEFAULT_SOURCE_TAGS: &[&str] = &["official", "trusted"];

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_UPLOAD_BYTES: usize = 64 * 1024 * 1024;

/// A source returned by the WARP server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSource {
    pub id: Uuid,
    pub name: String,
}

/// A blocking client for the WARP server REST API.
#[derive(Clone)]
pub struct NetworkClient {
    agent: ureq::Agent,
    server_url: String,
    token: Option<String>,
}

impl NetworkClient {
    pub fn new(server_url: impl AsRef<str>, token: Option<String>) -> Result<Self, String> {
        let server_url = normalize_server_url(server_url.as_ref())?;
        let token = token.filter(|token| !token.trim().is_empty());
        let agent = ureq::AgentBuilder::new().timeout(REQUEST_TIMEOUT).build();

        Ok(Self {
            agent,
            server_url,
            token,
        })
    }

    /// Create a client using the optional process-local r2warp configuration.
    pub fn from_environment() -> Self {
        let server_url =
            std::env::var("R2WARP_SERVER_URL").unwrap_or_else(|_| DEFAULT_SERVER_URL.to_string());
        let token = std::env::var("R2WARP_API_TOKEN").ok();

        Self::new(server_url, token).unwrap_or_else(|_| {
            Self::new(DEFAULT_SERVER_URL, None).expect("the built-in WARP server URL must be valid")
        })
    }

    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    pub fn is_authenticated(&self) -> bool {
        self.token.is_some()
    }

    /// Change the endpoint while retaining the session's API key, if any.
    pub fn set_server_url(&mut self, server_url: impl AsRef<str>) -> Result<(), String> {
        self.server_url = normalize_server_url(server_url.as_ref())?;
        Ok(())
    }

    /// Replace the in-memory API key. An empty value clears authentication.
    pub fn set_token(&mut self, token: Option<String>) {
        self.token = token.filter(|token| !token.trim().is_empty());
    }

    pub fn status(&self) -> Result<String, String> {
        #[derive(Deserialize)]
        struct StatusResponse {
            status: String,
        }

        let response: StatusResponse = self.get_json("/api/v1/status")?;
        Ok(response.status)
    }

    /// Return all visible sources, up to the server's maximum page size.
    pub fn list_sources(&self) -> Result<Vec<RemoteSource>, String> {
        #[derive(Deserialize)]
        struct SourceResponse {
            items: Vec<SourceItem>,
        }

        #[derive(Deserialize)]
        struct SourceItem {
            id: Uuid,
            name: String,
        }

        let response: SourceResponse = self.post_json(
            "/api/v1/sources/query",
            &json!({
                "limit": 100,
                "page": 0,
            }),
        )?;
        Ok(response
            .items
            .into_iter()
            .map(|source| RemoteSource {
                id: source.id,
                name: source.name,
            })
            .collect())
    }

    /// Create a writable source for the currently authenticated user.
    pub fn create_source(&self, name: &str) -> Result<RemoteSource, String> {
        #[derive(Deserialize)]
        struct CreateSourceResponse {
            id: Uuid,
            name: String,
        }

        let name = name.trim();
        if name.is_empty() {
            return Err("Source name cannot be empty".to_string());
        }
        if !self.is_authenticated() {
            return Err(
                "Creating a source requires an API key. Set R2WARP_API_TOKEN or use 'zw auth <token>'."
                    .to_string(),
            );
        }

        let response: CreateSourceResponse = self.post_json(
            "/api/v1/sources",
            &json!({
                "name": name,
                // An empty list tells the server to add the current user.
                "user_ids": [],
            }),
        )?;
        Ok(RemoteSource {
            id: response.id,
            name: response.name,
        })
    }

    /// Resolve a server target ID for a WARP target.
    pub fn target_id(&self, target: &Target) -> Result<i32, String> {
        #[derive(Deserialize)]
        struct TargetResponse {
            id: i32,
            arch: Option<String>,
            platform: Option<String>,
        }

        let targets: Vec<TargetResponse> = self.post_json(
            "/api/v1/targets/query",
            &json!({
                "arch": target.architecture,
                "platform": target.platform,
            }),
        )?;

        targets
            .into_iter()
            .find(|candidate| {
                candidate.arch.as_deref() == Some(target.architecture.as_str())
                    && candidate.platform.as_deref() == Some(target.platform.as_str())
            })
            .map(|target| target.id)
            .ok_or_else(|| {
                format!(
                    "No server target for architecture '{}' and platform '{}'",
                    target.architecture, target.platform
                )
            })
    }

    /// Fetch a WARP flatbuffer containing functions matching `guids`.
    pub fn query_functions(
        &self,
        target_id: i32,
        source: Option<Uuid>,
        source_tags: &[&str],
        guids: &[FunctionGUID],
    ) -> Result<Vec<u8>, String> {
        if guids.is_empty() {
            return Ok(Vec::new());
        }

        self.post_bytes(
            "/api/v1/functions/query",
            &function_query_body(target_id, source, source_tags, guids),
        )
    }

    /// Upload a WARP flatbuffer and return the created commit ID.
    pub fn push_file(&self, source: Uuid, bytes: &[u8], name: &str) -> Result<i32, String> {
        #[derive(Deserialize)]
        struct PushResponse {
            commit_id: i32,
        }

        if !self.is_authenticated() {
            return Err(
                "Uploading requires an API key. Set R2WARP_API_TOKEN or use 'zw auth <token>'."
                    .to_string(),
            );
        }
        if bytes.is_empty() {
            return Err("Refusing to upload an empty WARP file".to_string());
        }
        if bytes.len() > MAX_UPLOAD_BYTES {
            return Err(format!(
                "WARP file is {} bytes; the server accepts files up to {} bytes",
                bytes.len(),
                MAX_UPLOAD_BYTES
            ));
        }

        let commit_name = name.trim();
        if commit_name.is_empty() {
            return Err("Commit name cannot be empty".to_string());
        }

        let response: PushResponse = self.post_json(
            "/api/v1/files/json",
            &json!({
                "file": base64::engine::general_purpose::STANDARD.encode(bytes),
                "name": commit_name,
                "source": source.to_string(),
                "description": Value::Null,
            }),
        )?;
        Ok(response.commit_id)
    }

    fn get_json<T: DeserializeOwned>(&self, endpoint: &str) -> Result<T, String> {
        let response = self
            .request("GET", endpoint)
            .call()
            .map_err(|error| request_error(endpoint, error))?;
        parse_json(endpoint, self.read_response(endpoint, response)?)
    }

    fn post_json<T: DeserializeOwned>(&self, endpoint: &str, body: &Value) -> Result<T, String> {
        parse_json(endpoint, self.post_bytes(endpoint, body)?)
    }

    fn post_bytes(&self, endpoint: &str, body: &Value) -> Result<Vec<u8>, String> {
        let response = self
            .request("POST", endpoint)
            .set("Content-Type", "application/json")
            .send_string(&body.to_string())
            .map_err(|error| request_error(endpoint, error))?;
        self.read_response(endpoint, response)
    }

    fn request(&self, method: &str, endpoint: &str) -> ureq::Request {
        let request = self
            .agent
            .request(method, &format!("{}{}", self.server_url, endpoint))
            .set("Accept", "application/json");
        match &self.token {
            Some(token) => request.set("Authorization", &format!("Bearer {}", token)),
            None => request,
        }
    }

    fn read_response(&self, endpoint: &str, response: ureq::Response) -> Result<Vec<u8>, String> {
        let mut body = Vec::new();
        response
            .into_reader()
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|error| format!("Failed reading {} response: {}", endpoint, error))?;

        if body.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(format!(
                "{} response exceeded the {} byte limit",
                endpoint, MAX_RESPONSE_BYTES
            ));
        }
        Ok(body)
    }
}

fn normalize_server_url(server_url: &str) -> Result<String, String> {
    let server_url = server_url.trim().trim_end_matches('/');
    if server_url.is_empty() {
        return Err("Server URL cannot be empty".to_string());
    }
    if !(server_url.starts_with("https://") || server_url.starts_with("http://")) {
        return Err("Server URL must start with http:// or https://".to_string());
    }
    if server_url.chars().any(char::is_whitespace) {
        return Err("Server URL cannot contain whitespace".to_string());
    }
    Ok(server_url.to_string())
}

fn function_query_body(
    target_id: i32,
    source: Option<Uuid>,
    source_tags: &[&str],
    guids: &[FunctionGUID],
) -> Value {
    let mut guids: Vec<_> = guids.iter().map(ToString::to_string).collect();
    guids.sort_unstable();
    guids.dedup();

    let mut body = json!({
        "format": "flatbuffer",
        "target_id": target_id,
        "guids": guids,
        "limit": 10_000,
        "page": 0,
    });
    if let Some(source) = source {
        body["source_id"] = json!(source.to_string());
    }
    if !source_tags.is_empty() {
        body["source_tags"] = json!(source_tags);
    }
    body
}

fn parse_json<T: DeserializeOwned>(endpoint: &str, bytes: Vec<u8>) -> Result<T, String> {
    serde_json::from_slice(&bytes).map_err(|error| {
        let preview = String::from_utf8_lossy(&bytes);
        let preview: String = preview.chars().take(256).collect();
        format!(
            "Invalid JSON response from {}: {}{}",
            endpoint,
            error,
            if preview.is_empty() {
                String::new()
            } else {
                format!(" ({})", preview)
            }
        )
    })
}

fn request_error(endpoint: &str, error: ureq::Error) -> String {
    match error {
        ureq::Error::Status(status, response) => {
            let detail = response
                .into_string()
                .ok()
                .filter(|body| !body.trim().is_empty())
                .map(|body| {
                    let body: String = body.chars().take(256).collect();
                    format!(": {}", body)
                })
                .unwrap_or_default();
            format!("{} returned HTTP {}{}", endpoint, status, detail)
        }
        ureq::Error::Transport(error) => format!("Request to {} failed: {}", endpoint, error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_server_urls() {
        let client = NetworkClient::new(" https://warp.example/ ", None).unwrap();
        assert_eq!(client.server_url(), "https://warp.example");
        assert!(NetworkClient::new("warp.example", None).is_err());
        assert!(NetworkClient::new("https://warp .example", None).is_err());
    }

    #[test]
    fn function_query_is_flatbuffer_and_deduplicated() {
        let guid = FunctionGUID::from_uuid(Uuid::nil());
        let source = Uuid::from_u128(1);
        let body = function_query_body(17, Some(source), &["official", "trusted"], &[guid, guid]);

        assert_eq!(body["format"], "flatbuffer");
        assert_eq!(body["target_id"], 17);
        assert_eq!(body["source_id"], source.to_string());
        assert_eq!(body["source_tags"], json!(["official", "trusted"]));
        assert_eq!(body["guids"].as_array().unwrap().len(), 1);
    }
}
