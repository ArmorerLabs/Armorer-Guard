use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path};

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

use super::config::{FilesystemBrokerConfig, HttpBrokerConfig};
use super::crypto;
use super::enforcement::ExecutionToken;

pub const HTTP_BROKER_VERSION: &str = "armorer-guard-http-broker-request/v1";
pub const FILESYSTEM_BROKER_VERSION: &str = "armorer-guard-filesystem-broker-request/v1";
const EXECUTION_TOKEN_HEADER: &str = "X-Armorer-Guard-Execution-Token";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpBrokerArguments {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpBrokerRequest {
    pub schema_version: String,
    pub token: ExecutionToken,
    pub arguments: HttpBrokerArguments,
    pub observed_at: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemBrokerArguments {
    pub operation: String,
    pub path: String,
    #[serde(default)]
    pub content: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemBrokerRequest {
    pub schema_version: String,
    pub token: ExecutionToken,
    pub arguments: FilesystemBrokerArguments,
    pub observed_at: u64,
}

struct FilesystemRoute {
    config: FilesystemBrokerConfig,
    directory: Dir,
}

pub struct BrokerEngine {
    http_routes: Vec<HttpBrokerConfig>,
    filesystem_routes: Vec<FilesystemRoute>,
    client: Client,
}

pub(super) struct PreparedHttp {
    request: reqwest::blocking::Request,
    maximum_response_bytes: usize,
}

pub(super) struct PreparedFilesystem {
    route_index: usize,
    arguments: FilesystemBrokerArguments,
}

impl BrokerEngine {
    pub fn load(
        http_routes: &[HttpBrokerConfig],
        filesystem_routes: &[FilesystemBrokerConfig],
    ) -> Result<Self, String> {
        let filesystem_routes = filesystem_routes
            .iter()
            .map(|config| {
                let directory = Dir::open_ambient_dir(&config.root, ambient_authority())
                    .map_err(|error| format!("failed to open filesystem broker root: {error}"))?;
                Ok(FilesystemRoute {
                    config: config.clone(),
                    directory,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| format!("failed to build guarded HTTP client: {error}"))?;
        Ok(Self {
            http_routes: http_routes.to_vec(),
            filesystem_routes,
            client,
        })
    }

    pub fn prepare_http(
        &self,
        token: &ExecutionToken,
        arguments: &HttpBrokerArguments,
    ) -> Result<PreparedHttp, String> {
        let route = self
            .http_routes
            .iter()
            .find(|route| {
                route.capability_id == token.capability_id
                    && arguments.url.starts_with(&route.url_prefix)
                    && route
                        .allowed_methods
                        .iter()
                        .any(|method| method == &arguments.method)
            })
            .ok_or_else(|| "HTTP effect is outside the configured broker route".to_string())?;
        let credential = read_secret(Path::new(&route.credential_file))?;
        let method = reqwest::Method::from_bytes(arguments.method.as_bytes())
            .map_err(|_| "HTTP broker method is invalid".to_string())?;
        let mut request = self.client.request(method, &arguments.url);
        for (name, value) in &arguments.headers {
            if name.eq_ignore_ascii_case(&route.credential_header)
                || name.eq_ignore_ascii_case("authorization")
                || name.eq_ignore_ascii_case("proxy-authorization")
                || name.eq_ignore_ascii_case(EXECUTION_TOKEN_HEADER)
            {
                return Err("agent-controlled credential headers are forbidden".to_string());
            }
            request = request.header(name, value);
        }
        let encoded_token = hex(&crypto::canonical_bytes(token)?);
        request = request
            .header(&route.credential_header, credential)
            .header(EXECUTION_TOKEN_HEADER, encoded_token);
        if let Some(body) = &arguments.body {
            request = request.body(body.clone());
        }
        let request = request
            .build()
            .map_err(|error| format!("failed to prepare guarded HTTP effect: {error}"))?;
        Ok(PreparedHttp {
            request,
            maximum_response_bytes: route.maximum_response_bytes,
        })
    }

    pub fn dispatch_http(&self, prepared: PreparedHttp) -> Result<serde_json::Value, String> {
        let response = self
            .client
            .execute(prepared.request)
            .map_err(|error| format!("guarded HTTP effect failed: {error}"))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter(|(name, _)| {
                !name.as_str().eq_ignore_ascii_case("set-cookie")
                    && !name.as_str().eq_ignore_ascii_case("www-authenticate")
            })
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.to_string(), value.to_string()))
            })
            .collect::<BTreeMap<_, _>>();
        let bytes = response
            .bytes()
            .map_err(|error| format!("failed to read guarded HTTP response: {error}"))?;
        if bytes.len() > prepared.maximum_response_bytes {
            return Err("guarded HTTP response exceeds configured maximum".to_string());
        }
        let body = String::from_utf8(bytes.to_vec())
            .map_err(|_| "guarded HTTP response is not UTF-8".to_string())?;
        Ok(serde_json::json!({"status": status, "headers": headers, "body": body}))
    }

    pub fn prepare_filesystem(
        &self,
        token: &ExecutionToken,
        arguments: &FilesystemBrokerArguments,
    ) -> Result<PreparedFilesystem, String> {
        validate_relative_path(&arguments.path)?;
        let (route_index, route) = self
            .filesystem_routes
            .iter()
            .enumerate()
            .find(|route| {
                route.1.config.capability_id == token.capability_id
                    && route
                        .1
                        .config
                        .allowed_operations
                        .iter()
                        .any(|operation| operation == &arguments.operation)
            })
            .ok_or_else(|| {
                "filesystem effect is outside the configured broker route".to_string()
            })?;
        match arguments.operation.as_str() {
            "read" | "remove" if arguments.content.is_some() => {
                return Err(format!(
                    "filesystem {} cannot include content",
                    arguments.operation
                ));
            }
            "write" => {
                let content = arguments
                    .content
                    .as_deref()
                    .ok_or_else(|| "filesystem write requires content".to_string())?;
                if content.len() > route.config.maximum_bytes {
                    return Err("guarded filesystem write exceeds configured maximum".to_string());
                }
            }
            "read" | "remove" => {}
            _ => return Err("unsupported filesystem broker operation".to_string()),
        }
        Ok(PreparedFilesystem {
            route_index,
            arguments: arguments.clone(),
        })
    }

    pub fn dispatch_filesystem(
        &self,
        prepared: PreparedFilesystem,
    ) -> Result<serde_json::Value, String> {
        let route = &self.filesystem_routes[prepared.route_index];
        let arguments = prepared.arguments;
        match arguments.operation.as_str() {
            "read" => {
                let bytes = route
                    .directory
                    .read(&arguments.path)
                    .map_err(|error| format!("guarded filesystem read failed: {error}"))?;
                if bytes.len() > route.config.maximum_bytes {
                    return Err("guarded filesystem read exceeds configured maximum".to_string());
                }
                let content = String::from_utf8(bytes)
                    .map_err(|_| "guarded filesystem content is not UTF-8".to_string())?;
                Ok(serde_json::json!({"operation": "read", "content": content}))
            }
            "write" => {
                let content = arguments.content.as_deref().unwrap_or_default();
                route
                    .directory
                    .write(&arguments.path, content.as_bytes())
                    .map_err(|error| format!("guarded filesystem write failed: {error}"))?;
                Ok(serde_json::json!({"operation": "write", "bytes": content.len()}))
            }
            "remove" => {
                route
                    .directory
                    .remove_file(&arguments.path)
                    .map_err(|error| format!("guarded filesystem removal failed: {error}"))?;
                Ok(serde_json::json!({"operation": "remove"}))
            }
            _ => Err("unsupported filesystem broker operation".to_string()),
        }
    }
}

fn validate_relative_path(path: &str) -> Result<(), String> {
    let raw = path;
    let path = Path::new(raw);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || raw
            .split(['/', '\\'])
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("filesystem broker path must be a normalized relative path".to_string());
    }
    Ok(())
}

fn read_secret(path: &Path) -> Result<String, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .map_err(|error| format!("failed to inspect broker credential: {error}"))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err("broker credential must not be accessible by group or other".to_string());
        }
    }
    let value = fs::read_to_string(path)
        .map_err(|error| format!("failed to read broker credential: {error}"))?;
    let value = value.trim().to_string();
    if value.is_empty() || value.contains(['\r', '\n']) {
        return Err("broker credential is empty or contains a newline".to_string());
    }
    Ok(value)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn token(capability_id: &str) -> ExecutionToken {
        ExecutionToken {
            schema_version: "armorer-guard-execution-token/v1".to_string(),
            token_id: "execution-token/test".to_string(),
            decision_id: "decision/test".to_string(),
            request_id: "request/test".to_string(),
            agent_id: "agent".to_string(),
            workload_identity: "spiffe://tenant/agent".to_string(),
            tenant_id: "tenant".to_string(),
            capability_id: capability_id.to_string(),
            resource_type: "resource".to_string(),
            resource_id: "resource/1".to_string(),
            arguments_digest: "sha256:test".to_string(),
            policy_revision: 1,
            issued_at: 1,
            expires_at: 2,
            maximum_usage_count: 1,
            signature: "signature".to_string(),
        }
    }

    #[test]
    fn path_validation_rejects_escape_and_absolute_paths() {
        assert!(validate_relative_path("case/record.txt").is_ok());
        assert!(validate_relative_path("../secret").is_err());
        assert!(validate_relative_path("/etc/passwd").is_err());
        assert!(validate_relative_path("case/./record").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn http_broker_owns_credentials_and_rejects_agent_auth_headers() {
        use std::os::unix::fs::PermissionsExt;

        let directory = std::env::temp_dir().join(format!(
            "guard-http-broker-{}",
            super::super::crypto::opaque_id("test", &[6; 32]).replace('/', "-")
        ));
        fs::create_dir_all(&directory).unwrap();
        let credential = directory.join("credential");
        fs::write(&credential, "gateway-secret\n").unwrap();
        fs::set_permissions(&credential, fs::Permissions::from_mode(0o600)).unwrap();
        let broker = BrokerEngine::load(
            &[HttpBrokerConfig {
                capability_id: "api.send".to_string(),
                url_prefix: "https://api.example.test/v1/".to_string(),
                allowed_methods: vec!["POST".to_string()],
                credential_header: "X-Guard-Token".to_string(),
                credential_file: credential.to_string_lossy().to_string(),
                maximum_response_bytes: 1024,
            }],
            &[],
        )
        .unwrap();
        let arguments = HttpBrokerArguments {
            method: "POST".to_string(),
            url: "https://api.example.test/v1/messages".to_string(),
            headers: BTreeMap::new(),
            body: Some("{}".to_string()),
        };
        let prepared = broker.prepare_http(&token("api.send"), &arguments).unwrap();
        assert_eq!(
            prepared.request.headers()["X-Guard-Token"],
            "gateway-secret"
        );
        assert!(prepared
            .request
            .headers()
            .contains_key(EXECUTION_TOKEN_HEADER));

        let mut injected = arguments;
        injected
            .headers
            .insert("Authorization".to_string(), "Bearer attacker".to_string());
        assert!(broker
            .prepare_http(&token("api.send"), &injected)
            .err()
            .unwrap()
            .contains("credential headers"));
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_broker_cannot_follow_a_symlink_outside_its_root() {
        use std::os::unix::fs::symlink;

        let directory = std::env::temp_dir().join(format!(
            "guard-filesystem-broker-{}",
            super::super::crypto::opaque_id("test", &[6; 32]).replace('/', "-")
        ));
        fs::create_dir_all(&directory).unwrap();
        symlink("/etc/passwd", directory.join("escape")).unwrap();
        let broker = BrokerEngine::load(
            &[],
            &[FilesystemBrokerConfig {
                capability_id: "filesystem.read".to_string(),
                root: directory.to_string_lossy().to_string(),
                allowed_operations: vec!["read".to_string()],
                maximum_bytes: 1024 * 1024,
            }],
        )
        .unwrap();
        let prepared = broker
            .prepare_filesystem(
                &token("filesystem.read"),
                &FilesystemBrokerArguments {
                    operation: "read".to_string(),
                    path: "escape".to_string(),
                    content: None,
                },
            )
            .unwrap();
        assert!(broker.dispatch_filesystem(prepared).is_err());
    }
}
