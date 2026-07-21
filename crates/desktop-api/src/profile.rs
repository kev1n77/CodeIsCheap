use std::collections::HashSet;
use std::fmt;

use codeischeap_capture_ipc::{CapturedBody, CapturedBodyState, CapturedRequest};
use codeischeap_capture_policy::{CapturePolicy, PolicyError, normalize_additional_hosts};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use url::Url;

pub const CAPTURE_PROFILE_VERSION: &str = "0.1";
pub const DEFAULT_GATEWAY_UPSTREAM: &str = "https://api.openai.com";
pub const DEFAULT_CAPTURE_PROFILE_NAME: &str = "OpenAI default";
pub const MAX_CAPTURE_PROFILE_NAME_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureProfile {
    pub version: String,
    pub name: String,
    pub gateway_upstream: String,
    pub additional_hosts: Vec<String>,
}

impl Default for CaptureProfile {
    fn default() -> Self {
        Self {
            version: CAPTURE_PROFILE_VERSION.to_owned(),
            name: DEFAULT_CAPTURE_PROFILE_NAME.to_owned(),
            gateway_upstream: DEFAULT_GATEWAY_UPSTREAM.to_owned(),
            additional_hosts: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureProfileError {
    InvalidJson,
    UnsupportedVersion(String),
    InvalidName,
    InvalidGatewayUpstream,
    GatewayCredentialsForbidden,
    GatewayOriginRequired,
    BuiltInAdditionalHost(String),
    Policy(PolicyError),
}

impl fmt::Display for CaptureProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson => write!(formatter, "capture profile JSON is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "capture profile version {version} is unsupported"
                )
            }
            Self::InvalidName => write!(
                formatter,
                "capture profile name must be trimmed text of at most {MAX_CAPTURE_PROFILE_NAME_BYTES} bytes"
            ),
            Self::InvalidGatewayUpstream => write!(
                formatter,
                "Gateway upstream must be an absolute HTTP or HTTPS URL"
            ),
            Self::GatewayCredentialsForbidden => write!(
                formatter,
                "Gateway upstream must not contain embedded credentials"
            ),
            Self::GatewayOriginRequired => write!(
                formatter,
                "Gateway upstream must be an origin without a path, query, or fragment"
            ),
            Self::BuiltInAdditionalHost(host) => {
                write!(
                    formatter,
                    "additional capture host {host} is already built in"
                )
            }
            Self::Policy(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for CaptureProfileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Policy(error) => Some(error),
            _ => None,
        }
    }
}

impl From<PolicyError> for CaptureProfileError {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
    }
}

impl CaptureProfile {
    pub fn from_json(encoded: &str) -> Result<Self, CaptureProfileError> {
        let profile: Self =
            serde_json::from_str(encoded).map_err(|_| CaptureProfileError::InvalidJson)?;
        profile.validated()
    }

    pub fn validated(mut self) -> Result<Self, CaptureProfileError> {
        if self.version != CAPTURE_PROFILE_VERSION {
            return Err(CaptureProfileError::UnsupportedVersion(self.version));
        }
        let name = self.name.trim();
        if name.is_empty()
            || name.len() > MAX_CAPTURE_PROFILE_NAME_BYTES
            || name.chars().any(char::is_control)
        {
            return Err(CaptureProfileError::InvalidName);
        }
        self.name = name.to_owned();

        let upstream = validate_gateway_upstream(&self.gateway_upstream)?;
        self.gateway_upstream = canonical_origin(&upstream);
        self.additional_hosts = normalize_additional_hosts(&self.additional_hosts)?;
        let built_in_hosts = built_in_hosts()?;
        if let Some(host) = self
            .additional_hosts
            .iter()
            .find(|host| built_in_hosts.contains(host.as_str()))
        {
            return Err(CaptureProfileError::BuiltInAdditionalHost(host.clone()));
        }
        self.capture_policy()?;
        Ok(self)
    }

    pub fn gateway_url(&self) -> Result<Url, CaptureProfileError> {
        validate_gateway_upstream(&self.gateway_upstream)
    }

    pub fn capture_policy(&self) -> Result<CapturePolicy, CaptureProfileError> {
        let mut scope_hosts = self.additional_hosts.clone();
        let upstream = self.gateway_url()?;
        let upstream_host = upstream
            .host_str()
            .ok_or(CaptureProfileError::InvalidGatewayUpstream)?
            .to_ascii_lowercase();
        let default_policy = CapturePolicy::load_default()?;
        let upstream_has_openai_scope = default_policy
            .matching_target(&openai_scope_probe(&upstream_host))
            .is_some();
        if !upstream_has_openai_scope && !scope_hosts.contains(&upstream_host) {
            scope_hosts.push(upstream_host);
        }
        Ok(default_policy.with_additional_hosts(&scope_hosts)?)
    }
}

fn validate_gateway_upstream(value: &str) -> Result<Url, CaptureProfileError> {
    let upstream = Url::parse(value).map_err(|_| CaptureProfileError::InvalidGatewayUpstream)?;
    if !matches!(upstream.scheme(), "http" | "https") || upstream.host_str().is_none() {
        return Err(CaptureProfileError::InvalidGatewayUpstream);
    }
    if !upstream.username().is_empty() || upstream.password().is_some() {
        return Err(CaptureProfileError::GatewayCredentialsForbidden);
    }
    if upstream.path() != "/" || upstream.query().is_some() || upstream.fragment().is_some() {
        return Err(CaptureProfileError::GatewayOriginRequired);
    }
    Ok(upstream)
}

fn canonical_origin(upstream: &Url) -> String {
    let mut origin = upstream.origin().ascii_serialization();
    if origin.ends_with('/') {
        origin.pop();
    }
    origin
}

fn built_in_hosts() -> Result<HashSet<String>, CaptureProfileError> {
    Ok(CapturePolicy::load_default()?
        .targets
        .into_iter()
        .flat_map(|target| target.hosts)
        .collect())
}

fn openai_scope_probe(host: &str) -> CapturedRequest {
    CapturedRequest {
        method: "POST".to_owned(),
        scheme: "https".to_owned(),
        host: host.to_owned(),
        port: 443,
        path: "/v1/chat/completions".to_owned(),
        query: Vec::new(),
        headers: Vec::new(),
        body: CapturedBody {
            state: CapturedBodyState::Empty,
            content: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_uses_the_built_in_openai_scope() {
        let profile = CaptureProfile::default()
            .validated()
            .expect("default profile");
        assert_eq!(profile.gateway_upstream, DEFAULT_GATEWAY_UPSTREAM);
        assert_eq!(profile.capture_policy().expect("policy").targets.len(), 5);
    }

    #[test]
    fn custom_origins_and_hosts_are_canonical_and_bounded_by_existing_paths() {
        let profile = CaptureProfile {
            version: CAPTURE_PROFILE_VERSION.to_owned(),
            name: "  Private lab  ".to_owned(),
            gateway_upstream: "https://LOCALHOST:8443/".to_owned(),
            additional_hosts: vec![" Proxy.EXAMPLE.test. ".to_owned()],
        }
        .validated()
        .expect("custom profile");
        assert_eq!(profile.name, "Private lab");
        assert_eq!(profile.gateway_upstream, "https://localhost:8443");
        assert_eq!(profile.additional_hosts, ["proxy.example.test"]);

        let policy = profile.capture_policy().expect("custom policy");
        assert!(
            policy
                .matching_target(&openai_scope_probe("localhost"))
                .is_some()
        );
        let mut denied = openai_scope_probe("proxy.example.test");
        denied.path = "/admin".to_owned();
        assert!(policy.matching_target(&denied).is_none());
    }

    #[test]
    fn profiles_reject_credentials_non_origins_and_built_in_scope_expansion() {
        for upstream in [
            "ftp://example.test",
            "https://user:secret@example.test",
            "https://example.test/v1",
            "https://example.test?key=value",
        ] {
            assert!(
                CaptureProfile {
                    gateway_upstream: upstream.to_owned(),
                    ..CaptureProfile::default()
                }
                .validated()
                .is_err()
            );
        }
        assert_eq!(
            CaptureProfile {
                additional_hosts: vec!["api.openai.com".to_owned()],
                ..CaptureProfile::default()
            }
            .validated(),
            Err(CaptureProfileError::BuiltInAdditionalHost(
                "api.openai.com".to_owned()
            ))
        );
    }
}
