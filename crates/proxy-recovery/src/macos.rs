use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use url::Url;

use crate::{
    BackendDescriptor, MacOsAutoConfig, MacOsManualProxy, MacOsNetworkService, ProxyBackend,
    ProxySettings, ProxySnapshot, RecoveryError,
};

const NETWORKSETUP: &str = "/usr/sbin/networksetup";

#[derive(Debug, Clone)]
pub struct MacOsProxyBackend {
    networksetup_path: PathBuf,
}

impl MacOsProxyBackend {
    pub fn system() -> Self {
        Self {
            networksetup_path: PathBuf::from(NETWORKSETUP),
        }
    }

    pub(crate) fn for_networksetup_path(path: PathBuf) -> Result<Self, RecoveryError> {
        if path != Path::new(NETWORKSETUP) {
            return Err(RecoveryError::UnsupportedBackend);
        }
        Ok(Self {
            networksetup_path: path,
        })
    }

    fn run(&self, operation: &str, arguments: &[&str]) -> Result<String, RecoveryError> {
        let output = Command::new(&self.networksetup_path)
            .arg(operation)
            .args(arguments)
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .output()?;
        if !output.status.success() {
            return Err(RecoveryError::PlatformCommandFailed(operation.to_owned()));
        }
        String::from_utf8(output.stdout)
            .map_err(|_| RecoveryError::PlatformOutputInvalid(operation.to_owned()))
    }

    fn active_services(&self) -> Result<Vec<String>, RecoveryError> {
        let output = self.run("-listallnetworkservices", &[])?;
        Ok(parse_services(&output))
    }

    fn service_snapshot(&self, service: &str) -> Result<MacOsNetworkService, RecoveryError> {
        let web_proxy = parse_manual_proxy(
            service,
            "-getwebproxy",
            &self.run("-getwebproxy", &[service])?,
        )?;
        let secure_web_proxy = parse_manual_proxy(
            service,
            "-getsecurewebproxy",
            &self.run("-getsecurewebproxy", &[service])?,
        )?;
        let auto_config = parse_auto_config(
            "-getautoproxyurl",
            &self.run("-getautoproxyurl", &[service])?,
        )?;
        let auto_discovery_enabled = parse_auto_discovery(
            "-getproxyautodiscovery",
            &self.run("-getproxyautodiscovery", &[service])?,
        )?;
        let bypass_domains = parse_bypass_domains(&self.run("-getproxybypassdomains", &[service])?);
        Ok(MacOsNetworkService {
            name: service.to_owned(),
            web_proxy,
            secure_web_proxy,
            auto_config,
            auto_discovery_enabled,
            bypass_domains,
        })
    }

    fn set_state(
        &self,
        operation: &str,
        service: &str,
        enabled: bool,
    ) -> Result<(), RecoveryError> {
        self.run(operation, &[service, on_off(enabled)])?;
        Ok(())
    }

    fn set_manual(
        &self,
        operation: &str,
        state_operation: &str,
        service: &str,
        proxy: &MacOsManualProxy,
    ) -> Result<(), RecoveryError> {
        let port = proxy.port.to_string();
        self.run(operation, &[service, &proxy.server, &port])?;
        self.set_state(state_operation, service, proxy.enabled)
    }

    fn set_auto_config(
        &self,
        service: &str,
        auto_config: &MacOsAutoConfig,
    ) -> Result<(), RecoveryError> {
        if let Some(url) = &auto_config.url {
            self.run("-setautoproxyurl", &[service, url])?;
        } else if auto_config.enabled {
            return Err(RecoveryError::PlatformOutputInvalid(
                "-setautoproxyurl".to_owned(),
            ));
        }
        self.set_state("-setautoproxystate", service, auto_config.enabled)
    }

    fn set_bypass(&self, service: &str, domains: &[String]) -> Result<(), RecoveryError> {
        let mut arguments = vec![service];
        if domains.is_empty() {
            arguments.push("Empty");
        } else {
            arguments.extend(domains.iter().map(String::as_str));
        }
        self.run("-setproxybypassdomains", &arguments)?;
        Ok(())
    }

    fn apply_to_service(
        &self,
        service: &str,
        settings: &ProxySettings,
    ) -> Result<(), RecoveryError> {
        match settings {
            ProxySettings::Disabled => {
                self.set_state("-setwebproxystate", service, false)?;
                self.set_state("-setsecurewebproxystate", service, false)?;
                self.set_state("-setautoproxystate", service, false)?;
                self.set_state("-setproxyautodiscovery", service, false)?;
            }
            ProxySettings::Manual {
                http_proxy,
                https_proxy,
                bypass,
            } => {
                let (http_host, http_port) = proxy_endpoint(http_proxy)?;
                let (https_host, https_port) = proxy_endpoint(https_proxy)?;
                self.set_manual(
                    "-setwebproxy",
                    "-setwebproxystate",
                    service,
                    &MacOsManualProxy {
                        enabled: true,
                        server: http_host,
                        port: http_port,
                        authenticated: false,
                    },
                )?;
                self.set_manual(
                    "-setsecurewebproxy",
                    "-setsecurewebproxystate",
                    service,
                    &MacOsManualProxy {
                        enabled: true,
                        server: https_host,
                        port: https_port,
                        authenticated: false,
                    },
                )?;
                self.set_state("-setautoproxystate", service, false)?;
                self.set_state("-setproxyautodiscovery", service, false)?;
                self.set_bypass(service, bypass)?;
            }
            ProxySettings::AutoConfig { url } => {
                validate_pac_url(url)?;
                self.set_auto_config(
                    service,
                    &MacOsAutoConfig {
                        enabled: true,
                        url: Some(url.clone()),
                    },
                )?;
                self.set_state("-setwebproxystate", service, false)?;
                self.set_state("-setsecurewebproxystate", service, false)?;
                self.set_state("-setproxyautodiscovery", service, false)?;
            }
        }
        Ok(())
    }

    fn restore_service(&self, service: &MacOsNetworkService) -> Result<(), RecoveryError> {
        self.set_manual(
            "-setwebproxy",
            "-setwebproxystate",
            &service.name,
            &service.web_proxy,
        )?;
        self.set_manual(
            "-setsecurewebproxy",
            "-setsecurewebproxystate",
            &service.name,
            &service.secure_web_proxy,
        )?;
        self.set_auto_config(&service.name, &service.auto_config)?;
        self.set_state(
            "-setproxyautodiscovery",
            &service.name,
            service.auto_discovery_enabled,
        )?;
        self.set_bypass(&service.name, &service.bypass_domains)
    }
}

impl ProxyBackend for MacOsProxyBackend {
    fn descriptor(&self) -> BackendDescriptor {
        BackendDescriptor::MacOs {
            networksetup_path: self.networksetup_path.clone(),
        }
    }

    fn snapshot(&self) -> Result<ProxySnapshot, RecoveryError> {
        let services = self
            .active_services()?
            .iter()
            .map(|service| self.service_snapshot(service))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ProxySnapshot::MacOs { services })
    }

    fn apply(&self, settings: &ProxySettings) -> Result<(), RecoveryError> {
        for service in self.active_services()? {
            self.apply_to_service(&service, settings)?;
        }
        Ok(())
    }

    fn restore(&self, snapshot: &ProxySnapshot) -> Result<(), RecoveryError> {
        let ProxySnapshot::MacOs { services } = snapshot else {
            return Err(RecoveryError::SnapshotBackendMismatch);
        };
        for service in services {
            self.restore_service(service)?;
        }
        Ok(())
    }
}

fn parse_services(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("An asterisk"))
        .filter(|line| !line.starts_with('*'))
        .map(str::to_owned)
        .collect()
}

fn parse_manual_proxy(
    service: &str,
    operation: &str,
    output: &str,
) -> Result<MacOsManualProxy, RecoveryError> {
    let values = parse_key_values(output);
    let enabled = parse_bool(value(&values, "Enabled", operation)?, operation)?;
    let server = value(&values, "Server", operation)?.to_owned();
    let port = value(&values, "Port", operation)?
        .parse()
        .map_err(|_| RecoveryError::PlatformOutputInvalid(operation.to_owned()))?;
    let authenticated = parse_bool(
        value(&values, "Authenticated Proxy Enabled", operation)?,
        operation,
    )?;
    if authenticated {
        return Err(RecoveryError::AuthenticatedProxyUnsupported(
            service.to_owned(),
        ));
    }
    Ok(MacOsManualProxy {
        enabled,
        server,
        port,
        authenticated,
    })
}

fn parse_auto_config(operation: &str, output: &str) -> Result<MacOsAutoConfig, RecoveryError> {
    let values = parse_key_values(output);
    let enabled = parse_bool(value(&values, "Enabled", operation)?, operation)?;
    let raw_url = value(&values, "URL", operation)?;
    let url = if raw_url.is_empty() || raw_url == "(null)" {
        None
    } else {
        Some(raw_url.to_owned())
    };
    Ok(MacOsAutoConfig { enabled, url })
}

fn parse_auto_discovery(operation: &str, output: &str) -> Result<bool, RecoveryError> {
    let values = parse_key_values(output);
    let raw = values
        .get("Auto Proxy Discovery")
        .or_else(|| values.get("Enabled"))
        .ok_or_else(|| RecoveryError::PlatformOutputInvalid(operation.to_owned()))?;
    parse_bool(raw, operation)
}

fn parse_bypass_domains(output: &str) -> Vec<String> {
    if output.trim_start().starts_with("There aren't any") {
        return Vec::new();
    }
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

fn parse_key_values(output: &str) -> HashMap<String, String> {
    output
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .collect()
}

fn value<'a>(
    values: &'a HashMap<String, String>,
    key: &str,
    operation: &str,
) -> Result<&'a str, RecoveryError> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| RecoveryError::PlatformOutputInvalid(operation.to_owned()))
}

fn parse_bool(value: &str, operation: &str) -> Result<bool, RecoveryError> {
    match value.to_ascii_lowercase().as_str() {
        "yes" | "on" | "1" => Ok(true),
        "no" | "off" | "0" => Ok(false),
        _ => Err(RecoveryError::PlatformOutputInvalid(operation.to_owned())),
    }
}

fn proxy_endpoint(value: &str) -> Result<(String, u16), RecoveryError> {
    let url =
        Url::parse(value).map_err(|_| RecoveryError::InvalidProxyEndpoint(value.to_owned()))?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(RecoveryError::InvalidProxyEndpoint(value.to_owned()));
    }
    let host = url
        .host_str()
        .ok_or_else(|| RecoveryError::InvalidProxyEndpoint(value.to_owned()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| RecoveryError::InvalidProxyEndpoint(value.to_owned()))?;
    Ok((host.to_owned(), port))
}

fn validate_pac_url(value: &str) -> Result<(), RecoveryError> {
    let url =
        Url::parse(value).map_err(|_| RecoveryError::InvalidProxyEndpoint(value.to_owned()))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(RecoveryError::InvalidProxyEndpoint(value.to_owned()));
    }
    Ok(())
}

fn on_off(enabled: bool) -> &'static str {
    if enabled { "on" } else { "off" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_active_services_only() {
        let output = "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*USB 10/100/1000 LAN\nThunderbolt Bridge\n";
        assert_eq!(
            parse_services(output),
            vec!["Wi-Fi".to_owned(), "Thunderbolt Bridge".to_owned()]
        );
    }

    #[test]
    fn parses_manual_and_auto_proxy_output() {
        let manual = parse_manual_proxy(
            "Wi-Fi",
            "get",
            "Enabled: Yes\nServer: 127.0.0.1\nPort: 3210\nAuthenticated Proxy Enabled: 0\n",
        )
        .expect("manual proxy must parse");
        assert!(manual.enabled);
        assert_eq!(manual.server, "127.0.0.1");
        assert_eq!(manual.port, 3210);

        let auto =
            parse_auto_config("get", "URL: (null)\nEnabled: No\n").expect("auto proxy must parse");
        assert_eq!(
            auto,
            MacOsAutoConfig {
                enabled: false,
                url: None
            }
        );
        assert!(
            !parse_auto_discovery("get", "Auto Proxy Discovery: Off\n")
                .expect("discovery must parse")
        );
    }

    #[test]
    fn rejects_authenticated_proxy_snapshots() {
        let error = parse_manual_proxy(
            "Wi-Fi",
            "get",
            "Enabled: Yes\nServer: proxy.example\nPort: 8080\nAuthenticated Proxy Enabled: 1\n",
        )
        .expect_err("authenticated proxies must be rejected");
        assert!(matches!(
            error,
            RecoveryError::AuthenticatedProxyUnsupported(_)
        ));
    }
}
