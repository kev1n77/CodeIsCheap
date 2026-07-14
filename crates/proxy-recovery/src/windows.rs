use std::borrow::Cow;
use std::io;

use url::Url;
use windows_sys::Win32::Networking::WinInet::{
    INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, InternetSetOptionW,
};
use winreg::RegKey;
use winreg::enums::{
    HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_BINARY, REG_DWORD, REG_DWORD_BIG_ENDIAN,
    REG_EXPAND_SZ, REG_FULL_RESOURCE_DESCRIPTOR, REG_LINK, REG_MULTI_SZ, REG_NONE, REG_QWORD,
    REG_RESOURCE_LIST, REG_RESOURCE_REQUIREMENTS_LIST, REG_SZ, RegType,
};
use winreg::reg_value::RegValue;

use crate::{
    BackendDescriptor, ProxyBackend, ProxySettings, ProxySnapshot, RecoveryError,
    WindowsRegistryValue,
};

const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const MAIN_VALUES: &[&str] = &[
    "ProxyEnable",
    "ProxyServer",
    "ProxyOverride",
    "AutoConfigURL",
    "AutoDetect",
];
const CONNECTION_VALUES: &[&str] = &["DefaultConnectionSettings", "SavedLegacySettings"];

#[derive(Debug, Clone)]
pub struct WindowsProxyBackend {
    registry_path: String,
    notify: bool,
}

impl WindowsProxyBackend {
    pub fn system() -> Self {
        Self {
            registry_path: INTERNET_SETTINGS.to_owned(),
            notify: true,
        }
    }

    #[doc(hidden)]
    pub fn for_test_registry_path(path: impl Into<String>) -> Result<Self, RecoveryError> {
        let path = path.into();
        if !path.starts_with(r"Software\CodeIsCheap\Tests\") {
            return Err(RecoveryError::UnsupportedBackend);
        }
        Ok(Self {
            registry_path: path,
            notify: false,
        })
    }

    pub(crate) fn for_registry_path(registry_path: String, notify: bool) -> Self {
        Self {
            registry_path,
            notify,
        }
    }

    fn connections_path(&self) -> String {
        format!(r"{}\Connections", self.registry_path)
    }

    fn notify_if_needed(&self) -> Result<(), RecoveryError> {
        if !self.notify {
            return Ok(());
        }
        for option in [INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_OPTION_REFRESH] {
            let result =
                unsafe { InternetSetOptionW(std::ptr::null(), option, std::ptr::null(), 0) };
            if result == 0 {
                return Err(RecoveryError::Io(io::Error::last_os_error()));
            }
        }
        Ok(())
    }
}

impl ProxyBackend for WindowsProxyBackend {
    fn descriptor(&self) -> BackendDescriptor {
        BackendDescriptor::Windows {
            registry_path: self.registry_path.clone(),
            notify: self.notify,
        }
    }

    fn snapshot(&self) -> Result<ProxySnapshot, RecoveryError> {
        let root = RegKey::predef(HKEY_CURRENT_USER);
        let main = root.open_subkey_with_flags(&self.registry_path, KEY_READ)?;
        let main_values = capture_values(&main, MAIN_VALUES)?;
        let connection_values = match root.open_subkey_with_flags(self.connections_path(), KEY_READ)
        {
            Ok(connections) => capture_values(&connections, CONNECTION_VALUES)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(RecoveryError::Io(error)),
        };
        Ok(ProxySnapshot::Windows {
            main_values,
            connection_values,
        })
    }

    fn apply(&self, settings: &ProxySettings) -> Result<(), RecoveryError> {
        let root = RegKey::predef(HKEY_CURRENT_USER);
        let (main, _) = root.create_subkey(&self.registry_path)?;
        match settings {
            ProxySettings::Disabled => {
                main.set_value("ProxyEnable", &0_u32)?;
                main.set_value("AutoDetect", &0_u32)?;
                delete_if_exists(&main, "AutoConfigURL")?;
            }
            ProxySettings::Manual {
                http_proxy,
                https_proxy,
                bypass,
            } => {
                let http = proxy_authority(http_proxy)?;
                let https = proxy_authority(https_proxy)?;
                main.set_value("ProxyServer", &format!("http={http};https={https}"))?;
                main.set_value("ProxyOverride", &bypass.join(";"))?;
                main.set_value("ProxyEnable", &1_u32)?;
                main.set_value("AutoDetect", &0_u32)?;
                delete_if_exists(&main, "AutoConfigURL")?;
            }
            ProxySettings::AutoConfig { url } => {
                validate_pac_url(url)?;
                main.set_value("ProxyEnable", &0_u32)?;
                main.set_value("AutoDetect", &0_u32)?;
                main.set_value("AutoConfigURL", url)?;
                delete_if_exists(&main, "ProxyServer")?;
                delete_if_exists(&main, "ProxyOverride")?;
            }
        }
        self.notify_if_needed()
    }

    fn restore(&self, snapshot: &ProxySnapshot) -> Result<(), RecoveryError> {
        let ProxySnapshot::Windows {
            main_values,
            connection_values,
        } = snapshot
        else {
            return Err(RecoveryError::SnapshotBackendMismatch);
        };
        let root = RegKey::predef(HKEY_CURRENT_USER);
        restore_values(&root, &self.registry_path, MAIN_VALUES, main_values)?;
        restore_values(
            &root,
            &self.connections_path(),
            CONNECTION_VALUES,
            connection_values,
        )?;
        self.notify_if_needed()
    }
}

fn capture_values(
    key: &RegKey,
    names: &[&str],
) -> Result<Vec<WindowsRegistryValue>, RecoveryError> {
    let mut values = Vec::new();
    for name in names {
        match key.get_raw_value(name) {
            Ok(value) => values.push(WindowsRegistryValue {
                name: (*name).to_owned(),
                value_type: value.vtype.clone() as u32,
                bytes: value.bytes.into_owned(),
            }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(RecoveryError::Io(error)),
        }
    }
    Ok(values)
}

fn restore_values(
    root: &RegKey,
    path: &str,
    tracked_names: &[&str],
    values: &[WindowsRegistryValue],
) -> Result<(), RecoveryError> {
    let key = match root.open_subkey_with_flags(path, KEY_READ | KEY_WRITE) {
        Ok(key) => key,
        Err(error) if error.kind() == io::ErrorKind::NotFound && values.is_empty() => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => root.create_subkey(path)?.0,
        Err(error) => return Err(RecoveryError::Io(error)),
    };
    for name in tracked_names {
        delete_if_exists(&key, name)?;
    }
    for value in values {
        let raw = RegValue {
            bytes: Cow::Borrowed(&value.bytes),
            vtype: reg_type(value.value_type)?,
        };
        key.set_raw_value(&value.name, &raw)?;
    }
    Ok(())
}

fn delete_if_exists(key: &RegKey, name: &str) -> Result<(), RecoveryError> {
    match key.delete_value(name) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(RecoveryError::Io(error)),
    }
}

fn proxy_authority(endpoint: &str) -> Result<String, RecoveryError> {
    let url = Url::parse(endpoint)
        .map_err(|_| RecoveryError::InvalidProxyEndpoint(endpoint.to_owned()))?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(RecoveryError::InvalidProxyEndpoint(endpoint.to_owned()));
    }
    let host = url
        .host_str()
        .ok_or_else(|| RecoveryError::InvalidProxyEndpoint(endpoint.to_owned()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| RecoveryError::InvalidProxyEndpoint(endpoint.to_owned()))?;
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    Ok(format!("{host}:{port}"))
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

fn reg_type(value_type: u32) -> Result<RegType, RecoveryError> {
    let value_type = match value_type {
        value if value == REG_NONE.clone() as u32 => REG_NONE,
        value if value == REG_SZ.clone() as u32 => REG_SZ,
        value if value == REG_EXPAND_SZ.clone() as u32 => REG_EXPAND_SZ,
        value if value == REG_BINARY.clone() as u32 => REG_BINARY,
        value if value == REG_DWORD.clone() as u32 => REG_DWORD,
        value if value == REG_DWORD_BIG_ENDIAN.clone() as u32 => REG_DWORD_BIG_ENDIAN,
        value if value == REG_LINK.clone() as u32 => REG_LINK,
        value if value == REG_MULTI_SZ.clone() as u32 => REG_MULTI_SZ,
        value if value == REG_RESOURCE_LIST.clone() as u32 => REG_RESOURCE_LIST,
        value if value == REG_FULL_RESOURCE_DESCRIPTOR.clone() as u32 => {
            REG_FULL_RESOURCE_DESCRIPTOR
        }
        value if value == REG_RESOURCE_REQUIREMENTS_LIST.clone() as u32 => {
            REG_RESOURCE_REQUIREMENTS_LIST
        }
        value if value == REG_QWORD.clone() as u32 => REG_QWORD,
        _ => return Err(RecoveryError::SnapshotBackendMismatch),
    };
    Ok(value_type)
}
