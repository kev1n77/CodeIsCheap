//! Verified loading and least-environment process lifecycle for capture sidecars.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};

#[cfg(target_os = "macos")]
use security_framework::trust_settings::{Domain, TrustSettings, TrustSettingsForCertificate};
#[cfg(windows)]
use std::mem::size_of;
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
#[cfg(windows)]
use std::os::windows::{
    ffi::OsStrExt as _,
    io::{AsRawHandle, FromRawHandle, OwnedHandle},
};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CRYPT_E_NOT_FOUND, ERROR_SUCCESS, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE,
    GetLastError, HANDLE, LocalFree,
};
#[cfg(windows)]
use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
#[cfg(windows)]
use windows_sys::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_STORE_ADD_USE_EXISTING, CERT_STORE_OPEN_EXISTING_FLAG,
    CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_CURRENT_USER,
    CERT_SYSTEM_STORE_LOCAL_MACHINE, CertAddCertificateContextToStore, CertCloseStore,
    CertCreateCertificateContext, CertDeleteCertificateFromStore, CertEnumCertificatesInStore,
    CertFreeCertificateContext, CertOpenStore, HCERTSTORE, X509_ASN_ENCODING,
};
#[cfg(windows)]
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, CreateWellKnownSid, DACL_SECURITY_INFORMATION, GetAce, GetLengthSid,
    GetTokenInformation, IsValidAcl, IsValidSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    PSID, SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid,
    WinCreatorOwnerRightsSid, WinCreatorOwnerSid, WinLocalSystemSid,
};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_EXECUTE, FILE_READ_ATTRIBUTES,
    FILE_READ_DATA, FILE_READ_EA, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, WRITE_DAC,
    WRITE_OWNER,
};
#[cfg(windows)]
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
#[cfg(windows)]
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
    ACCESS_ALLOWED_OBJECT_ACE_TYPE,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub const SIDECAR_MANIFEST_VERSION: &str = "0.1";
pub const CAPTURE_CONTRACT_VERSION: &str = "0.1";
pub const MITMPROXY_VERSION: &str = "12.2.3";
pub const SIDECAR_NAME: &str = "codeischeap-mitmproxy";
pub const MANIFEST_FILENAME: &str = "sidecar-manifest.json";
pub const CA_CERTIFICATE_FILENAME: &str = "mitmproxy-ca-cert.pem";
pub const CA_PRIVATE_PEM_FILENAME: &str = "mitmproxy-ca.pem";
pub const CA_PRIVATE_P12_FILENAME: &str = "mitmproxy-ca.p12";

const CAPTURE_ENVIRONMENT: [&str; 4] = [
    "CIC_CAPTURE_HOSTS",
    "CIC_CAPTURE_IPC_ADDR",
    "CIC_CAPTURE_IPC_TOKEN",
    "CIC_CAPTURE_POLICY_PATH",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateAuthorityState {
    Missing,
    Ready,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateMaterialState {
    Missing,
    Restricted,
    Unchecked,
    Insecure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateTrustState {
    Unchecked,
    Trusted,
    NotTrusted,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateAuthorityStatus {
    pub state: CertificateAuthorityState,
    pub can_manage_trust: bool,
    pub fingerprint_sha256: Option<String>,
    pub subject: Option<String>,
    pub valid_from_unix_ms: Option<i64>,
    pub valid_until_unix_ms: Option<i64>,
    pub private_material: PrivateMaterialState,
    pub trust: CertificateTrustState,
    pub detail: Option<String>,
}

impl CertificateAuthorityStatus {
    #[must_use]
    pub fn missing() -> Self {
        Self {
            state: CertificateAuthorityState::Missing,
            can_manage_trust: false,
            fingerprint_sha256: None,
            subject: None,
            valid_from_unix_ms: None,
            valid_until_unix_ms: None,
            private_material: PrivateMaterialState::Missing,
            trust: CertificateTrustState::Unchecked,
            detail: None,
        }
    }
}

#[derive(Debug)]
pub enum CertificateAuthorityError {
    UnsupportedPlatform,
    MissingCertificate,
    InvalidCertificate(String),
    Platform(io::Error),
}

impl fmt::Display for CertificateAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                write!(formatter, "certificate trust management is unsupported")
            }
            Self::MissingCertificate => write!(formatter, "certificate authority is missing"),
            Self::InvalidCertificate(detail) => {
                write!(formatter, "certificate authority is invalid: {detail}")
            }
            Self::Platform(error) => write!(formatter, "certificate trust update failed: {error}"),
        }
    }
}

impl std::error::Error for CertificateAuthorityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Platform(error) => Some(error),
            _ => None,
        }
    }
}

#[must_use = "certificate trust installation can fail"]
pub fn install_certificate_authority(
    confdir: impl AsRef<Path>,
) -> Result<bool, CertificateAuthorityError> {
    #[cfg(windows)]
    {
        let certificate_der = load_certificate_der(confdir.as_ref())?;
        validate_trust_anchor(&certificate_der)?;
        windows_install_certificate(&certificate_der).map_err(CertificateAuthorityError::Platform)
    }
    #[cfg(not(windows))]
    {
        let _ = confdir;
        Err(CertificateAuthorityError::UnsupportedPlatform)
    }
}

#[must_use = "certificate trust removal can fail"]
pub fn uninstall_certificate_authority(
    confdir: impl AsRef<Path>,
) -> Result<bool, CertificateAuthorityError> {
    #[cfg(windows)]
    {
        let certificate_der = load_certificate_der(confdir.as_ref())?;
        windows_uninstall_certificate(&certificate_der).map_err(CertificateAuthorityError::Platform)
    }
    #[cfg(not(windows))]
    {
        let _ = confdir;
        Err(CertificateAuthorityError::UnsupportedPlatform)
    }
}

#[cfg(any(windows, test))]
fn load_certificate_der(confdir: &Path) -> Result<Vec<u8>, CertificateAuthorityError> {
    let encoded = fs::read(confdir.join(CA_CERTIFICATE_FILENAME)).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            CertificateAuthorityError::MissingCertificate
        } else {
            CertificateAuthorityError::Platform(error)
        }
    })?;
    let (remaining, pem) = parse_x509_pem(&encoded)
        .map_err(|_| CertificateAuthorityError::InvalidCertificate("invalid PEM".to_owned()))?;
    if !remaining.iter().all(u8::is_ascii_whitespace) || pem.label != "CERTIFICATE" {
        return Err(CertificateAuthorityError::InvalidCertificate(
            "unexpected PEM content".to_owned(),
        ));
    }
    let (remaining, _) = parse_x509_certificate(&pem.contents)
        .map_err(|_| CertificateAuthorityError::InvalidCertificate("invalid X.509".to_owned()))?;
    if !remaining.is_empty() {
        return Err(CertificateAuthorityError::InvalidCertificate(
            "trailing DER content".to_owned(),
        ));
    }
    Ok(pem.contents)
}

#[cfg(any(windows, test))]
fn validate_trust_anchor(certificate_der: &[u8]) -> Result<(), CertificateAuthorityError> {
    let (_, certificate) = parse_x509_certificate(certificate_der)
        .map_err(|_| CertificateAuthorityError::InvalidCertificate("invalid X.509".to_owned()))?;
    if certificate.subject() != certificate.issuer() {
        return Err(CertificateAuthorityError::InvalidCertificate(
            "certificate is not self-issued".to_owned(),
        ));
    }
    let is_ca = certificate
        .basic_constraints()
        .map_err(|_| {
            CertificateAuthorityError::InvalidCertificate("invalid basic constraints".to_owned())
        })?
        .is_some_and(|constraints| constraints.value.ca);
    if !is_ca {
        return Err(CertificateAuthorityError::InvalidCertificate(
            "basic constraints do not identify a CA".to_owned(),
        ));
    }
    if !certificate.validity().is_valid() {
        return Err(CertificateAuthorityError::InvalidCertificate(
            "certificate is outside its validity period".to_owned(),
        ));
    }
    certificate.verify_signature(None).map_err(|_| {
        CertificateAuthorityError::InvalidCertificate(
            "self-signature verification failed".to_owned(),
        )
    })
}

#[must_use]
pub fn inspect_certificate_authority(confdir: impl AsRef<Path>) -> CertificateAuthorityStatus {
    let confdir = confdir.as_ref();
    let certificate_path = confdir.join(CA_CERTIFICATE_FILENAME);
    let private_paths = [
        confdir.join(CA_PRIVATE_PEM_FILENAME),
        confdir.join(CA_PRIVATE_P12_FILENAME),
    ];
    let certificate_exists = certificate_path.is_file();
    let private_exists = private_paths.each_ref().map(|path| path.is_file());
    if !certificate_exists && private_exists.iter().all(|exists| !exists) {
        return CertificateAuthorityStatus::missing();
    }

    let private_material = private_material_state(&private_paths, private_exists);
    if !certificate_exists {
        return invalid_certificate_authority(
            private_material,
            "certificate authority files are incomplete",
        );
    }

    let encoded = match fs::read(&certificate_path) {
        Ok(encoded) => encoded,
        Err(_) => {
            return invalid_certificate_authority(
                private_material,
                "certificate authority certificate is unreadable",
            );
        }
    };
    let (remaining, pem) = match parse_x509_pem(&encoded) {
        Ok(parsed) => parsed,
        Err(_) => {
            return invalid_certificate_authority(
                private_material,
                "certificate authority certificate is invalid PEM",
            );
        }
    };
    if !remaining.iter().all(u8::is_ascii_whitespace) || pem.label != "CERTIFICATE" {
        return invalid_certificate_authority(
            private_material,
            "certificate authority certificate has unexpected PEM content",
        );
    }
    let (der_remaining, certificate) = match parse_x509_certificate(&pem.contents) {
        Ok(parsed) => parsed,
        Err(_) => {
            return invalid_certificate_authority(
                private_material,
                "certificate authority certificate is invalid X.509",
            );
        }
    };
    if !der_remaining.is_empty() {
        return invalid_certificate_authority(
            private_material,
            "certificate authority certificate has trailing DER content",
        );
    }
    let subject = certificate
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attribute| attribute.as_str().ok())
        .map(str::to_owned)
        .unwrap_or_else(|| certificate.subject().to_string());
    let validity = certificate.validity();
    let private_material_secure = !matches!(private_material, PrivateMaterialState::Insecure);
    let certificate_valid = validity.is_valid();
    let (state, detail) = if private_material == PrivateMaterialState::Missing {
        (
            CertificateAuthorityState::Invalid,
            Some("certificate authority files are incomplete".to_owned()),
        )
    } else if !private_material_secure {
        (
            CertificateAuthorityState::Invalid,
            Some("certificate authority private material permissions are too broad".to_owned()),
        )
    } else if !certificate_valid {
        (
            CertificateAuthorityState::Invalid,
            Some("certificate authority certificate is outside its validity period".to_owned()),
        )
    } else {
        (CertificateAuthorityState::Ready, None)
    };
    let (trust, can_manage_trust) = certificate_trust_status(&pem.contents);
    CertificateAuthorityStatus {
        state,
        can_manage_trust,
        fingerprint_sha256: Some(format_fingerprint(Sha256::digest(&pem.contents).as_slice())),
        subject: Some(subject),
        valid_from_unix_ms: Some(validity.not_before.timestamp().saturating_mul(1_000)),
        valid_until_unix_ms: Some(validity.not_after.timestamp().saturating_mul(1_000)),
        private_material,
        trust,
        detail,
    }
}

fn invalid_certificate_authority(
    private_material: PrivateMaterialState,
    detail: &str,
) -> CertificateAuthorityStatus {
    CertificateAuthorityStatus {
        state: CertificateAuthorityState::Invalid,
        can_manage_trust: false,
        fingerprint_sha256: None,
        subject: None,
        valid_from_unix_ms: None,
        valid_until_unix_ms: None,
        private_material,
        trust: CertificateTrustState::Unchecked,
        detail: Some(detail.to_owned()),
    }
}

fn private_material_state(paths: &[PathBuf; 2], exists: [bool; 2]) -> PrivateMaterialState {
    if !exists.into_iter().all(|exists| exists) {
        return PrivateMaterialState::Missing;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let restricted = paths.iter().all(|path| {
            fs::metadata(path)
                .map(|metadata| metadata.permissions().mode() & 0o077 == 0)
                .unwrap_or(false)
        });
        if restricted {
            PrivateMaterialState::Restricted
        } else {
            PrivateMaterialState::Insecure
        }
    }
    #[cfg(windows)]
    {
        windows_private_material_state(paths)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = paths;
        PrivateMaterialState::Unchecked
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsAclState {
    Restricted,
    Unchecked,
    Insecure,
}

#[cfg(windows)]
struct OwnedSid {
    storage: Vec<usize>,
    length: usize,
}

#[cfg(windows)]
impl OwnedSid {
    fn from_psid(sid: PSID) -> io::Result<Self> {
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Windows SID",
            ));
        }
        let length = unsafe { GetLengthSid(sid) } as usize;
        let mut storage = vec![0usize; length.div_ceil(size_of::<usize>())];
        unsafe {
            std::ptr::copy_nonoverlapping(
                sid.cast::<u8>(),
                storage.as_mut_ptr().cast::<u8>(),
                length,
            );
        }
        Ok(Self { storage, length })
    }

    fn well_known(kind: i32) -> io::Result<Self> {
        let capacity = SECURITY_MAX_SID_SIZE as usize;
        let mut storage = vec![0usize; capacity.div_ceil(size_of::<usize>())];
        let mut length = capacity as u32;
        if unsafe {
            CreateWellKnownSid(
                kind,
                std::ptr::null_mut(),
                storage.as_mut_ptr().cast(),
                &mut length,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            storage,
            length: length as usize,
        })
    }

    #[cfg(test)]
    fn as_psid(&self) -> PSID {
        self.storage.as_ptr().cast_mut().cast()
    }

    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.storage.as_ptr().cast(), self.length) }
    }
}

#[cfg(windows)]
struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

#[cfg(windows)]
impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

#[cfg(windows)]
fn windows_private_material_state(paths: &[PathBuf; 2]) -> PrivateMaterialState {
    if paths.iter().any(|path| File::open(path).is_err()) {
        return PrivateMaterialState::Unchecked;
    }
    let allowed_sids = match windows_allowed_private_material_sids() {
        Ok(sids) => sids,
        Err(_) => return PrivateMaterialState::Unchecked,
    };
    let mut state = WindowsAclState::Restricted;
    for path in paths {
        match windows_file_acl_state(path, &allowed_sids) {
            Ok(WindowsAclState::Restricted) => {}
            Ok(WindowsAclState::Unchecked) | Err(_) => state = WindowsAclState::Unchecked,
            Ok(WindowsAclState::Insecure) => return PrivateMaterialState::Insecure,
        }
    }
    match state {
        WindowsAclState::Restricted => PrivateMaterialState::Restricted,
        WindowsAclState::Unchecked => PrivateMaterialState::Unchecked,
        WindowsAclState::Insecure => PrivateMaterialState::Insecure,
    }
}

#[cfg(windows)]
fn windows_allowed_private_material_sids() -> io::Result<Vec<OwnedSid>> {
    Ok(vec![
        current_user_sid()?,
        OwnedSid::well_known(WinLocalSystemSid)?,
        OwnedSid::well_known(WinBuiltinAdministratorsSid)?,
        OwnedSid::well_known(WinCreatorOwnerSid)?,
        OwnedSid::well_known(WinCreatorOwnerRightsSid)?,
    ])
}

#[cfg(windows)]
fn current_user_sid() -> io::Result<OwnedSid> {
    let mut token_handle = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token_handle) };
    let mut required = 0;
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut required,
        );
    }
    if required == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buffer = vec![0usize; (required as usize).div_ceil(size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    OwnedSid::from_psid(token_user.User.Sid)
}

#[cfg(windows)]
fn windows_file_acl_state(path: &Path, allowed_sids: &[OwnedSid]) -> io::Result<WindowsAclState> {
    let mut wide_path = path.as_os_str().encode_wide().collect::<Vec<_>>();
    wide_path.push(0);
    let mut owner = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let result = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if result != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    let _descriptor = LocalSecurityDescriptor(descriptor);
    if dacl.is_null() {
        return Ok(WindowsAclState::Insecure);
    }
    if unsafe { IsValidAcl(dacl) } == 0 {
        return Ok(WindowsAclState::Unchecked);
    }
    if !sid_is_allowed(owner, allowed_sids)? {
        return Ok(WindowsAclState::Insecure);
    }

    let mut state = WindowsAclState::Restricted;
    let ace_count = unsafe { (*dacl).AceCount } as u32;
    for index in 0..ace_count {
        let mut raw_ace = std::ptr::null_mut();
        if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let header = unsafe { &*raw_ace.cast::<windows_sys::Win32::Security::ACE_HEADER>() };
        let ace_type = header.AceType as u32;
        if !matches!(
            ace_type,
            ACCESS_ALLOWED_ACE_TYPE
                | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                | ACCESS_ALLOWED_OBJECT_ACE_TYPE
                | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
                | ACCESS_ALLOWED_COMPOUND_ACE_TYPE
        ) {
            continue;
        }
        if (header.AceSize as usize) < size_of::<ACCESS_ALLOWED_ACE>() {
            state = WindowsAclState::Unchecked;
            continue;
        }
        let mask = unsafe { (*raw_ace.cast::<ACCESS_ALLOWED_ACE>()).Mask };
        if mask & WINDOWS_PRIVATE_MATERIAL_ACCESS == 0 {
            continue;
        }
        if !matches!(
            ace_type,
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
        ) {
            state = WindowsAclState::Unchecked;
            continue;
        }
        let ace = raw_ace.cast::<ACCESS_ALLOWED_ACE>();
        let sid = unsafe { std::ptr::addr_of_mut!((*ace).SidStart).cast() };
        if !sid_is_allowed(sid, allowed_sids)? {
            return Ok(WindowsAclState::Insecure);
        }
    }
    Ok(state)
}

#[cfg(windows)]
const WINDOWS_PRIVATE_MATERIAL_ACCESS: u32 = GENERIC_ALL
    | GENERIC_READ
    | GENERIC_WRITE
    | GENERIC_EXECUTE
    | FILE_READ_DATA
    | FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_READ_EA
    | FILE_WRITE_EA
    | FILE_EXECUTE
    | FILE_DELETE_CHILD
    | FILE_READ_ATTRIBUTES
    | FILE_WRITE_ATTRIBUTES
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER;

#[cfg(windows)]
fn sid_is_allowed(sid: PSID, allowed_sids: &[OwnedSid]) -> io::Result<bool> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Windows SID",
        ));
    }
    let length = unsafe { GetLengthSid(sid) } as usize;
    let bytes = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) };
    Ok(allowed_sids.iter().any(|allowed| allowed.bytes() == bytes))
}

fn certificate_trust_status(certificate_der: &[u8]) -> (CertificateTrustState, bool) {
    #[cfg(windows)]
    {
        windows_certificate_trust_status(certificate_der)
    }
    #[cfg(target_os = "macos")]
    {
        (macos_certificate_trust_state(certificate_der), false)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = certificate_der;
        (CertificateTrustState::Unsupported, false)
    }
}

#[cfg(target_os = "macos")]
fn macos_certificate_trust_state(certificate_der: &[u8]) -> CertificateTrustState {
    for domain in [Domain::User, Domain::Admin, Domain::System] {
        let settings = TrustSettings::new(domain);
        let certificates = match settings.iter() {
            Ok(certificates) => certificates,
            Err(_) => return CertificateTrustState::Unchecked,
        };
        for candidate in certificates {
            if candidate.to_der() != certificate_der {
                continue;
            }
            return match settings.tls_trust_settings_for_certificate(&candidate) {
                Ok(result) => macos_trust_result_state(result),
                Err(_) => CertificateTrustState::Unchecked,
            };
        }
    }
    CertificateTrustState::NotTrusted
}

#[cfg(target_os = "macos")]
fn macos_trust_result_state(result: Option<TrustSettingsForCertificate>) -> CertificateTrustState {
    match result {
        None
        | Some(TrustSettingsForCertificate::TrustRoot)
        | Some(TrustSettingsForCertificate::TrustAsRoot) => CertificateTrustState::Trusted,
        Some(
            TrustSettingsForCertificate::Deny
            | TrustSettingsForCertificate::Unspecified
            | TrustSettingsForCertificate::Invalid,
        ) => CertificateTrustState::NotTrusted,
    }
}

#[cfg(windows)]
struct WindowsCertificateStore(HCERTSTORE);

#[cfg(windows)]
impl Drop for WindowsCertificateStore {
    fn drop(&mut self) {
        unsafe {
            CertCloseStore(self.0, 0);
        }
    }
}

#[cfg(windows)]
struct WindowsCertificateContext(*mut CERT_CONTEXT);

#[cfg(windows)]
impl Drop for WindowsCertificateContext {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CertFreeCertificateContext(self.0);
            }
        }
    }
}

#[cfg(windows)]
fn windows_certificate_trust_status(certificate_der: &[u8]) -> (CertificateTrustState, bool) {
    match windows_root_store_contains(CERT_SYSTEM_STORE_CURRENT_USER, certificate_der) {
        Ok(true) => return (CertificateTrustState::Trusted, true),
        Ok(false) => {}
        Err(_) => return (CertificateTrustState::Unchecked, false),
    }
    match windows_root_store_contains(CERT_SYSTEM_STORE_LOCAL_MACHINE, certificate_der) {
        Ok(true) => (CertificateTrustState::Trusted, false),
        Ok(false) => (CertificateTrustState::NotTrusted, true),
        Err(_) => (CertificateTrustState::Unchecked, false),
    }
}

#[cfg(windows)]
fn windows_root_store_contains(scope: u32, certificate_der: &[u8]) -> io::Result<bool> {
    let store = windows_open_root_store(scope, true)?;
    windows_certificate_store_contains(store.0, certificate_der)
}

#[cfg(windows)]
fn windows_certificate_store_contains(
    store: HCERTSTORE,
    certificate_der: &[u8],
) -> io::Result<bool> {
    match windows_find_certificate(store, certificate_der)? {
        Some(context) => {
            unsafe {
                CertFreeCertificateContext(context);
            }
            Ok(true)
        }
        None => Ok(false),
    }
}

#[cfg(windows)]
fn windows_install_certificate(certificate_der: &[u8]) -> io::Result<bool> {
    let store = windows_open_root_store(CERT_SYSTEM_STORE_CURRENT_USER, false)?;
    windows_add_certificate_to_store(store.0, certificate_der)
}

#[cfg(windows)]
fn windows_uninstall_certificate(certificate_der: &[u8]) -> io::Result<bool> {
    let store = windows_open_root_store(CERT_SYSTEM_STORE_CURRENT_USER, false)?;
    windows_delete_certificate_from_store(store.0, certificate_der)
}

#[cfg(windows)]
fn windows_add_certificate_to_store(store: HCERTSTORE, certificate_der: &[u8]) -> io::Result<bool> {
    if let Some(context) = windows_find_certificate(store, certificate_der)? {
        unsafe {
            CertFreeCertificateContext(context);
        }
        return Ok(false);
    }
    let context = unsafe {
        CertCreateCertificateContext(
            X509_ASN_ENCODING,
            certificate_der.as_ptr(),
            certificate_der.len() as u32,
        )
    };
    if context.is_null() {
        return Err(io::Error::last_os_error());
    }
    let context = WindowsCertificateContext(context);
    if unsafe {
        CertAddCertificateContextToStore(
            store,
            context.0,
            CERT_STORE_ADD_USE_EXISTING,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(true)
}

#[cfg(windows)]
fn windows_delete_certificate_from_store(
    store: HCERTSTORE,
    certificate_der: &[u8],
) -> io::Result<bool> {
    let Some(context) = windows_find_certificate(store, certificate_der)? else {
        return Ok(false);
    };
    if unsafe { CertDeleteCertificateFromStore(context) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(true)
}

#[cfg(windows)]
fn windows_open_root_store(scope: u32, read_only: bool) -> io::Result<WindowsCertificateStore> {
    const ROOT_STORE: [u16; 5] = [b'R' as u16, b'O' as u16, b'O' as u16, b'T' as u16, 0];
    let access = if read_only {
        CERT_STORE_READONLY_FLAG
    } else {
        0
    };
    let store = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            0,
            0,
            scope | CERT_STORE_OPEN_EXISTING_FLAG | access,
            ROOT_STORE.as_ptr().cast(),
        )
    };
    if store.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(WindowsCertificateStore(store))
}

#[cfg(windows)]
fn windows_find_certificate(
    store: HCERTSTORE,
    certificate_der: &[u8],
) -> io::Result<Option<*mut CERT_CONTEXT>> {
    let mut context: *mut CERT_CONTEXT = std::ptr::null_mut();
    loop {
        context = unsafe { CertEnumCertificatesInStore(store, context) };
        if context.is_null() {
            let error = unsafe { GetLastError() };
            return if error == CRYPT_E_NOT_FOUND as u32 {
                Ok(None)
            } else {
                Err(io::Error::from_raw_os_error(error as i32))
            };
        }
        let encoded = unsafe {
            std::slice::from_raw_parts((*context).pbCertEncoded, (*context).cbCertEncoded as usize)
        };
        // Subject and serial are not strong enough to identify the exact local CA.
        if encoded == certificate_der {
            return Ok(Some(context));
        }
    }
}

fn format_fingerprint(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[derive(Debug)]
pub enum SidecarError {
    Io(io::Error),
    Json(serde_json::Error),
    UnsupportedPlatform,
    InvalidManifest(String),
    InvalidBundlePath(String),
    MissingBundleFile(String),
    BundleFileIsSymlink(String),
    SizeMismatch(String),
    HashMismatch(String),
    TargetMismatch { expected: String, actual: String },
    SignatureRequired,
    InvalidLaunchConfig(String),
    ProcessExited(Option<i32>),
    StartupTimeout(Duration),
}

impl fmt::Display for SidecarError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "sidecar I/O failed: {error}"),
            Self::Json(error) => write!(formatter, "sidecar metadata is invalid JSON: {error}"),
            Self::UnsupportedPlatform => write!(formatter, "sidecar platform is unsupported"),
            Self::InvalidManifest(detail) => {
                write!(formatter, "sidecar manifest is invalid: {detail}")
            }
            Self::InvalidBundlePath(name) => {
                write!(formatter, "sidecar bundle path is invalid: {name}")
            }
            Self::MissingBundleFile(name) => {
                write!(formatter, "sidecar bundle file is missing: {name}")
            }
            Self::BundleFileIsSymlink(name) => write!(
                formatter,
                "sidecar bundle file must not be a symlink: {name}"
            ),
            Self::SizeMismatch(name) => {
                write!(formatter, "sidecar bundle file size does not match: {name}")
            }
            Self::HashMismatch(name) => {
                write!(formatter, "sidecar bundle file hash does not match: {name}")
            }
            Self::TargetMismatch { expected, actual } => {
                write!(formatter, "sidecar target is {actual}, expected {expected}")
            }
            Self::SignatureRequired => write!(
                formatter,
                "sidecar release requires a valid platform signature"
            ),
            Self::InvalidLaunchConfig(detail) => write!(
                formatter,
                "sidecar launch configuration is invalid: {detail}"
            ),
            Self::ProcessExited(code) => write!(
                formatter,
                "sidecar exited before accepting connections with code {code:?}"
            ),
            Self::StartupTimeout(timeout) => write!(
                formatter,
                "sidecar did not accept connections within {} ms",
                timeout.as_millis()
            ),
        }
    }
}

impl std::error::Error for SidecarError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for SidecarError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for SidecarError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleRequirements {
    pub require_platform_signature: bool,
}

impl BundleRequirements {
    #[must_use]
    pub const fn development() -> Self {
        Self {
            require_platform_signature: false,
        }
    }

    #[must_use]
    pub const fn release() -> Self {
        Self {
            require_platform_signature: true,
        }
    }
}

#[derive(Debug)]
pub struct SidecarBundle {
    root: PathBuf,
    executable: PathBuf,
    policy: PathBuf,
    sbom: PathBuf,
    manifest: SidecarManifest,
}

impl SidecarBundle {
    pub fn load(
        root: impl AsRef<Path>,
        requirements: BundleRequirements,
    ) -> Result<Self, SidecarError> {
        let root = root.as_ref().to_path_buf();
        let manifest_path = checked_bundle_file(&root, MANIFEST_FILENAME)?;
        let manifest: SidecarManifest = serde_json::from_reader(File::open(manifest_path)?)?;
        validate_manifest(&manifest, requirements)?;

        let executable = checked_bundle_file(&root, &manifest.artifact.file)?;
        validate_size_and_hash(&executable, &manifest.artifact)?;
        let policy = checked_bundle_file(&root, &manifest.capture_contract.policy_file)?;
        validate_hash(
            &policy,
            &manifest.capture_contract.policy_sha256,
            &manifest.capture_contract.policy_file,
        )?;
        let sbom = checked_bundle_file(&root, &manifest.sbom.file)?;
        validate_hash(&sbom, &manifest.sbom.sha256, &manifest.sbom.file)?;
        validate_sbom(&sbom)?;

        Ok(Self {
            root,
            executable,
            policy,
            sbom,
            manifest,
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    #[must_use]
    pub fn policy(&self) -> &Path {
        &self.policy
    }

    #[must_use]
    pub fn sbom(&self) -> &Path {
        &self.sbom
    }

    #[must_use]
    pub fn target_triple(&self) -> &str {
        &self.manifest.target_triple
    }

    pub fn command(&self, config: &SidecarLaunchConfig) -> Result<Command, SidecarError> {
        config.validate()?;
        fs::create_dir_all(&config.confdir)?;
        let mut command = Command::new(&self.executable);
        command.env_clear();
        for key in inherited_environment_keys() {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        command
            .env("CIC_CAPTURE_IPC_ADDR", config.ipc_addr.to_string())
            .env("CIC_CAPTURE_IPC_TOKEN", &config.ipc_token)
            .env("CIC_CAPTURE_HOSTS", config.target_hosts.join(","))
            .env("CIC_CAPTURE_POLICY_PATH", &self.policy)
            .args([
                OsStr::new("--listen-host"),
                OsStr::new(&config.listen_addr.ip().to_string()),
                OsStr::new("--listen-port"),
                OsStr::new(&config.listen_addr.port().to_string()),
                OsStr::new("--set"),
                OsStr::new(&format!("confdir={}", config.confdir.display())),
                OsStr::new("--set"),
                OsStr::new("termlog_verbosity=error"),
            ])
            .current_dir(&config.confdir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for host in &config.target_hosts {
            command.arg("--allow-hosts").arg(allow_host_pattern(host));
        }
        #[cfg(unix)]
        command.process_group(0);
        Ok(command)
    }

    pub fn launch(
        &self,
        config: &SidecarLaunchConfig,
        startup_timeout: Duration,
    ) -> Result<SidecarProcess, SidecarError> {
        let mut child = self.command(config)?.spawn()?;
        #[cfg(windows)]
        let job = match WindowsJob::assign(&child) {
            Ok(job) => job,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(SidecarError::Io(error));
            }
        };
        let started = Instant::now();
        while started.elapsed() < startup_timeout {
            if let Some(status) = child.try_wait()? {
                #[cfg(unix)]
                let _ = terminate_process_group(child.id());
                return Err(SidecarError::ProcessExited(status.code()));
            }
            if TcpStream::connect_timeout(&config.listen_addr, Duration::from_millis(100)).is_ok() {
                return Ok(SidecarProcess {
                    child: Some(child),
                    endpoint: config.listen_addr,
                    #[cfg(windows)]
                    job: Some(job),
                });
            }
            thread::sleep(Duration::from_millis(50));
        }
        stop_spawned_process(&mut child);
        Err(SidecarError::StartupTimeout(startup_timeout))
    }
}

pub struct SidecarProcess {
    child: Option<Child>,
    endpoint: SocketAddr,
    #[cfg(windows)]
    job: Option<WindowsJob>,
}

impl SidecarProcess {
    #[must_use]
    pub const fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub fn stop(&mut self) -> Result<(), SidecarError> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        #[cfg(windows)]
        drop(self.job.take());
        #[cfg(unix)]
        let process_group_error = terminate_process_group(child.id()).err();
        if child.try_wait()?.is_none() {
            child.kill()?;
        }
        child.wait()?;
        #[cfg(unix)]
        if let Some(error) = process_group_error {
            return Err(error);
        }
        Ok(())
    }
}

fn stop_spawned_process(child: &mut Child) {
    #[cfg(unix)]
    let _ = terminate_process_group(child.id());
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
fn terminate_process_group(process_id: u32) -> Result<(), SidecarError> {
    let process_group = i32::try_from(process_id).map_err(|_| {
        SidecarError::InvalidLaunchConfig("sidecar process ID is invalid".to_owned())
    })?;
    let result = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(SidecarError::Io(error))
    }
}

#[cfg(windows)]
struct WindowsJob(OwnedHandle);

#[cfg(windows)]
impl WindowsJob {
    fn assign(child: &Child) -> io::Result<Self> {
        let raw_job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw_job.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = Self(unsafe { OwnedHandle::from_raw_handle(raw_job.cast()) });
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                job.handle(),
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                u32::try_from(std::mem::size_of_val(&limits)).expect("job limits fit in u32"),
            )
        };
        if configured == 0 {
            return Err(io::Error::last_os_error());
        }
        let assigned = unsafe {
            AssignProcessToJobObject(
                job.handle(),
                child.as_raw_handle().cast::<std::ffi::c_void>(),
            )
        };
        if assigned == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(job)
    }

    fn handle(&self) -> HANDLE {
        self.0.as_raw_handle().cast()
    }
}

impl Drop for SidecarProcess {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

pub struct SidecarLaunchConfig {
    pub ipc_addr: SocketAddr,
    ipc_token: String,
    pub target_hosts: Vec<String>,
    pub listen_addr: SocketAddr,
    pub confdir: PathBuf,
}

impl SidecarLaunchConfig {
    #[must_use]
    pub fn new(
        ipc_addr: SocketAddr,
        ipc_token: impl Into<String>,
        target_hosts: Vec<String>,
        listen_addr: SocketAddr,
        confdir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            ipc_addr,
            ipc_token: ipc_token.into(),
            target_hosts,
            listen_addr,
            confdir: confdir.into(),
        }
    }

    fn validate(&self) -> Result<(), SidecarError> {
        if !self.ipc_addr.ip().is_loopback() || self.ipc_addr.port() == 0 {
            return Err(SidecarError::InvalidLaunchConfig(
                "capture IPC must use a non-zero loopback address".to_owned(),
            ));
        }
        if !self.listen_addr.ip().is_loopback() || self.listen_addr.port() == 0 {
            return Err(SidecarError::InvalidLaunchConfig(
                "proxy listener must use a non-zero loopback address".to_owned(),
            ));
        }
        if self.ipc_token.len() < 16 || self.ipc_token.chars().any(char::is_whitespace) {
            return Err(SidecarError::InvalidLaunchConfig(
                "capture IPC token is too short or contains whitespace".to_owned(),
            ));
        }
        if self.target_hosts.is_empty()
            || self
                .target_hosts
                .iter()
                .any(|host| host != &host.to_ascii_lowercase() || !is_valid_target_host(host))
        {
            return Err(SidecarError::InvalidLaunchConfig(
                "capture hosts must be lowercase DNS names or IP addresses".to_owned(),
            ));
        }
        if !self.confdir.is_absolute() {
            return Err(SidecarError::InvalidLaunchConfig(
                "sidecar configuration directory must be absolute".to_owned(),
            ));
        }
        Ok(())
    }
}

fn allow_host_pattern(host: &str) -> String {
    format!(r"^{}:\d+$", regex::escape(host))
}

fn is_valid_target_host(host: &str) -> bool {
    if host.is_empty()
        || host.len() > 253
        || host.contains(',')
        || host.chars().any(char::is_whitespace)
        || host.ends_with('.')
    {
        return false;
    }
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    })
}

impl fmt::Debug for SidecarLaunchConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SidecarLaunchConfig")
            .field("ipc_addr", &self.ipc_addr)
            .field("ipc_token", &"[REDACTED]")
            .field("target_hosts", &self.target_hosts)
            .field("listen_addr", &self.listen_addr)
            .field("confdir", &self.confdir)
            .finish()
    }
}

#[derive(Debug, Deserialize)]
struct SidecarManifest {
    schema_version: String,
    name: String,
    version: String,
    target_triple: String,
    mitmproxy_version: String,
    artifact: Artifact,
    capture_contract: CaptureContract,
    sbom: HashedFile,
    signature: Signature,
    integration_probe: IntegrationProbe,
    bundle_ready: bool,
    release_ready: bool,
}

#[derive(Debug, Deserialize)]
struct Artifact {
    file: String,
    bytes: u64,
    sha256: String,
    max_bytes: u64,
}

#[derive(Debug, Deserialize)]
struct CaptureContract {
    ipc_protocol: String,
    envelope: String,
    policy: String,
    policy_file: String,
    policy_sha256: String,
    allowed_environment: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct HashedFile {
    file: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct Signature {
    status: String,
}

#[derive(Debug, Deserialize)]
struct IntegrationProbe {
    started: bool,
    forwarding_preserved: bool,
    credential_canaries_in_envelope: u64,
    prompt_preserved: bool,
    response_preserved: bool,
    compressed_response_preserved: bool,
    stream_credentials_removed: bool,
    non_target_tunnel: bool,
    http2_preserved: bool,
}

fn validate_manifest(
    manifest: &SidecarManifest,
    requirements: BundleRequirements,
) -> Result<(), SidecarError> {
    if manifest.schema_version != SIDECAR_MANIFEST_VERSION
        || manifest.name != SIDECAR_NAME
        || manifest.version != env!("CARGO_PKG_VERSION")
        || manifest.mitmproxy_version != MITMPROXY_VERSION
    {
        return Err(SidecarError::InvalidManifest(
            "component versions do not match the desktop runtime".to_owned(),
        ));
    }
    let expected_target = current_target_triple()?.to_owned();
    if manifest.target_triple != expected_target {
        return Err(SidecarError::TargetMismatch {
            expected: expected_target,
            actual: manifest.target_triple.clone(),
        });
    }
    let expected_artifact = executable_name(&manifest.target_triple);
    if manifest.artifact.file != expected_artifact {
        return Err(SidecarError::InvalidManifest(
            "artifact name does not match the target triple".to_owned(),
        ));
    }
    let contract = &manifest.capture_contract;
    if contract.ipc_protocol != CAPTURE_CONTRACT_VERSION
        || contract.envelope != CAPTURE_CONTRACT_VERSION
        || contract.policy != CAPTURE_CONTRACT_VERSION
    {
        return Err(SidecarError::InvalidManifest(
            "capture contract versions are unsupported".to_owned(),
        ));
    }
    let actual_environment = contract
        .allowed_environment
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if actual_environment != CAPTURE_ENVIRONMENT.into_iter().collect() {
        return Err(SidecarError::InvalidManifest(
            "capture environment contract is broader than expected".to_owned(),
        ));
    }
    let probe = &manifest.integration_probe;
    if !manifest.bundle_ready
        || !probe.started
        || !probe.forwarding_preserved
        || !probe.prompt_preserved
        || !probe.response_preserved
        || !probe.compressed_response_preserved
        || !probe.stream_credentials_removed
        || !probe.non_target_tunnel
        || !probe.http2_preserved
        || probe.credential_canaries_in_envelope != 0
    {
        return Err(SidecarError::InvalidManifest(
            "integration probe did not prove a safe bundle".to_owned(),
        ));
    }
    if requirements.require_platform_signature
        && (manifest.signature.status != "valid" || !manifest.release_ready)
    {
        return Err(SidecarError::SignatureRequired);
    }
    Ok(())
}

fn validate_size_and_hash(path: &Path, artifact: &Artifact) -> Result<(), SidecarError> {
    let size = fs::metadata(path)?.len();
    if size != artifact.bytes || size > artifact.max_bytes {
        return Err(SidecarError::SizeMismatch(artifact.file.clone()));
    }
    validate_hash(path, &artifact.sha256, &artifact.file)
}

fn validate_hash(path: &Path, expected: &str, name: &str) -> Result<(), SidecarError> {
    if expected.len() != 64
        || !expected
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SidecarError::InvalidManifest(format!(
            "{name} SHA-256 is malformed"
        )));
    }
    let mut source = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let actual = format!("{:x}", digest.finalize());
    if actual != expected {
        return Err(SidecarError::HashMismatch(name.to_owned()));
    }
    Ok(())
}

fn validate_sbom(path: &Path) -> Result<(), SidecarError> {
    let sbom: serde_json::Value = serde_json::from_reader(File::open(path)?)?;
    if sbom.get("bomFormat").and_then(|value| value.as_str()) != Some("CycloneDX")
        || sbom
            .get("components")
            .and_then(|value| value.as_array())
            .is_none_or(Vec::is_empty)
    {
        return Err(SidecarError::InvalidManifest(
            "CycloneDX SBOM is incomplete".to_owned(),
        ));
    }
    Ok(())
}

fn checked_bundle_file(root: &Path, name: &str) -> Result<PathBuf, SidecarError> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(SidecarError::InvalidBundlePath(name.to_owned()));
    }
    let path = root.join(name);
    let metadata = fs::symlink_metadata(&path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => SidecarError::MissingBundleFile(name.to_owned()),
        _ => SidecarError::Io(error),
    })?;
    if metadata.file_type().is_symlink() {
        return Err(SidecarError::BundleFileIsSymlink(name.to_owned()));
    }
    if !metadata.is_file() {
        return Err(SidecarError::MissingBundleFile(name.to_owned()));
    }
    Ok(path)
}

#[must_use]
pub fn executable_name(target_triple: &str) -> String {
    let extension = if target_triple.ends_with("windows-msvc") {
        ".exe"
    } else {
        ""
    };
    format!("{SIDECAR_NAME}-{target_triple}{extension}")
}

pub fn current_target_triple() -> Result<&'static str, SidecarError> {
    if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        Ok("x86_64-pc-windows-msvc")
    } else if cfg!(all(target_os = "windows", target_arch = "aarch64")) {
        Ok("aarch64-pc-windows-msvc")
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        Ok("x86_64-apple-darwin")
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Ok("aarch64-apple-darwin")
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Ok("x86_64-unknown-linux-gnu")
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        Ok("aarch64-unknown-linux-gnu")
    } else {
        Err(SidecarError::UnsupportedPlatform)
    }
}

fn inherited_environment_keys() -> &'static [&'static str] {
    if cfg!(target_os = "windows") {
        &["SystemRoot", "WINDIR", "TEMP", "TMP"]
    } else {
        &["TMPDIR"]
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::fs;
    use std::net::TcpListener;
    use std::process::Command;

    use serde_json::json;
    use tempfile::tempdir;

    use super::*;

    const TEST_CA_CERTIFICATE: &str = r#"-----BEGIN CERTIFICATE-----
MIIBQjCB6aADAgECAgQHW80VMAoGCCqGSM49BAMCMB4xHDAaBgNVBAMME0NvZGVJ
c0NoZWFwIFRlc3QgQ0EwIBcNMjAwMTAxMDAwMDAwWhgPMjA5OTAxMDEwMDAwMDBa
MB4xHDAaBgNVBAMME0NvZGVJc0NoZWFwIFRlc3QgQ0EwWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAARpQZZ+uLCf4LSJkRYYbrRFyDZjxMEz6ICzavun2i9vIRApTRW3
hYy+LoZKGeZqtqs6ElkjHfXoyv9NxVt/zmaaoxMwETAPBgNVHRMBAf8EBTADAQH/
MAoGCCqGSM49BAMCA0gAMEUCIQC1PB8+NumezrQf5unFGhVeufUcyw/sjH6p1aqs
1oexSwIgPbdZbKBtb4YrSWCzD7WcGRJXvm7PBVLX+T7LZVzL7Q0=
-----END CERTIFICATE-----
"#;

    #[test]
    fn certificate_authority_status_distinguishes_missing_ready_and_invalid_assets() {
        let directory = tempdir().expect("CA directory");
        let root = directory.path();
        assert_eq!(
            inspect_certificate_authority(root),
            CertificateAuthorityStatus::missing()
        );

        fs::write(root.join(CA_PRIVATE_PEM_FILENAME), b"private-pem").unwrap();
        let incomplete = inspect_certificate_authority(root);
        assert_eq!(incomplete.state, CertificateAuthorityState::Invalid);
        assert_eq!(incomplete.private_material, PrivateMaterialState::Missing);

        fs::write(root.join(CA_PRIVATE_P12_FILENAME), b"private-p12").unwrap();
        fs::write(root.join(CA_CERTIFICATE_FILENAME), TEST_CA_CERTIFICATE).unwrap();
        restrict_test_private_material(root);
        let ready = inspect_certificate_authority(root);
        assert_eq!(ready.state, CertificateAuthorityState::Ready);
        assert_eq!(ready.subject.as_deref(), Some("CodeIsCheap Test CA"));
        assert_eq!(ready.valid_from_unix_ms, Some(1_577_836_800_000));
        assert_eq!(ready.valid_until_unix_ms, Some(4_070_908_800_000));
        assert_eq!(
            ready.fingerprint_sha256.as_deref(),
            Some(
                "4F:4C:45:B1:BF:86:99:E3:1C:5F:B7:23:3F:29:9E:47:80:1E:72:93:AB:11:99:6C:83:A7:15:00:55:2C:22:AA"
            )
        );
        #[cfg(any(unix, windows))]
        assert_eq!(ready.private_material, PrivateMaterialState::Restricted);
        #[cfg(not(any(unix, windows)))]
        assert_eq!(ready.private_material, PrivateMaterialState::Unchecked);
        assert_platform_trust_status(&ready);

        fs::write(root.join(CA_CERTIFICATE_FILENAME), b"not a certificate").unwrap();
        let invalid = inspect_certificate_authority(root);
        assert_eq!(invalid.state, CertificateAuthorityState::Invalid);
        assert!(invalid.detail.as_deref().unwrap().contains("invalid PEM"));
    }

    #[test]
    fn certificate_metadata_survives_missing_private_material_for_uninstall() {
        let directory = tempdir().expect("CA directory");
        fs::write(
            directory.path().join(CA_CERTIFICATE_FILENAME),
            TEST_CA_CERTIFICATE,
        )
        .unwrap();

        let status = inspect_certificate_authority(directory.path());
        assert_eq!(status.state, CertificateAuthorityState::Invalid);
        assert_eq!(status.private_material, PrivateMaterialState::Missing);
        assert!(status.fingerprint_sha256.is_some());
        assert_eq!(status.subject.as_deref(), Some("CodeIsCheap Test CA"));
        assert_platform_trust_status(&status);
    }

    #[test]
    fn certificate_trust_lifecycle_rejects_invalid_anchor_material() {
        let directory = tempdir().expect("CA directory");
        fs::write(
            directory.path().join(CA_CERTIFICATE_FILENAME),
            TEST_CA_CERTIFICATE,
        )
        .unwrap();
        let certificate_der = load_certificate_der(directory.path()).expect("certificate DER");
        validate_trust_anchor(&certificate_der).expect("valid self-signed CA");

        fs::write(
            directory.path().join(CA_CERTIFICATE_FILENAME),
            b"not a certificate",
        )
        .unwrap();
        assert!(matches!(
            load_certificate_der(directory.path()),
            Err(CertificateAuthorityError::InvalidCertificate(_))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_certificate_store_lifecycle_is_exact_and_idempotent() {
        use windows_sys::Win32::Security::Cryptography::CERT_STORE_PROV_MEMORY;

        let (_, pem) = parse_x509_pem(TEST_CA_CERTIFICATE.as_bytes()).expect("test CA PEM");
        let store = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_MEMORY,
                0,
                0,
                0,
                std::ptr::null::<std::ffi::c_void>(),
            )
        };
        assert!(!store.is_null(), "memory certificate store must open");
        let store = WindowsCertificateStore(store);

        assert!(windows_add_certificate_to_store(store.0, &pem.contents).expect("add CA"));
        assert!(windows_certificate_store_contains(store.0, &pem.contents).expect("find CA"));
        assert!(!windows_add_certificate_to_store(store.0, &pem.contents).expect("idempotent add"));
        assert!(windows_delete_certificate_from_store(store.0, &pem.contents).expect("remove CA"));
        assert!(!windows_certificate_store_contains(store.0, &pem.contents).expect("CA removed"));
        assert!(
            !windows_delete_certificate_from_store(store.0, &pem.contents)
                .expect("idempotent remove")
        );
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires an interactive Windows session and mutates CurrentUser ROOT"]
    fn real_windows_ca_trust_round_trip() {
        struct TrustCleanup(PathBuf);

        impl Drop for TrustCleanup {
            fn drop(&mut self) {
                let _ = uninstall_certificate_authority(&self.0);
            }
        }

        let directory = tempdir().expect("CA directory");
        fs::write(
            directory.path().join(CA_CERTIFICATE_FILENAME),
            TEST_CA_CERTIFICATE,
        )
        .unwrap();
        let _cleanup = TrustCleanup(directory.path().to_path_buf());
        eprintln!("cleaning any pre-existing test CA trust");
        let _ = uninstall_certificate_authority(directory.path()).expect("initial cleanup");
        eprintln!("checking initial trust state");
        let status = inspect_certificate_authority(directory.path());
        assert_eq!(status.trust, CertificateTrustState::NotTrusted);
        assert!(status.can_manage_trust);

        eprintln!("installing test CA trust");
        assert!(install_certificate_authority(directory.path()).expect("install CA"));
        eprintln!("checking idempotent test CA installation");
        assert!(!install_certificate_authority(directory.path()).expect("idempotent install"));
        eprintln!("checking installed trust state");
        let status = inspect_certificate_authority(directory.path());
        assert_eq!(status.trust, CertificateTrustState::Trusted);
        assert!(status.can_manage_trust);

        eprintln!("removing test CA trust");
        assert!(uninstall_certificate_authority(directory.path()).expect("remove CA"));
        eprintln!("checking idempotent test CA removal");
        assert!(!uninstall_certificate_authority(directory.path()).expect("idempotent removal"));
        eprintln!("checking final trust state");
        let status = inspect_certificate_authority(directory.path());
        assert_eq!(status.trust, CertificateTrustState::NotTrusted);
        assert!(status.can_manage_trust);
    }

    #[cfg(unix)]
    #[test]
    fn certificate_authority_rejects_private_material_visible_to_other_users() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempdir().expect("CA directory");
        let root = directory.path();
        fs::write(root.join(CA_CERTIFICATE_FILENAME), TEST_CA_CERTIFICATE).unwrap();
        for name in [CA_PRIVATE_PEM_FILENAME, CA_PRIVATE_P12_FILENAME] {
            let path = root.join(name);
            fs::write(&path, b"private").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
        }

        let status = inspect_certificate_authority(root);
        assert_eq!(status.state, CertificateAuthorityState::Invalid);
        assert_eq!(status.private_material, PrivateMaterialState::Insecure);
    }

    #[cfg(windows)]
    #[test]
    fn certificate_authority_rejects_windows_private_material_visible_to_everyone() {
        let directory = tempdir().expect("CA directory");
        let root = directory.path();
        fs::write(root.join(CA_CERTIFICATE_FILENAME), TEST_CA_CERTIFICATE).unwrap();
        for name in [CA_PRIVATE_PEM_FILENAME, CA_PRIVATE_P12_FILENAME] {
            let path = root.join(name);
            fs::write(&path, b"private").unwrap();
            set_windows_test_acl(&path, true);
        }

        let status = inspect_certificate_authority(root);
        assert_eq!(status.state, CertificateAuthorityState::Invalid);
        assert_eq!(status.private_material, PrivateMaterialState::Insecure);
    }

    fn restrict_test_private_material(root: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            for name in [CA_PRIVATE_PEM_FILENAME, CA_PRIVATE_P12_FILENAME] {
                fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        #[cfg(windows)]
        for name in [CA_PRIVATE_PEM_FILENAME, CA_PRIVATE_P12_FILENAME] {
            set_windows_test_acl(&root.join(name), false);
        }
        #[cfg(not(any(unix, windows)))]
        let _ = root;
    }

    fn assert_platform_trust_status(status: &CertificateAuthorityStatus) {
        #[cfg(windows)]
        {
            assert_eq!(status.trust, CertificateTrustState::NotTrusted);
            assert!(status.can_manage_trust);
        }
        #[cfg(target_os = "macos")]
        {
            assert_eq!(status.trust, CertificateTrustState::NotTrusted);
            assert!(!status.can_manage_trust);
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            assert_eq!(status.trust, CertificateTrustState::Unsupported);
            assert!(!status.can_manage_trust);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_trust_results_preserve_explicit_trust_and_denial() {
        assert_eq!(
            macos_trust_result_state(None),
            CertificateTrustState::Trusted
        );
        for trusted in [
            TrustSettingsForCertificate::TrustRoot,
            TrustSettingsForCertificate::TrustAsRoot,
        ] {
            assert_eq!(
                macos_trust_result_state(Some(trusted)),
                CertificateTrustState::Trusted
            );
        }
        for untrusted in [
            TrustSettingsForCertificate::Deny,
            TrustSettingsForCertificate::Unspecified,
            TrustSettingsForCertificate::Invalid,
        ] {
            assert_eq!(
                macos_trust_result_state(Some(untrusted)),
                CertificateTrustState::NotTrusted
            );
        }
    }

    #[cfg(windows)]
    fn set_windows_test_acl(path: &Path, include_world: bool) {
        use std::os::windows::ffi::OsStrExt as _;

        use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetNamedSecurityInfoW};
        use windows_sys::Win32::Security::{
            ACL, ACL_REVISION, AddAccessAllowedAce, DACL_SECURITY_INFORMATION, InitializeAcl,
            PROTECTED_DACL_SECURITY_INFORMATION, WinBuiltinAdministratorsSid, WinLocalSystemSid,
            WinWorldSid,
        };
        use windows_sys::Win32::Storage::FileSystem::{FILE_ALL_ACCESS, FILE_GENERIC_READ};

        let mut sids = vec![
            current_user_sid().expect("current user SID"),
            OwnedSid::well_known(WinLocalSystemSid).expect("SYSTEM SID"),
            OwnedSid::well_known(WinBuiltinAdministratorsSid).expect("Administrators SID"),
        ];
        if include_world {
            sids.push(OwnedSid::well_known(WinWorldSid).expect("Everyone SID"));
        }
        let acl_size = size_of::<ACL>()
            + sids
                .iter()
                .map(|sid| size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>() + sid.length)
                .sum::<usize>();
        let mut acl_storage = vec![0usize; acl_size.div_ceil(size_of::<usize>())];
        let acl = acl_storage.as_mut_ptr().cast::<ACL>();
        assert_ne!(
            unsafe { InitializeAcl(acl, acl_size as u32, ACL_REVISION) },
            0,
            "initialize test ACL: {}",
            io::Error::last_os_error()
        );
        for (index, sid) in sids.iter().enumerate() {
            let access = if include_world && index == sids.len() - 1 {
                FILE_GENERIC_READ
            } else {
                FILE_ALL_ACCESS
            };
            assert_ne!(
                unsafe { AddAccessAllowedAce(acl, ACL_REVISION, access, sid.as_psid()) },
                0,
                "add test ACL entry: {}",
                io::Error::last_os_error()
            );
        }
        let mut wide_path = path.as_os_str().encode_wide().collect::<Vec<_>>();
        wide_path.push(0);
        let result = unsafe {
            SetNamedSecurityInfoW(
                wide_path.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(
            result,
            ERROR_SUCCESS,
            "set test ACL: {}",
            io::Error::from_raw_os_error(result as i32)
        );
    }

    fn sha256(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn bundle(signature: &str) -> (tempfile::TempDir, PathBuf) {
        let directory = tempdir().expect("bundle directory");
        let root = directory.path().to_path_buf();
        let target = current_target_triple().expect("test platform");
        let artifact_name = executable_name(target);
        let artifact = b"synthetic-sidecar";
        let policy = br#"{"version":"0.1"}"#;
        let sbom = br#"{"bomFormat":"CycloneDX","components":[{"name":"mitmproxy"}]}"#;
        fs::write(root.join(&artifact_name), artifact).expect("artifact");
        fs::write(root.join("capture-policy.v0.1.json"), policy).expect("policy");
        fs::write(root.join("sidecar-sbom.cdx.json"), sbom).expect("sbom");
        let manifest = json!({
            "schema_version": "0.1",
            "name": SIDECAR_NAME,
            "version": env!("CARGO_PKG_VERSION"),
            "target_triple": target,
            "mitmproxy_version": MITMPROXY_VERSION,
            "artifact": {
                "file": artifact_name,
                "bytes": artifact.len(),
                "sha256": sha256(artifact),
                "max_bytes": 1024
            },
            "capture_contract": {
                "ipc_protocol": "0.1",
                "envelope": "0.1",
                "policy": "0.1",
                "policy_file": "capture-policy.v0.1.json",
                "policy_sha256": sha256(policy),
                "allowed_environment": CAPTURE_ENVIRONMENT
            },
            "sbom": {"file": "sidecar-sbom.cdx.json", "sha256": sha256(sbom)},
            "signature": {"status": signature},
            "integration_probe": {
                "started": true,
                "forwarding_preserved": true,
                "credential_canaries_in_envelope": 0,
                "prompt_preserved": true,
                "response_preserved": true,
                "compressed_response_preserved": true,
                "stream_credentials_removed": true,
                "non_target_tunnel": true,
                "http2_preserved": true
            },
            "bundle_ready": true,
            "release_ready": signature == "valid"
        });
        fs::write(
            root.join(MANIFEST_FILENAME),
            serde_json::to_vec(&manifest).expect("manifest"),
        )
        .expect("manifest file");
        (directory, root)
    }

    #[test]
    fn development_bundle_verifies_every_file_and_contract() {
        let (_directory, root) = bundle("unsigned");
        let loaded = SidecarBundle::load(&root, BundleRequirements::development())
            .expect("development bundle must load");
        assert_eq!(loaded.target_triple(), current_target_triple().unwrap());
        assert_eq!(loaded.root(), root);
        assert!(loaded.policy().ends_with("capture-policy.v0.1.json"));
        assert!(loaded.sbom().ends_with("sidecar-sbom.cdx.json"));
    }

    #[test]
    fn release_bundle_requires_signature_and_rejects_tampering() {
        let (_directory, root) = bundle("unsigned");
        assert!(matches!(
            SidecarBundle::load(&root, BundleRequirements::release()),
            Err(SidecarError::SignatureRequired)
        ));

        fs::write(
            root.join(executable_name(current_target_triple().unwrap())),
            b"tampered",
        )
        .expect("tamper artifact");
        assert!(matches!(
            SidecarBundle::load(&root, BundleRequirements::development()),
            Err(SidecarError::SizeMismatch(_)) | Err(SidecarError::HashMismatch(_))
        ));
    }

    #[test]
    fn command_contains_only_explicit_capture_and_platform_environment() {
        let (_directory, root) = bundle("unsigned");
        let loaded = SidecarBundle::load(&root, BundleRequirements::development()).unwrap();
        let confdir = root.join("conf");
        let config = SidecarLaunchConfig::new(
            "127.0.0.1:41001".parse().unwrap(),
            "synthetic-token-123456",
            vec!["api.openai.com".to_owned(), "api.anthropic.com".to_owned()],
            "127.0.0.1:41002".parse().unwrap(),
            &confdir,
        );

        let command = loaded.command(&config).expect("command must build");
        assert_eq!(command.get_program(), loaded.executable());
        assert_eq!(command.get_current_dir(), Some(confdir.as_path()));
        let environment = command
            .get_envs()
            .filter_map(|(name, value)| value.map(|value| (name, value)))
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect::<BTreeMap<OsString, OsString>>();
        assert_eq!(
            environment.get(OsStr::new("CIC_CAPTURE_IPC_TOKEN")),
            Some(&OsString::from("synthetic-token-123456"))
        );
        assert_eq!(
            environment.get(OsStr::new("CIC_CAPTURE_HOSTS")),
            Some(&OsString::from("api.openai.com,api.anthropic.com"))
        );
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--allow-hosts", r"^api\.openai\.com:\d+$"])
        );
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--allow-hosts", r"^api\.anthropic\.com:\d+$"])
        );
        let allowed = inherited_environment_keys()
            .iter()
            .copied()
            .chain(CAPTURE_ENVIRONMENT)
            .map(OsStr::new)
            .collect::<BTreeSet<_>>();
        assert!(
            environment
                .keys()
                .all(|key| allowed.contains(key.as_os_str()))
        );
        assert!(!format!("{config:?}").contains("synthetic-token-123456"));
    }

    #[test]
    fn launch_configuration_rejects_non_loopback_and_relative_state() {
        let (_directory, root) = bundle("unsigned");
        let loaded = SidecarBundle::load(&root, BundleRequirements::development()).unwrap();
        let invalid = SidecarLaunchConfig::new(
            "0.0.0.0:41001".parse().unwrap(),
            "synthetic-token-123456",
            vec!["api.openai.com".to_owned()],
            "127.0.0.1:41002".parse().unwrap(),
            "relative-conf",
        );
        assert!(matches!(
            loaded.command(&invalid),
            Err(SidecarError::InvalidLaunchConfig(_))
        ));

        for host in ["-api.openai.com", "api.openai.com|.*", "api..openai.com"] {
            let invalid_host = SidecarLaunchConfig::new(
                "127.0.0.1:41001".parse().unwrap(),
                "synthetic-token-123456",
                vec![host.to_owned()],
                "127.0.0.1:41002".parse().unwrap(),
                &root,
            );
            assert!(matches!(
                loaded.command(&invalid_host),
                Err(SidecarError::InvalidLaunchConfig(_))
            ));
        }
    }

    #[test]
    fn allow_host_patterns_are_anchored_and_escape_regex_metacharacters() {
        assert_eq!(
            allow_host_pattern("api.openai.com"),
            r"^api\.openai\.com:\d+$"
        );
        assert_eq!(allow_host_pattern("127.0.0.1"), r"^127\.0\.0\.1:\d+$");
    }

    #[test]
    fn launch_starts_a_verified_process_without_inheriting_unapproved_environment() {
        let (_directory, root) = bundle("unsigned");
        let source = root.join("fixture.rs");
        fs::write(
            &source,
            r#"
use std::env;
use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

fn main() {
    let args = env::args().collect::<Vec<_>>();
    if args.get(1).map(String::as_str) == Some("--descendant") {
        let port = args[2].parse::<u16>().unwrap();
        let confdir = PathBuf::from(&args[3]);
        let _listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
        fs::write(confdir.join("descendant-ready.txt"), port.to_string()).unwrap();
        thread::sleep(Duration::from_secs(30));
        return;
    }
    let host = args.windows(2).find(|pair| pair[0] == "--listen-host").unwrap()[1].clone();
    let port = args.windows(2).find(|pair| pair[0] == "--listen-port").unwrap()[1].clone();
    let confdir = args.iter().find_map(|arg| arg.strip_prefix("confdir=")).unwrap();
    let descendant_port = env::var("CIC_CAPTURE_IPC_TOKEN").unwrap().rsplit('-').next().unwrap().parse::<u16>().unwrap();
    let mut environment = env::vars().collect::<Vec<_>>();
    environment.sort();
    fs::write(
        PathBuf::from(confdir).join("observed-environment.txt"),
        environment.into_iter().map(|(key, value)| format!("{key}={value}\n")).collect::<String>(),
    ).unwrap();
    Command::new(env::current_exe().unwrap())
        .arg("--descendant")
        .arg(descendant_port.to_string())
        .arg(confdir)
        .spawn()
        .unwrap();
    let listener = TcpListener::bind(format!("{host}:{port}")).unwrap();
    let _ = listener.accept();
    thread::sleep(Duration::from_secs(30));
}
"#,
        )
        .expect("fixture source");
        let executable = root.join(executable_name(current_target_triple().unwrap()));
        assert!(
            Command::new("rustc")
                .arg(&source)
                .arg("-o")
                .arg(&executable)
                .status()
                .expect("rustc must run")
                .success()
        );
        let artifact = fs::read(&executable).expect("compiled fixture");
        let manifest_path = root.join(MANIFEST_FILENAME);
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest["artifact"]["bytes"] = artifact.len().into();
        manifest["artifact"]["sha256"] = sha256(&artifact).into();
        manifest["artifact"]["max_bytes"] = (artifact.len() + 1).into();
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

        let bundle = SidecarBundle::load(&root, BundleRequirements::development()).unwrap();
        let ipc_port = free_port();
        let listen_port = free_port();
        let descendant_port = free_port();
        let confdir = root.join("runtime-conf");
        let token = format!("runtime-token-123456-{descendant_port}");
        let config = SidecarLaunchConfig::new(
            format!("127.0.0.1:{ipc_port}").parse().unwrap(),
            &token,
            vec!["api.openai.com".to_owned()],
            format!("127.0.0.1:{listen_port}").parse().unwrap(),
            &confdir,
        );

        let mut process = bundle
            .launch(&config, Duration::from_secs(5))
            .expect("verified fixture must start");
        assert_eq!(process.endpoint(), config.listen_addr);
        let environment = fs::read_to_string(confdir.join("observed-environment.txt")).unwrap();
        assert!(environment.contains(&format!("CIC_CAPTURE_IPC_TOKEN={token}")));
        assert!(environment.contains("CIC_CAPTURE_HOSTS=api.openai.com"));
        assert!(!environment.lines().any(|line| line.starts_with("PATH=")));
        wait_for_file(&confdir.join("descendant-ready.txt"));
        process.stop().expect("fixture must stop");
        wait_for_port_release(descendant_port);
    }

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .expect("ephemeral port")
            .local_addr()
            .expect("local address")
            .port()
    }

    fn wait_for_file(path: &Path) {
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(5) {
            if path.is_file() {
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
        panic!("fixture did not create {}", path.display());
    }

    fn wait_for_port_release(port: u16) {
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(5) {
            if TcpListener::bind(("127.0.0.1", port)).is_ok() {
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
        panic!("sidecar descendant still owns port {port}");
    }
}
