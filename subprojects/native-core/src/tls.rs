use std::{
    fmt,
    fs::{self, File},
    io::BufReader,
    path::Path,
    sync::{Arc, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use rustls::{
    client::danger::HandshakeSignatureValid,
    crypto::{ring, CryptoProvider},
    pki_types::{CertificateDer, PrivateKeyDer, UnixTime},
    server::{
        danger::{ClientCertVerified, ClientCertVerifier},
        ClientHello, ResolvesServerCert, WebPkiClientVerifier,
    },
    sign::CertifiedKey,
    version, CertificateError, DigitallySignedStruct, DistinguishedName, Error as RustlsError,
    RootCertStore, ServerConfig, SignatureScheme,
};
use tokio_rustls::TlsAcceptor;
use x509_parser::{
    certificate::X509Certificate, parse_x509_certificate, parse_x509_crl, prelude::GeneralName,
    revocation_list::CertificateRevocationList,
};

use crate::{
    config::{sni_matches, MtlsMode, TlsConfig, TlsMinVersion},
    error::{CoreError, Result},
};

const MAX_CERTIFICATE_FILE_BYTES: u64 = 1024 * 1024;
const MAX_PRIVATE_KEY_FILE_BYTES: u64 = 64 * 1024;
const MAX_CRL_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CERTIFICATE_CHAIN_LENGTH: usize = 16;
const MAX_CRLS_PER_FILE: usize = 16;
const EXPIRY_WARNING_SECONDS: i64 = 30 * 24 * 60 * 60;
const CRL_CLOCK_SKEW_SECONDS: i64 = 300;

#[derive(Debug)]
struct CrlSet {
    entries: Vec<CrlEntry>,
}

#[derive(Debug)]
struct CrlEntry {
    issuer_der: Vec<u8>,
    revoked_serials: Vec<Vec<u8>>,
    this_update: i64,
    next_update: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RevocationStatus {
    Good,
    Revoked,
    NotCovered,
    Stale,
}

impl fmt::Display for RevocationStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Good => formatter.write_str("certificate is not revoked"),
            Self::Revoked => formatter.write_str("certificate serial is revoked"),
            Self::NotCovered => formatter.write_str("no CRL covers the certificate issuer"),
            Self::Stale => formatter.write_str("the applicable CRL is outside its validity window"),
        }
    }
}

impl CrlSet {
    fn load(path: &Path, trusted_certificates: &[CertificateDer<'static>]) -> Result<Self> {
        ensure_file_size(path, MAX_CRL_FILE_BYTES, "CRL")?;
        let bytes = fs::read(path).map_err(|error| {
            CoreError::Config(format!("cannot read CRL {}: {error}", path.display()))
        })?;
        let der_values = decode_crl_file(&bytes)?;
        if der_values.is_empty() {
            return Err(CoreError::Config("CRL file contains no CRLs".to_string()));
        }
        if der_values.len() > MAX_CRLS_PER_FILE {
            return Err(CoreError::Config(format!(
                "CRL file contains more than {MAX_CRLS_PER_FILE} CRLs"
            )));
        }
        let now = now_unix_seconds();
        let mut entries = Vec::with_capacity(der_values.len());
        for der in der_values {
            let (remaining, crl) = parse_x509_crl(&der).map_err(|error| {
                CoreError::Config(format!("invalid X.509 CRL in {}: {error}", path.display()))
            })?;
            if !remaining.is_empty() {
                return Err(CoreError::Config(
                    "CRL contains trailing DER data".to_string(),
                ));
            }
            validate_crl_time(&crl, now)?;
            if crl.next_update().is_none() {
                return Err(CoreError::Config("CRL must contain nextUpdate".to_string()));
            }
            verify_crl_signature(&crl, trusted_certificates, now)?;
            let mut revoked_serials = Vec::new();
            for revoked in crl.iter_revoked_certificates() {
                let serial = normalize_serial(revoked.raw_serial());
                if serial.is_empty() {
                    return Err(CoreError::Config(
                        "CRL contains an empty revoked serial number".to_string(),
                    ));
                }
                revoked_serials.push(serial);
            }
            entries.push(CrlEntry {
                issuer_der: crl.issuer().as_raw().to_vec(),
                revoked_serials,
                this_update: crl.last_update().timestamp(),
                next_update: crl.next_update().expect("checked above").timestamp(),
            });
        }
        Ok(Self { entries })
    }

    fn check(&self, leaf: &X509Certificate<'_>, now: i64) -> RevocationStatus {
        let issuer = leaf.issuer().as_raw();
        let mut covered = false;
        let serial = normalize_serial(leaf.raw_serial());
        for entry in &self.entries {
            if entry.issuer_der.as_slice() != issuer {
                continue;
            }
            covered = true;
            if now < entry.this_update.saturating_sub(CRL_CLOCK_SKEW_SECONDS)
                || now > entry.next_update.saturating_add(CRL_CLOCK_SKEW_SECONDS)
            {
                return RevocationStatus::Stale;
            }
            if entry.revoked_serials.iter().any(|value| value == &serial) {
                return RevocationStatus::Revoked;
            }
        }
        if covered {
            RevocationStatus::Good
        } else {
            RevocationStatus::NotCovered
        }
    }
}

#[derive(Debug)]
struct RevocationClientVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    crls: Arc<CrlSet>,
}

impl ClientCertVerifier for RevocationClientVerifier {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, RustlsError> {
        let verified = self
            .inner
            .verify_client_cert(end_entity, intermediates, now)?;
        let (remaining, leaf) = parse_x509_certificate(end_entity.as_ref())
            .map_err(|_| RustlsError::InvalidCertificate(CertificateError::BadEncoding))?;
        if !remaining.is_empty() {
            return Err(RustlsError::InvalidCertificate(
                CertificateError::BadEncoding,
            ));
        }
        match self.crls.check(&leaf, now.as_secs() as i64) {
            RevocationStatus::Good => Ok(verified),
            RevocationStatus::Revoked => {
                Err(RustlsError::InvalidCertificate(CertificateError::Revoked))
            }
            RevocationStatus::NotCovered => Err(RustlsError::InvalidCertificate(
                CertificateError::UnknownIssuer,
            )),
            RevocationStatus::Stale => {
                Err(RustlsError::InvalidCertificate(CertificateError::Expired))
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[derive(Clone)]
pub struct TlsBundle {
    pub acceptor: TlsAcceptor,
    pub quic_crypto: Option<Arc<rustls::ServerConfig>>,
}

#[derive(Debug, Clone, Default)]
pub struct TlsConnectionInfo {
    pub server_name: Option<String>,
    pub version: Option<String>,
    pub alpn: Option<String>,
}

static PROVIDER_INSTALLED: OnceLock<()> = OnceLock::new();

pub fn install_provider() -> Result<()> {
    if PROVIDER_INSTALLED.get().is_some() {
        return Ok(());
    }
    let _ = ring::default_provider().install_default();
    let _ = PROVIDER_INSTALLED.set(());
    Ok(())
}

pub fn build_tls_bundle(config: &TlsConfig, quic_enabled: bool) -> Result<TlsBundle> {
    let provider = Arc::new(ring::default_provider());
    let certs = load_certificates(&config.cert_file)?;
    let key = load_private_key(config)?;
    if config.validate_certificate {
        validate_server_certificate(&certs, config)?;
        validate_server_revocation(&certs, config)?;
    }
    let certified = CertifiedKey::from_der(certs, key, &provider)
        .map_err(|error| CoreError::Config(format!("certificate/key mismatch: {error}")))?;
    let resolver = Arc::new(StrictSniResolver {
        certified: Arc::new(certified),
        allowed_sni: config.allowed_sni.clone(),
        allow_missing_sni: config.allow_missing_sni,
    });

    let tcp = build_server_config(config, resolver.clone(), provider.clone(), false)?;
    let quic = if quic_enabled {
        Some(Arc::new(build_server_config(
            config, resolver, provider, true,
        )?))
    } else {
        None
    };
    Ok(TlsBundle {
        acceptor: TlsAcceptor::from(Arc::new(tcp)),
        quic_crypto: quic,
    })
}

fn build_server_config(
    config: &TlsConfig,
    resolver: Arc<StrictSniResolver>,
    provider: Arc<CryptoProvider>,
    quic: bool,
) -> Result<ServerConfig> {
    let versions: &[&'static rustls::SupportedProtocolVersion] = if quic {
        &[&version::TLS13]
    } else {
        match config.min_version {
            TlsMinVersion::Tls12 => &[&version::TLS13, &version::TLS12],
            TlsMinVersion::Tls13 => &[&version::TLS13],
        }
    };
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions)
        .map_err(|error| CoreError::Config(format!("TLS version configuration failed: {error}")))?;
    let builder = match config.mtls {
        MtlsMode::Off => builder.with_no_client_auth(),
        MtlsMode::Optional | MtlsMode::Required => {
            let ca_path = config
                .client_ca_file
                .as_ref()
                .ok_or_else(|| CoreError::Config("mTLS requires client_ca_file".to_string()))?;
            let mut roots = RootCertStore::empty();
            let ca_certs = load_certificates(ca_path)?;
            let trusted_issuers = ca_certs.clone();
            let (added, ignored) = roots.add_parsable_certificates(ca_certs);
            if added == 0 || ignored > 0 {
                return Err(CoreError::Config(
                    "client CA contains unusable certificates".to_string(),
                ));
            }
            let verifier =
                WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone());
            let verifier = if config.mtls == MtlsMode::Optional {
                verifier.allow_unauthenticated()
            } else {
                verifier
            }
            .build()
            .map_err(|error| {
                CoreError::Config(format!("client certificate verifier failed: {error}"))
            })?;
            let verifier: Arc<dyn ClientCertVerifier> = verifier;
            let path = config
                .client_crl_file
                .as_ref()
                .ok_or_else(|| CoreError::Config("mTLS requires client_crl_file".to_string()))?;
            tracing::info!(path = %path.display(), "mTLS client certificate revocation is enforced by CRL");
            builder.with_client_cert_verifier(Arc::new(RevocationClientVerifier {
                inner: verifier,
                crls: Arc::new(CrlSet::load(path, &trusted_issuers)?),
            }))
        }
    };
    let mut server = builder.with_cert_resolver(resolver);
    server.alpn_protocols = if quic {
        vec![b"h3".to_vec()]
    } else {
        config
            .alpn
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect()
    };
    server.max_early_data_size = 0;
    Ok(server)
}

#[derive(Debug)]
struct StrictSniResolver {
    certified: Arc<CertifiedKey>,
    allowed_sni: Vec<String>,
    allow_missing_sni: bool,
}

impl ResolvesServerCert for StrictSniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let server_name = client_hello.server_name();
        let allowed = match server_name {
            Some(name) => self
                .allowed_sni
                .iter()
                .any(|pattern| sni_matches(pattern, name)),
            None => self.allow_missing_sni,
        };
        if allowed {
            Some(self.certified.clone())
        } else {
            None
        }
    }
}

fn load_certificates(path: &std::path::Path) -> Result<Vec<CertificateDer<'static>>> {
    ensure_file_size(path, MAX_CERTIFICATE_FILE_BYTES, "certificate")?;
    let file = File::open(path).map_err(|error| {
        CoreError::Config(format!(
            "cannot open certificate {}: {error}",
            path.display()
        ))
    })?;
    let mut reader = BufReader::new(file);
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| CoreError::Config(format!("invalid certificate PEM: {error}")))?;
    if certificates.is_empty() {
        return Err(CoreError::Config(
            "certificate PEM contains no certificates".to_string(),
        ));
    }
    if certificates.len() > MAX_CERTIFICATE_CHAIN_LENGTH {
        return Err(CoreError::Config(
            "certificate chain exceeds the configured trust limit".to_string(),
        ));
    }
    Ok(certificates)
}

fn load_private_key(config: &TlsConfig) -> Result<PrivateKeyDer<'static>> {
    let path = &config.key_file;
    ensure_file_size(path, MAX_PRIVATE_KEY_FILE_BYTES, "private key")?;
    if config.require_private_key_permissions {
        validate_private_key_permissions(path)?;
    }
    let file = File::open(path).map_err(|error| {
        CoreError::Config(format!(
            "cannot open private key {}: {error}",
            path.display()
        ))
    })?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|error| CoreError::Config(format!("invalid private key PEM: {error}")))?
        .ok_or_else(|| CoreError::Config("private key PEM contains no supported key".to_string()))
}

fn ensure_file_size(path: &std::path::Path, limit: u64, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        CoreError::Config(format!(
            "cannot inspect {label} {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(CoreError::Config(format!(
            "{label} {} must not be a symlink",
            path.display()
        )));
    }
    if !metadata.is_file() {
        return Err(CoreError::Config(format!(
            "{label} {} must be a regular file",
            path.display()
        )));
    }
    if metadata.len() == 0 || metadata.len() > limit {
        return Err(CoreError::Config(format!(
            "{label} file size must be between 1 and {limit} bytes"
        )));
    }
    Ok(())
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn normalize_serial(serial: &[u8]) -> Vec<u8> {
    match serial.iter().position(|byte| *byte != 0) {
        Some(index) => serial[index..].to_vec(),
        None => Vec::new(),
    }
}

fn validate_crl_time(crl: &CertificateRevocationList<'_>, now: i64) -> Result<()> {
    let this_update = crl.last_update().timestamp();
    let next_update = crl.next_update().map(|value| value.timestamp());
    if next_update.is_some_and(|value| value < this_update) {
        return Err(CoreError::Config(
            "CRL nextUpdate precedes thisUpdate".to_string(),
        ));
    }
    if this_update > now.saturating_add(CRL_CLOCK_SKEW_SECONDS) {
        return Err(CoreError::Config(
            "CRL thisUpdate is in the future".to_string(),
        ));
    }
    if next_update.is_some_and(|value| value < now.saturating_sub(CRL_CLOCK_SKEW_SECONDS)) {
        return Err(CoreError::Config("CRL has expired".to_string()));
    }
    Ok(())
}

fn verify_crl_signature(
    crl: &CertificateRevocationList<'_>,
    trusted_certificates: &[CertificateDer<'static>],
    now: i64,
) -> Result<()> {
    let mut issuer_matched = false;
    for certificate_der in trusted_certificates {
        let (remaining, certificate) = parse_x509_certificate(certificate_der.as_ref())
            .map_err(|error| CoreError::Config(format!("invalid trusted certificate: {error}")))?;
        if !remaining.is_empty() || certificate.subject().as_raw() != crl.issuer().as_raw() {
            continue;
        }
        issuer_matched = true;
        let validity = certificate.validity();
        if now < validity.not_before.timestamp() || now > validity.not_after.timestamp() {
            continue;
        }
        let is_ca = certificate
            .basic_constraints()
            .map_err(|error| CoreError::Config(format!("invalid CA basic constraints: {error}")))?
            .is_some_and(|extension| extension.value.ca);
        if !is_ca {
            continue;
        }
        if let Some(key_usage) = certificate
            .key_usage()
            .map_err(|error| CoreError::Config(format!("invalid CA key usage: {error}")))?
        {
            if !key_usage.value.crl_sign() {
                continue;
            }
        }
        crl.verify_signature(certificate.public_key())
            .map_err(|error| {
                CoreError::Config(format!("CRL signature verification failed: {error}"))
            })?;
        return Ok(());
    }
    if issuer_matched {
        Err(CoreError::Config(
            "CRL issuer matched a trusted certificate, but no usable CA key verified the signature"
                .to_string(),
        ))
    } else {
        Err(CoreError::Config(
            "CRL issuer does not match a trusted CA certificate".to_string(),
        ))
    }
}

fn decode_crl_file(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .ok_or_else(|| CoreError::Config("CRL file is empty".to_string()))?;
    if bytes[start..].starts_with(b"-----BEGIN") {
        decode_pem_crls(&bytes[start..])
    } else {
        Ok(vec![bytes.to_vec()])
    }
}

fn decode_pem_crls(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| CoreError::Config("CRL PEM is not valid UTF-8".to_string()))?;
    let mut lines = text.lines();
    let mut values = Vec::new();
    loop {
        let header = loop {
            match lines.next() {
                Some(line) if line.trim().is_empty() => continue,
                Some(line) => break line.trim(),
                None => return Ok(values),
            }
        };
        if header != "-----BEGIN X509 CRL-----" {
            return Err(CoreError::Config(
                "CRL PEM must contain only X509 CRL blocks".to_string(),
            ));
        }
        let mut encoded = String::new();
        let mut ended = false;
        for line in lines.by_ref() {
            let line = line.trim();
            if line == "-----END X509 CRL-----" {
                ended = true;
                break;
            }
            if line.starts_with("-----") {
                return Err(CoreError::Config(
                    "CRL PEM contains an invalid nested header".to_string(),
                ));
            }
            if line
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')))
            {
                return Err(CoreError::Config(
                    "CRL PEM contains invalid base64 data".to_string(),
                ));
            }
            encoded.push_str(line);
        }
        if !ended {
            return Err(CoreError::Config(
                "CRL PEM block is not terminated".to_string(),
            ));
        }
        let der = BASE64_STANDARD
            .decode(encoded.as_bytes())
            .map_err(|error| {
                CoreError::Config(format!("CRL PEM base64 decoding failed: {error}"))
            })?;
        if der.is_empty() {
            return Err(CoreError::Config(
                "CRL PEM block contains no DER data".to_string(),
            ));
        }
        values.push(der);
        if values.len() > MAX_CRLS_PER_FILE {
            return Err(CoreError::Config(format!(
                "CRL file contains more than {MAX_CRLS_PER_FILE} CRLs"
            )));
        }
    }
}

fn validate_server_revocation(
    certificates: &[CertificateDer<'static>],
    config: &TlsConfig,
) -> Result<()> {
    let Some(path) = &config.crl_file else {
        return Ok(());
    };
    let crls = CrlSet::load(path, certificates)?;
    let (remaining, leaf) = parse_x509_certificate(certificates[0].as_ref())
        .map_err(|error| CoreError::Config(format!("invalid server certificate: {error}")))?;
    if !remaining.is_empty() {
        return Err(CoreError::Config(
            "server certificate contains trailing DER data".to_string(),
        ));
    }
    let status = crls.check(&leaf, now_unix_seconds());
    if status == RevocationStatus::Good {
        Ok(())
    } else {
        Err(CoreError::Config(format!(
            "server certificate revocation check failed: {status}"
        )))
    }
}

#[cfg(unix)]
fn validate_private_key_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path).map_err(|error| {
        CoreError::Config(format!(
            "cannot inspect private key permissions {}: {error}",
            path.display()
        ))
    })?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(CoreError::Config(format!(
            "private key {} must not be accessible by group or other users (mode {:o})",
            path.display(),
            mode
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn validate_private_key_permissions(path: &Path) -> Result<()> {
    use std::{ffi::c_void, os::windows::ffi::OsStrExt, ptr};

    use windows_sys::Win32::{
        Foundation::{CloseHandle, LocalFree, HANDLE},
        Security::{
            Authorization::{ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT},
            EqualSid, GetAce, GetLengthSid, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
            GetTokenInformation, IsValidSid, TokenUser, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
            DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER,
        },
        System::{
            SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
    };

    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    struct LocalGuard(*mut c_void);
    impl Drop for LocalGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = LocalFree(self.0);
                }
            }
        }
    }

    fn sid_equals(left: PSID, right: PSID) -> bool {
        !left.is_null() && !right.is_null() && unsafe { EqualSid(left, right) } != 0
    }

    fn sid_from_string(value: &str) -> Result<LocalGuard> {
        let wide = value.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let mut sid: PSID = ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) } == 0 || sid.is_null() {
            return Err(CoreError::Config(format!(
                "cannot resolve well-known SID {value} for private key ACL validation"
            )));
        }
        Ok(LocalGuard(sid))
    }

    fn current_user_sid() -> Result<Vec<u32>> {
        let mut token: HANDLE = ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(CoreError::Config(
                "cannot inspect the current process token for private key ACL validation"
                    .to_string(),
            ));
        }
        let _token = HandleGuard(token);
        let mut needed = 0_u32;
        unsafe {
            let _ = GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed);
        }
        if needed == 0 {
            return Err(CoreError::Config(
                "current process token has no user SID".to_string(),
            ));
        }
        let mut buffer = vec![0_u8; needed as usize];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(CoreError::Config(
                "cannot read the current process user SID".to_string(),
            ));
        }
        let token_user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
        let sid = token_user.User.Sid;
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
            return Err(CoreError::Config(
                "current process token contains an invalid user SID".to_string(),
            ));
        }
        let length = unsafe { GetLengthSid(sid) } as usize;
        if length == 0 {
            return Err(CoreError::Config(
                "current process user SID has no usable length".to_string(),
            ));
        }
        let mut words = vec![0_u32; length.div_ceil(std::mem::size_of::<u32>())];
        unsafe {
            ptr::copy_nonoverlapping(sid.cast::<u8>(), words.as_mut_ptr().cast::<u8>(), length);
        }
        Ok(words)
    }

    let current_sid = current_user_sid()?;
    let current_sid_ptr = current_sid.as_ptr().cast::<c_void>() as PSID;
    let system_sid = sid_from_string("S-1-5-18")?;
    let administrators_sid = sid_from_string("S-1-5-32-544")?;
    let trusted = |sid: PSID| {
        sid_equals(sid, current_sid_ptr)
            || sid_equals(sid, system_sid.0)
            || sid_equals(sid, administrators_sid.0)
    };

    let wide_path = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 || descriptor.is_null() {
        return Err(CoreError::Config(format!(
            "cannot read private key ACL {} (Windows error {status})",
            path.display()
        )));
    }
    let _descriptor = LocalGuard(descriptor);

    let mut owner: PSID = ptr::null_mut();
    let mut owner_defaulted = 0;
    if unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut owner_defaulted) } == 0
        || owner.is_null()
        || unsafe { IsValidSid(owner) } == 0
    {
        return Err(CoreError::Config(
            "private key security descriptor has no valid owner".to_string(),
        ));
    }
    if !trusted(owner) {
        return Err(CoreError::Config(
            "private key owner must be the current user, SYSTEM, or Administrators".to_string(),
        ));
    }

    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
        || dacl_present == 0
        || dacl.is_null()
    {
        return Err(CoreError::Config(
            "private key must have an explicit DACL".to_string(),
        ));
    }

    let ace_count = unsafe { (*dacl).AceCount as u32 };
    if ace_count == 0 || ace_count > 4096 {
        return Err(CoreError::Config(
            "private key DACL has an invalid ACE count".to_string(),
        ));
    }
    let mut trusted_allow_count = 0_u32;
    for index in 0..ace_count {
        let mut raw_ace: *mut c_void = ptr::null_mut();
        if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(CoreError::Config(format!(
                "cannot inspect private key ACL entry {index}"
            )));
        }
        let header = unsafe { &*(raw_ace as *const ACE_HEADER) };
        if u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        let ace_type = u32::from(header.AceType);
        if ace_type == ACCESS_DENIED_ACE_TYPE {
            continue;
        }
        if ace_type != ACCESS_ALLOWED_ACE_TYPE {
            return Err(CoreError::Config(format!(
                "private key DACL contains unsupported ACE type {ace_type}"
            )));
        }
        let ace = unsafe { &*(raw_ace as *const ACCESS_ALLOWED_ACE) };
        let sid = (&ace.SidStart as *const u32).cast::<c_void>() as PSID;
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
            return Err(CoreError::Config(format!(
                "private key DACL entry {index} contains an invalid SID"
            )));
        }
        let sid_length = unsafe { GetLengthSid(sid) } as u32;
        if sid_length == 0 || u32::from(header.AceSize) < 8 + sid_length {
            return Err(CoreError::Config(format!(
                "private key DACL entry {index} is malformed"
            )));
        }
        if !trusted(sid) {
            return Err(CoreError::Config(format!(
                "private key ACL grants access to an untrusted principal at ACE {index}"
            )));
        }
        trusted_allow_count += 1;
    }
    if trusted_allow_count == 0 {
        return Err(CoreError::Config(
            "private key DACL grants access to no trusted principal".to_string(),
        ));
    }
    Ok(())
}

fn validate_server_certificate(
    certificates: &[CertificateDer<'static>],
    config: &TlsConfig,
) -> Result<()> {
    let mut parsed = Vec::with_capacity(certificates.len());
    for certificate in certificates {
        let (remaining, parsed_certificate) = parse_x509_certificate(certificate.as_ref())
            .map_err(|error| CoreError::Config(format!("invalid X.509 certificate: {error}")))?;
        if !remaining.is_empty() {
            return Err(CoreError::Config(
                "certificate contains trailing DER data".to_string(),
            ));
        }
        parsed.push(parsed_certificate);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    for (index, certificate) in parsed.iter().enumerate() {
        let validity = &certificate.validity();
        if now < validity.not_before.timestamp() {
            return Err(CoreError::Config(format!(
                "certificate {index} is not valid yet"
            )));
        }
        if now > validity.not_after.timestamp() {
            return Err(CoreError::Config(format!(
                "certificate {index} has expired"
            )));
        }
        if index == 0 {
            let remaining = validity.not_after.timestamp().saturating_sub(now);
            if remaining <= EXPIRY_WARNING_SECONDS {
                tracing::warn!(
                    days = remaining / 86_400,
                    "TLS leaf certificate expires soon"
                );
            }
        }

        let signer = if index + 1 < parsed.len() {
            &parsed[index + 1]
        } else if certificate.issuer() == certificate.subject() {
            certificate
        } else {
            return Err(CoreError::Config(
                "certificate chain is incomplete and does not end at a self-signed root"
                    .to_string(),
            ));
        };
        if certificate.issuer() != signer.subject() {
            return Err(CoreError::Config(format!(
                "certificate {index} issuer does not match the next certificate subject"
            )));
        }
        certificate
            .verify_signature(Some(signer.public_key()))
            .map_err(|error| {
                CoreError::Config(format!("certificate {index} signature is invalid: {error}"))
            })?;
    }

    let leaf = &parsed[0];
    let extended_key_usage = leaf
        .extended_key_usage()
        .map_err(|error| CoreError::Config(format!("invalid certificate EKU: {error}")))?
        .ok_or_else(|| {
            CoreError::Config("leaf certificate has no extended key usage".to_string())
        })?;
    if !extended_key_usage.value.any && !extended_key_usage.value.server_auth {
        return Err(CoreError::Config(
            "leaf certificate EKU does not permit server authentication".to_string(),
        ));
    }
    let san = leaf
        .subject_alternative_name()
        .map_err(|error| CoreError::Config(format!("invalid certificate SAN: {error}")))?
        .ok_or_else(|| CoreError::Config("leaf certificate has no SAN extension".to_string()))?;
    let dns_names = san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(name) => Some(*name),
            _ => None,
        })
        .collect::<Vec<_>>();
    if dns_names.is_empty() {
        return Err(CoreError::Config(
            "leaf certificate SAN contains no DNS names".to_string(),
        ));
    }
    for pattern in &config.allowed_sni {
        if !dns_names
            .iter()
            .any(|name| sni_matches(pattern, name) || sni_matches(name, pattern))
        {
            return Err(CoreError::Config(format!(
                "certificate SAN does not cover allowed SNI pattern {pattern}"
            )));
        }
    }
    Ok(())
}

impl TlsConnectionInfo {
    pub fn from_connection(connection: &rustls::ServerConnection) -> Self {
        Self {
            server_name: connection.server_name().map(ToOwned::to_owned),
            version: connection
                .protocol_version()
                .map(|value| format!("{value:?}")),
            alpn: connection
                .alpn_protocol()
                .map(|value| String::from_utf8_lossy(value).into_owned()),
        }
    }

    pub fn from_quic(server_name: Option<String>, alpn: Option<Vec<u8>>) -> Self {
        Self {
            server_name,
            version: Some("TLS1.3".to_string()),
            alpn: alpn.map(|value| String::from_utf8_lossy(&value).into_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use std::process::Command;
    use std::{
        path::PathBuf,
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        },
    };

    use rcgen::{
        BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType,
        ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose,
        RevocationReason, RevokedCertParams, SerialNumber,
    };

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn write(label: &str, bytes: &[u8]) -> Self {
            let path = std::env::temp_dir().join(format!(
                "highwall-tls-{}-{}-{label}",
                std::process::id(),
                TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::write(&path, bytes).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    fn server_config() -> TlsConfig {
        TlsConfig {
            allowed_sni: vec!["localhost".to_string()],
            ..TlsConfig::default()
        }
    }

    fn self_signed_with_eku(eku: Option<ExtendedKeyUsagePurpose>) -> CertificateDer<'static> {
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).expect("valid SAN");
        if let Some(eku) = eku {
            params.extended_key_usages.push(eku);
        }
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec().into()
    }

    fn make_ca(common_name: &str) -> (Issuer<'static, KeyPair>, CertificateDer<'static>) {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let key = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        (Issuer::new(params, key), certificate.der().to_vec().into())
    }

    fn issue_leaf(
        issuer: &Issuer<'_, KeyPair>,
        serial: u64,
        eku: ExtendedKeyUsagePurpose,
    ) -> CertificateDer<'static> {
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).expect("valid SAN");
        params.serial_number = Some(SerialNumber::from(serial));
        params.use_authority_key_identifier_extension = true;
        params.extended_key_usages.push(eku);
        let key = KeyPair::generate().unwrap();
        params
            .signed_by(&key, issuer)
            .unwrap()
            .der()
            .to_vec()
            .into()
    }

    fn make_crl(issuer: &Issuer<'_, KeyPair>, revoked_serials: &[u64], expired: bool) -> Vec<u8> {
        let (this_update, next_update) = if expired {
            (
                rcgen::date_time_ymd(2010, 1, 1),
                rcgen::date_time_ymd(2011, 1, 1),
            )
        } else {
            (
                rcgen::date_time_ymd(2025, 1, 1),
                rcgen::date_time_ymd(2035, 1, 1),
            )
        };
        let revoked_certs = revoked_serials
            .iter()
            .map(|serial| RevokedCertParams {
                serial_number: SerialNumber::from(*serial),
                revocation_time: rcgen::date_time_ymd(2026, 1, 1),
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            })
            .collect();
        CertificateRevocationListParams {
            this_update,
            next_update,
            crl_number: SerialNumber::from(1_u64),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(issuer)
        .unwrap()
        .der()
        .to_vec()
    }

    #[test]
    fn server_auth_eku_is_accepted() {
        let certificate = self_signed_with_eku(Some(ExtendedKeyUsagePurpose::ServerAuth));
        validate_server_certificate(&[certificate], &server_config()).unwrap();
    }

    #[test]
    fn any_eku_is_accepted_for_server_authentication() {
        let certificate = self_signed_with_eku(Some(ExtendedKeyUsagePurpose::Any));
        validate_server_certificate(&[certificate], &server_config()).unwrap();
    }

    #[test]
    fn missing_eku_is_rejected() {
        let certificate = self_signed_with_eku(None);
        assert!(validate_server_certificate(&[certificate], &server_config()).is_err());
    }

    #[test]
    fn client_auth_only_eku_is_rejected() {
        let certificate = self_signed_with_eku(Some(ExtendedKeyUsagePurpose::ClientAuth));
        assert!(validate_server_certificate(&[certificate], &server_config()).is_err());
    }

    #[test]
    fn missing_san_coverage_is_rejected() {
        let mut params = CertificateParams::new(vec!["other.test".to_string()]).unwrap();
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        let key = KeyPair::generate().unwrap();
        let certificate: CertificateDer<'static> =
            params.self_signed(&key).unwrap().der().to_vec().into();
        let config = TlsConfig {
            allowed_sni: vec!["localhost".to_string()],
            ..TlsConfig::default()
        };
        assert!(validate_server_certificate(&[certificate], &config).is_err());
    }

    #[test]
    fn crl_revoked_server_certificate_is_rejected() {
        let (issuer, ca) = make_ca("test server ca");
        let leaf = issue_leaf(&issuer, 0x1234, ExtendedKeyUsagePurpose::ServerAuth);
        let crl = make_crl(&issuer, &[0x1234], false);
        let file = TempFile::write("revoked.der", &crl);
        let mut config = server_config();
        config.crl_file = Some(file.path().to_path_buf());
        let error = validate_server_revocation(&[leaf.clone(), ca.clone()], &config).unwrap_err();
        assert!(error.to_string().contains("revoked"));

        let crls = CrlSet::load(file.path(), &[ca]).unwrap();
        let (_, parsed_leaf) = parse_x509_certificate(leaf.as_ref()).unwrap();
        assert_eq!(
            crls.check(&parsed_leaf, now_unix_seconds()),
            RevocationStatus::Revoked
        );
    }

    #[test]
    fn crl_without_matching_serial_accepts_certificate() {
        let (issuer, ca) = make_ca("test server ca");
        let leaf = issue_leaf(&issuer, 0x1234, ExtendedKeyUsagePurpose::ServerAuth);
        let crl = make_crl(&issuer, &[0x9999], false);
        let file = TempFile::write("valid.der", &crl);
        let crls = CrlSet::load(file.path(), &[ca]).unwrap();
        let (_, parsed_leaf) = parse_x509_certificate(leaf.as_ref()).unwrap();
        assert_eq!(
            crls.check(&parsed_leaf, now_unix_seconds()),
            RevocationStatus::Good
        );
    }

    #[test]
    fn expired_crl_is_rejected() {
        let (issuer, ca) = make_ca("test server ca");
        let _leaf = issue_leaf(&issuer, 0x1234, ExtendedKeyUsagePurpose::ServerAuth);
        let crl = make_crl(&issuer, &[0x1234], true);
        let file = TempFile::write("expired.der", &crl);
        let error = CrlSet::load(file.path(), &[ca]).unwrap_err();
        assert!(error.to_string().contains("expired"));
    }

    #[test]
    fn crl_with_wrong_issuer_is_rejected() {
        let (server_issuer, server_ca) = make_ca("server ca");
        let (other_issuer, _other_ca) = make_ca("unrelated ca");
        let _leaf = issue_leaf(&server_issuer, 0x1234, ExtendedKeyUsagePurpose::ServerAuth);
        let crl = make_crl(&other_issuer, &[], false);
        let file = TempFile::write("wrong-issuer.der", &crl);
        assert!(CrlSet::load(file.path(), &[server_ca]).is_err());
    }

    #[test]
    fn tampered_crl_signature_is_rejected() {
        let (issuer, ca) = make_ca("test server ca");
        let _leaf = issue_leaf(&issuer, 0x1234, ExtendedKeyUsagePurpose::ServerAuth);
        let mut crl = make_crl(&issuer, &[], false);
        *crl.last_mut().unwrap() ^= 0x01;
        let file = TempFile::write("tampered.der", &crl);
        assert!(CrlSet::load(file.path(), &[ca]).is_err());
    }

    #[test]
    fn mtls_client_verifier_rejects_revoked_leaf() {
        let (issuer, ca) = make_ca("client ca");
        let leaf = issue_leaf(&issuer, 0x55aa, ExtendedKeyUsagePurpose::ClientAuth);
        let crl = make_crl(&issuer, &[0x55aa], false);
        let file = TempFile::write("client-revoked.der", &crl);
        let crls = Arc::new(CrlSet::load(file.path(), std::slice::from_ref(&ca)).unwrap());
        let mut roots = RootCertStore::empty();
        roots.add(ca).unwrap();
        let inner = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(ring::default_provider()),
        )
        .build()
        .unwrap();
        let now = UnixTime::now();
        inner.verify_client_cert(&leaf, &[], now).unwrap();
        let verifier = RevocationClientVerifier { inner, crls };
        let error = verifier.verify_client_cert(&leaf, &[], now).unwrap_err();
        assert!(matches!(
            error,
            RustlsError::InvalidCertificate(CertificateError::Revoked)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_private_key_acl_rejects_broad_access_and_accepts_owner_only() {
        fn current_user_sid() -> String {
            let output = Command::new("whoami")
                .args(["/user", "/fo", "csv", "/nh"])
                .output()
                .expect("whoami must be available on Windows");
            assert!(output.status.success());
            let text = String::from_utf8_lossy(&output.stdout);
            text.trim()
                .rsplit(',')
                .next()
                .unwrap()
                .trim()
                .trim_matches('"')
                .to_string()
        }

        fn run_icacls(path: &Path, arguments: &[&str]) {
            let output = Command::new("icacls")
                .arg(path)
                .args(arguments)
                .output()
                .expect("icacls must be available on Windows");
            assert!(
                output.status.success(),
                "icacls failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let file = TempFile::write("acl-test.key", b"test-private-key-material");
        let users = "*S-1-5-32-545:(R)";
        run_icacls(file.path(), &["/inheritance:r", "/grant:r", users]);
        assert!(validate_private_key_permissions(file.path()).is_err());

        let current = format!("*{}:(R)", current_user_sid());
        run_icacls(
            file.path(),
            &["/remove:g", "*S-1-5-32-545", "/grant:r", &current],
        );
        validate_private_key_permissions(file.path()).unwrap();
    }

    #[test]
    fn provider_installation_is_idempotent() {
        install_provider().unwrap();
        install_provider().unwrap();
    }

    #[test]
    fn quic_crypto_disables_early_data_and_uses_h3_only() {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let certificate = CertificateDer::from(generated.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(generated.signing_key.serialize_der().into());
        let provider = Arc::new(ring::default_provider());
        let certified = CertifiedKey::from_der(vec![certificate], key, &provider).unwrap();
        let config = server_config();
        let resolver = Arc::new(StrictSniResolver {
            certified: Arc::new(certified),
            allowed_sni: config.allowed_sni.clone(),
            allow_missing_sni: config.allow_missing_sni,
        });
        let tcp = build_server_config(&config, resolver.clone(), provider.clone(), false).unwrap();
        assert_eq!(tcp.max_early_data_size, 0);
        assert_eq!(
            tcp.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        let quic = build_server_config(&config, resolver, provider, true).unwrap();
        assert_eq!(quic.max_early_data_size, 0);
        assert_eq!(quic.alpn_protocols, vec![b"h3".to_vec()]);
    }

    fn _assert_send_sync() {
        fn check<T: Send + Sync>() {}
        check::<Arc<TlsBundle>>();
    }
}
