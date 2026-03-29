/// TLS module for secure RDP connections
///
/// Provides TLS/SSL encryption for RDP protocol using rustls
use anyhow::{Context, Result, bail};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info};

/// TLS configuration for RDP server
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

impl Default for TlsConfig {
    fn default() -> Self {
        TlsConfig {
            cert_path: "certs/server.crt".to_string(),
            key_path: "certs/server.key".to_string(),
        }
    }
}

/// Create TLS acceptor from configuration
pub fn create_tls_acceptor(config: &TlsConfig) -> Result<TlsAcceptor> {
    debug!("Loading TLS certificate from: {}", config.cert_path);
    debug!("Loading TLS private key from: {}", config.key_path);

    // Load certificate chain
    let cert_path = Path::new(&config.cert_path);
    if !cert_path.exists() {
        bail!(
            "Certificate file not found: {}. Generate with: openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes",
            config.cert_path
        );
    }

    let certs = load_certs(cert_path)?;

    // Load private key
    let key_path = Path::new(&config.key_path);
    if !key_path.exists() {
        bail!("Private key file not found: {}", config.key_path);
    }

    let key = load_private_key(key_path)?;

    // Create server config
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to create TLS server config")?;

    info!("TLS certificate loaded successfully");

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Load certificates from PEM file
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let cert_file = std::fs::File::open(path).context("Failed to open certificate file")?;
    let mut reader = std::io::BufReader::new(cert_file);

    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificate PEM")?;

    if certs.is_empty() {
        bail!("No certificates found in {}", path.display());
    }

    Ok(certs)
}

/// Load private key from PEM file
fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let key_file = std::fs::File::open(path).context("Failed to open private key file")?;
    let mut reader = std::io::BufReader::new(key_file);

    // Try to read as PKCS#8 first
    if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut reader).next() {
        let key = key.context("Failed to parse PKCS#8 private key")?;
        return Ok(PrivateKeyDer::Pkcs8(key));
    }

    // Rewind and try RSA
    let key_file = std::fs::File::open(path).context("Failed to reopen private key file")?;
    let mut reader = std::io::BufReader::new(key_file);

    if let Some(key) = rustls_pemfile::rsa_private_keys(&mut reader).next() {
        let key = key.context("Failed to parse RSA private key")?;
        return Ok(PrivateKeyDer::Pkcs1(key));
    }

    bail!("No valid private key found in {}", path.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_config_default() {
        let config = TlsConfig::default();
        assert_eq!(config.cert_path, "certs/server.crt");
        assert_eq!(config.key_path, "certs/server.key");
    }

    #[test]
    fn test_create_tls_acceptor_nonexistent_cert() {
        let config = TlsConfig {
            cert_path: "/nonexistent/path/cert.pem".to_string(),
            key_path: "/nonexistent/path/key.pem".to_string(),
        };
        let result = create_tls_acceptor(&config);
        assert!(result.is_err());
        let err_msg = format!("{}", result.err().unwrap());
        // Should mention the file or give a helpful message
        assert!(
            err_msg.contains("not found") || err_msg.contains("Certificate"),
            "Error should mention missing certificate, got: {}",
            err_msg
        );
    }
}
