/// RDP Server module
///
/// Accepts inbound TCP connections, applies rate limiting and connection
/// tracking, then delegates each connection to an `RdpSession`.
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::application::{RdpApplicationFactory, RdpAuthenticator};
use crate::security::{ConnectionManager, RateLimiter};
use crate::session::RdpSession;
use crate::tls::{TlsConfig, create_tls_acceptor};

/// RDP server configuration
pub struct RdpServerConfig {
    pub address: String,
    pub port: u16,
    pub width: u16,
    pub height: u16,
    pub enable_tls: bool,
    pub tls_config: Option<TlsConfig>,
}

/// Main RDP server
pub struct RdpServer {
    config: Arc<RdpServerConfig>,
    rate_limiter: Arc<RateLimiter>,
    conn_manager: Arc<ConnectionManager>,
    app_factory: Arc<dyn RdpApplicationFactory>,
    authenticator: Option<Arc<dyn RdpAuthenticator>>,
}

impl RdpServer {
    pub fn new(
        config: RdpServerConfig,
        app_factory: Arc<dyn RdpApplicationFactory>,
        authenticator: Option<Arc<dyn RdpAuthenticator>>,
    ) -> Self {
        RdpServer {
            config: Arc::new(config),
            rate_limiter: Arc::new(RateLimiter::new()),
            conn_manager: Arc::new(ConnectionManager::new()),
            app_factory,
            authenticator,
        }
    }

    /// Start the RDP server
    pub async fn run(&self) -> Result<()> {
        let addr = format!("{}:{}", self.config.address, self.config.port);

        // Initialise TLS if enabled
        let tls_acceptor = if self.config.enable_tls {
            let tls_config = self
                .config
                .tls_config
                .as_ref()
                .context("TLS enabled but no TLS config provided")?;

            info!("Starting RDP server with TLS on {}", addr);
            Some(create_tls_acceptor(tls_config)?)
        } else {
            info!("Starting RDP server (plaintext) on {}", addr);
            None
        };

        let listener = TcpListener::bind(&addr)
            .await
            .context("Failed to bind RDP server")?;

        let tls_status = if tls_acceptor.is_some() {
            "with TLS"
        } else {
            "plaintext"
        };
        info!("RDP server listening on {} ({})", addr, tls_status);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let ip = peer_addr.ip();

                    // Check rate limit
                    if let Err(e) = self.rate_limiter.check_connection(ip) {
                        warn!("Rate limit exceeded for {}: {}", peer_addr, e);
                        drop(stream);
                        continue;
                    }

                    // Check connection limit
                    if let Err(e) = self.conn_manager.check_connection_limit(ip) {
                        warn!("Connection limit exceeded for {}: {}", peer_addr, e);
                        drop(stream);
                        continue;
                    }

                    let attempts = self.rate_limiter.get_attempts(ip);
                    let active_conns = self.conn_manager.get_connection_count(ip);
                    info!(
                        "New RDP connection from {} (attempts: {}, active: {})",
                        peer_addr, attempts, active_conns
                    );

                    let config = self.config.clone();
                    let rate_limiter = self.rate_limiter.clone();
                    let conn_manager = self.conn_manager.clone();
                    let tls_acceptor_clone = tls_acceptor.clone();
                    let app_factory = self.app_factory.clone();
                    let authenticator = self.authenticator.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_rdp_connection(
                            stream,
                            config,
                            ip,
                            tls_acceptor_clone,
                            rate_limiter.clone(),
                            conn_manager.clone(),
                            app_factory,
                            authenticator,
                        )
                        .await
                        {
                            error!("RDP connection error from {}: {:#}", peer_addr, e);
                        } else {
                            info!("RDP connection closed cleanly from {}", peer_addr);
                            rate_limiter.record_success(ip);
                        }

                        conn_manager.remove_connection(ip);
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }
}

/// Handle an individual RDP connection
#[allow(clippy::too_many_arguments)]
async fn handle_rdp_connection(
    stream: TcpStream,
    config: Arc<RdpServerConfig>,
    ip: std::net::IpAddr,
    tls_acceptor: Option<TlsAcceptor>,
    _rate_limiter: Arc<RateLimiter>,
    _conn_manager: Arc<ConnectionManager>,
    app_factory: Arc<dyn RdpApplicationFactory>,
    authenticator: Option<Arc<dyn RdpAuthenticator>>,
) -> Result<()> {
    info!("Handling new RDP connection from {}", ip);

    let app = app_factory.create().context("Failed to create application")?;

    let mut session = RdpSession::new(
        stream,
        config.width,
        config.height,
        tls_acceptor,
        app,
        authenticator,
    )
    .context("Failed to create RDP session")?;

    session
        .run()
        .await
        .context("RDP session failed during protocol execution")?;

    info!("RDP session completed for {}", ip);

    Ok(())
}
