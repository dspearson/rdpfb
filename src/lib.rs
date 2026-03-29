/// rdpfb — serve any framebuffer over RDP
///
/// A library for building RDP servers that render arbitrary content.
/// Implement [`RdpApplication`] to provide your rendering logic,
/// then hand it to [`RdpServer`] and you have a working RDP server.
///
/// # Example
///
/// ```rust,no_run
/// use rdpfb::prelude::*;
/// use std::sync::Arc;
/// use tokio::sync::Notify;
///
/// struct MyApp {
///     notify: Arc<Notify>,
/// }
///
/// impl RdpApplication for MyApp {
///     fn on_connect(&mut self, width: u16, height: u16, fb: &mut Framebuffer) -> anyhow::Result<()> {
///         fb.fill_rect(10, 10, 100, 100, Color::new(255, 0, 0));
///         Ok(())
///     }
///
///     fn on_input(&mut self, _event: InputEvent) -> anyhow::Result<()> {
///         Ok(())
///     }
///
///     fn render(&mut self, _fb: &mut Framebuffer) -> anyhow::Result<bool> {
///         Ok(false)
///     }
///
///     fn content_notify(&self) -> Arc<Notify> {
///         self.notify.clone()
///     }
/// }
///
/// struct MyAppFactory;
///
/// impl RdpApplicationFactory for MyAppFactory {
///     fn create(&self) -> anyhow::Result<Box<dyn RdpApplication>> {
///         Ok(Box::new(MyApp { notify: Arc::new(Notify::new()) }))
///     }
/// }
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     let config = RdpServerConfig {
///         address: "0.0.0.0".into(),
///         port: 3389,
///         width: 1024,
///         height: 768,
///         enable_tls: true,
///         tls_config: Some(TlsConfig {
///             cert_path: "certs/server.crt".into(),
///             key_path: "certs/server.key".into(),
///         }),
///     };
///     let server = RdpServer::new(config, Arc::new(MyAppFactory), None);
///     server.run().await
/// }
/// ```

pub mod application;
pub mod framebuffer;
pub mod graphics;
pub mod protocol;
pub mod security;
pub mod server;
pub mod session;
pub mod stream;
pub mod tls;

/// Convenience re-exports for common usage.
pub mod prelude {
    pub use crate::application::{RdpApplication, RdpApplicationFactory, RdpAuthenticator};
    pub use crate::framebuffer::{Color, Framebuffer};
    pub use crate::protocol::rdp::InputEvent;
    pub use crate::server::{RdpServer, RdpServerConfig};
    pub use crate::tls::TlsConfig;
}
