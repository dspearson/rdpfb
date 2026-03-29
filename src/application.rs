/// Application traits for RDP framebuffer server
///
/// Defines the interface between the RDP protocol layer and the application
/// that renders content into the framebuffer.
use crate::framebuffer::Framebuffer;
use crate::protocol::rdp::InputEvent;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Notify;

/// Trait for RDP applications that render to a framebuffer.
pub trait RdpApplication: Send {
    /// Called when the client connects and resolution is known.
    /// Set up rendering pipeline, spawn processes, etc.
    fn on_connect(&mut self, width: u16, height: u16, framebuffer: &mut Framebuffer) -> Result<()>;

    /// Called for each input event from the RDP client.
    fn on_input(&mut self, event: InputEvent) -> Result<()>;

    /// Render current state into the framebuffer.
    /// Return true if the framebuffer changed and needs sending to the client.
    fn render(&mut self, framebuffer: &mut Framebuffer) -> Result<bool>;

    /// Returns a Notify that the application signals when it has new content.
    fn content_notify(&self) -> Arc<Notify>;
}

/// Factory for creating application instances (one per RDP connection).
pub trait RdpApplicationFactory: Send + Sync + 'static {
    fn create(&self) -> Result<Box<dyn RdpApplication>>;
}

/// Optional authenticator for validating RDP client credentials.
pub trait RdpAuthenticator: Send + Sync {
    fn authenticate(&self, username: &str, password: &str) -> bool;
}
