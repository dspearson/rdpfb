/// RDP Session Handler
///
/// Orchestrates the complete RDP connection sequence and manages session state.
mod input;
mod protocol_io;

use anyhow::{Context, Result, bail};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::application::{RdpApplication, RdpAuthenticator};
use crate::framebuffer::Framebuffer;
use crate::graphics::bitmap::*;
use crate::protocol::mcs::*;
use crate::protocol::pdu::*;
use crate::protocol::rdp::*;
use crate::protocol::sec::*;
use crate::stream::RdpStream;

/// Connection state machine
#[derive(Debug, Clone, Copy, PartialEq)]
enum ConnectionState {
    Initial,
    X224Connected,
    McsConnected,
    McsAttached,
    ChannelsJoined,
    SecurityEstablished,
    CapabilitiesExchanged,
    Finalized,
    Active,
}

/// RDP Session
pub struct RdpSession {
    stream: Option<RdpStream>,
    tls_acceptor: Option<TlsAcceptor>,
    state: ConnectionState,
    client_info: ClientInfo,
    user_id: u16,
    framebuffer: Framebuffer,
    width: u16,
    height: u16,
    color_depth: u16,
    target_bpp: u16,
    // Previous frame for dirty region detection
    prev_frame: Vec<u8>,
    // Application and authenticator
    app: Box<dyn RdpApplication>,
    authenticator: Option<Arc<dyn RdpAuthenticator>>,
}

impl RdpSession {
    /// Create a new RDP session
    pub fn new(
        stream: TcpStream,
        width: u16,
        height: u16,
        tls_acceptor: Option<TlsAcceptor>,
        app: Box<dyn RdpApplication>,
        authenticator: Option<Arc<dyn RdpAuthenticator>>,
    ) -> Result<Self> {
        debug!("Creating new RDP session: {}x{} pixels", width, height);

        let framebuffer = Framebuffer::new(width as usize, height as usize);
        let user_id = MCS_USERCHANNEL_BASE + 1;

        Ok(RdpSession {
            stream: Some(RdpStream::Plain(stream)),
            tls_acceptor,
            state: ConnectionState::Initial,
            client_info: ClientInfo::default(),
            user_id,
            framebuffer,
            width,
            height,
            color_depth: 16, // Default to 16-bit colour
            target_bpp: 24,  // Recomputed after client negotiation
            prev_frame: Vec::new(),
            app,
            authenticator,
        })
    }

    /// Run the complete RDP connection sequence
    pub async fn run(&mut self) -> Result<()> {
        info!("Starting RDP session state machine");
        info!("Current state: {:?}", self.state);

        // X.224 Connection sequence
        info!("STAGE 1/9: X.224 Connection");
        self.handle_x224_connection()
            .await
            .context("Failed during X.224 connection stage")?;
        self.state = ConnectionState::X224Connected;
        info!("X.224 connected - State: {:?}", self.state);

        // MCS Connection sequence
        info!("STAGE 2/9: MCS Connect");
        self.handle_mcs_connect()
            .await
            .context("Failed during MCS connect stage")?;
        self.state = ConnectionState::McsConnected;
        info!("MCS connected - State: {:?}", self.state);

        // MCS Erect Domain
        info!("STAGE 3/9: MCS Erect Domain");
        self.handle_mcs_erect_domain()
            .await
            .context("Failed during MCS erect domain stage")?;
        debug!("MCS erect domain complete");

        // MCS Attach User
        info!("STAGE 4/9: MCS Attach User");
        self.handle_mcs_attach_user()
            .await
            .context("Failed during MCS attach user stage")?;
        self.state = ConnectionState::McsAttached;
        info!(
            "User attached (user_id=0x{:04X}) - State: {:?}",
            self.user_id, self.state
        );

        // MCS Channel Joins
        info!("STAGE 5/9: MCS Channel Joins");
        self.handle_mcs_channel_joins()
            .await
            .context("Failed during MCS channel join stage")?;
        self.state = ConnectionState::ChannelsJoined;
        info!("Channels joined - State: {:?}", self.state);

        // RDP Security Exchange (Client Info PDU)
        info!("STAGE 6/9: RDP Security Exchange");
        self.handle_client_info()
            .await
            .context("Failed during RDP security exchange stage")?;
        self.state = ConnectionState::SecurityEstablished;
        info!("Security established - State: {:?}", self.state);

        // RDP Capabilities Exchange (Demand Active / Confirm Active)
        info!("STAGE 7/9: RDP Capabilities Exchange");
        self.handle_capabilities_exchange()
            .await
            .context("Failed during capabilities exchange stage")?;
        self.state = ConnectionState::CapabilitiesExchanged;
        info!("Capabilities exchanged - State: {:?}", self.state);

        // RDP Finalization
        info!("STAGE 8/9: RDP Finalization");
        self.handle_finalization()
            .await
            .context("Failed during finalization stage")?;
        self.state = ConnectionState::Finalized;
        info!("Connection finalized - State: {:?}", self.state);

        // Skip initial screen — let the main event loop send the first frame
        // once the shell prompt has actually rendered (avoids capturing partial
        // output like zsh's PROMPT_SP '%' marker)
        self.state = ConnectionState::Active;
        info!("Session active - State: {:?}", self.state);

        // Main event loop
        info!("Entering main event loop");
        self.main_loop().await.context("Error in main event loop")?;

        info!("Session ended gracefully");
        Ok(())
    }

    /// Handle X.224 Connection Request/Confirm
    async fn handle_x224_connection(&mut self) -> Result<()> {
        let mut buf = vec![0u8; 4096];

        let n = self
            .stream
            .as_mut()
            .unwrap()
            .read(&mut buf)
            .await
            .context("Failed to read X.224 CR")?;

        if n == 0 {
            bail!("Connection closed before X.224 CR received");
        }

        // Validate TPKT header
        if n < 4 {
            bail!("TPKT header too short: {} bytes (minimum 4 required)", n);
        }

        if buf[0] != TPKT_VERSION {
            bail!(
                "Invalid TPKT version: {} (expected {})",
                buf[0],
                TPKT_VERSION
            );
        }

        let tpkt_length = u16::from_be_bytes([buf[2], buf[3]]) as u32;
        if tpkt_length as usize != n {
            warn!(
                "TPKT length mismatch: header says {}, received {}",
                tpkt_length, n
            );
        }

        // Parse client's requested protocols from RDP Negotiation Request
        let client_requested_protocols = self.parse_rdp_negotiation_request(&buf[..n])?;

        // Determine which protocol to use
        let selected_protocol = if client_requested_protocols & PROTOCOL_SSL != 0
            && self.tls_acceptor.is_some()
        {
            info!("Client supports TLS and server has TLS configured - selecting TLS");
            PROTOCOL_SSL
        } else if client_requested_protocols & PROTOCOL_HYBRID != 0 {
            info!("Client requested CredSSP but we don't support it - falling back to TLS or RDP");
            if self.tls_acceptor.is_some() {
                PROTOCOL_SSL
            } else {
                PROTOCOL_RDP
            }
        } else {
            info!("Using standard RDP security (no TLS)");
            PROTOCOL_RDP
        };

        // Send X.224 Connection Confirm with selected protocol
        let response = self.build_x224_connection_confirm(selected_protocol);
        self.write_tpkt(&response)
            .await
            .context("Failed to send X.224 CC")?;

        // If TLS was selected, upgrade the connection now
        if selected_protocol == PROTOCOL_SSL {
            self.upgrade_to_tls()
                .await
                .context("Failed to upgrade connection to TLS")?;
        }

        Ok(())
    }

    /// Parse RDP Negotiation Request from X.224 CR
    fn parse_rdp_negotiation_request(&self, data: &[u8]) -> Result<u32> {
        // Skip TPKT header (4 bytes) and X.224 CR header (7 bytes minimum)
        if data.len() < 11 {
            debug!("No RDP negotiation request (packet too short), assuming RDP only");
            return Ok(PROTOCOL_RDP);
        }

        // Look for RDP_NEG_REQ (0x01) in the X.224 CR
        let mut offset = 11; // After TPKT + X.224 headers
        while offset + 8 <= data.len() {
            if data[offset] == RDP_NEG_REQ {
                // Found negotiation request
                // Format: type(1) + flags(1) + length(2) + requestedProtocols(4)
                if offset + 8 <= data.len() {
                    let protocols = u32::from_le_bytes([
                        data[offset + 4],
                        data[offset + 5],
                        data[offset + 6],
                        data[offset + 7],
                    ]);
                    debug!(
                        "Found RDP_NEG_REQ at offset {}, protocols: 0x{:08X}",
                        offset, protocols
                    );
                    return Ok(protocols);
                }
            }
            offset += 1;
        }

        debug!("No RDP_NEG_REQ found, assuming RDP only");
        Ok(PROTOCOL_RDP)
    }

    /// Upgrade connection to TLS
    async fn upgrade_to_tls(&mut self) -> Result<()> {
        info!("Upgrading connection to TLS...");

        // Take ownership of the TLS acceptor
        let acceptor = self
            .tls_acceptor
            .take()
            .context("TLS acceptor not available")?;

        // Take the stream out of the Option
        let plain_stream = self.stream.take().context("Stream not available")?;

        // Extract TCP stream
        let tcp_stream = match plain_stream {
            RdpStream::Plain(s) => s,
            RdpStream::Tls(_) => bail!("Stream already upgraded to TLS"),
        };

        let tls_stream = acceptor
            .accept(tcp_stream)
            .await
            .context("TLS handshake failed")?;
        info!("TLS handshake completed successfully");

        // Replace stream with TLS version
        self.stream = Some(RdpStream::Tls(Box::new(tls_stream)));

        Ok(())
    }

    /// Build X.224 Connection Confirm
    fn build_x224_connection_confirm(&self, selected_protocol: u32) -> Vec<u8> {
        let mut pdu = vec![
            // X.224 CC TPDU (7 bytes + RDP Negotiation Response)
            // LI = length of everything after LI byte = 6 (X.224 header) + 8 (RDP neg response) = 14
            0x0E,                        // LI (length indicator) = 14
            X224_TPDU_CONNECTION_CONFIRM, // 0xD0
            0,
            0, // Destination ref
            0,
            0, // Source ref
            0, // Class/options
            // RDP Negotiation Response (8 bytes)
            RDP_NEG_RSP, // Type
            0,           // Flags
            8,
            0, // Length
        ];
        pdu.extend_from_slice(&selected_protocol.to_le_bytes()); // Selected protocol

        pdu
    }

    /// Handle MCS Connect-Initial/Response
    async fn handle_mcs_connect(&mut self) -> Result<()> {
        let mcs_data = self
            .read_mcs_pdu()
            .await
            .context("Failed to read MCS Connect-Initial PDU")?;

        let connect_initial =
            McsConnectInitial::decode(&mcs_data).context("Failed to parse MCS Connect-Initial")?;

        // Parse GCC Conference Create Request from user data
        self.client_info = parse_gcc_create_request(&connect_initial.user_data)
            .context("Failed to parse GCC Create Request")?;

        // Use client's requested resolution
        let old_width = self.width;
        let old_height = self.height;
        let old_depth = self.color_depth;

        self.width = self.client_info.desktop_width;
        self.height = self.client_info.desktop_height;
        self.color_depth = self.client_info.color_depth;

        // Compute target_bpp once, used for ALL bitmap updates
        self.target_bpp = if self.color_depth >= 24 { 24 } else { 16 };

        info!(
            "Client requested resolution: {}x{} @ {} bpp (target_bpp={}, was {}x{} @ {} bpp)",
            self.width,
            self.height,
            self.color_depth,
            self.target_bpp,
            old_width,
            old_height,
            old_depth
        );

        // Apply client-requested resolution: recreate framebuffer
        self.framebuffer = Framebuffer::new(self.width as usize, self.height as usize);

        // Notify the application of the connection with resolved dimensions
        self.app
            .on_connect(self.width, self.height, &mut self.framebuffer)
            .context("Application on_connect failed")?;

        debug!(
            "Client info - build: {}, keyboard: 0x{:08X}, channels: {}",
            self.client_info.client_build,
            self.client_info.keyboard_type,
            self.client_info.channels.len()
        );

        if !self.client_info.channels.is_empty() {
            debug!("Virtual channels requested:");
            for (i, ch) in self.client_info.channels.iter().enumerate() {
                debug!(
                    "  {}. name='{}', options=0x{:08X}",
                    i + 1,
                    ch.name,
                    ch.options
                );
            }
        }

        // Build and send MCS Connect-Response
        let gcc_response =
            build_gcc_create_response(&self.client_info).context("Failed to build GCC response")?;
        let connect_response = McsConnectResponse::new_success(gcc_response);
        let response_data = connect_response
            .encode()
            .context("Failed to encode MCS Connect-Response")?;
        self.write_mcs_pdu(&response_data)
            .await
            .context("Failed to send MCS Connect-Response")?;

        Ok(())
    }

    /// Handle MCS Erect Domain Request
    async fn handle_mcs_erect_domain(&mut self) -> Result<()> {
        let mcs_data = self
            .read_mcs_pdu()
            .await
            .context("Failed to read MCS Erect Domain PDU")?;
        McsErectDomainRequest::decode(&mcs_data)
            .context("Failed to decode MCS Erect Domain Request")?;
        Ok(())
    }

    /// Handle MCS Attach User Request/Confirm
    async fn handle_mcs_attach_user(&mut self) -> Result<()> {
        let mcs_data = self
            .read_mcs_pdu()
            .await
            .context("Failed to read MCS Attach User PDU")?;
        McsAttachUserRequest::decode(&mcs_data)
            .context("Failed to decode MCS Attach User Request")?;

        let confirm = McsAttachUserConfirm::new_success(self.user_id);
        let confirm_data = confirm
            .encode()
            .context("Failed to encode Attach User Confirm")?;
        self.write_mcs_pdu(&confirm_data)
            .await
            .context("Failed to send Attach User Confirm")?;

        Ok(())
    }

    /// Handle MCS Channel Join Requests
    async fn handle_mcs_channel_joins(&mut self) -> Result<()> {
        // Client will join:
        // 1. User channel (user_id)
        // 2. Global channel (MCS_GLOBAL_CHANNEL)
        // 3. Any virtual channels requested

        let num_joins = 2 + self.client_info.channels.len();
        info!(
            "Expecting {} channel join requests (2 standard + {} virtual)",
            num_joins,
            self.client_info.channels.len()
        );

        for i in 0..num_joins {
            let mcs_data = self.read_mcs_pdu().await.context(format!(
                "Failed to read MCS PDU for channel join {}/{}",
                i + 1,
                num_joins
            ))?;

            let join_request = McsChannelJoinRequest::decode(&mcs_data).context(format!(
                "Failed to decode Channel Join Request {}/{}",
                i + 1,
                num_joins
            ))?;

            let confirm =
                McsChannelJoinConfirm::new_success(join_request.user_id, join_request.channel_id);
            let confirm_data = confirm
                .encode()
                .context("Failed to encode Channel Join Confirm")?;
            self.write_mcs_pdu(&confirm_data).await.context(format!(
                "Failed to send Channel Join Confirm {}/{}",
                i + 1,
                num_joins
            ))?;
        }

        info!("All {} channel joins completed", num_joins);

        Ok(())
    }

    /// Handle Client Info PDU (Security Exchange)
    ///
    /// The Client Info PDU (MS-RDPBCGR 2.2.1.11) carries the TS_INFO_PACKET
    /// which contains domain, username, password, and shell fields.
    /// When auth credentials are configured, we validate them here.
    async fn handle_client_info(&mut self) -> Result<()> {
        // Read raw MCS PDU — the Client Info PDU is NOT wrapped in a Share Control
        // header. After the MCS header comes: security_header(4) + TS_INFO_PACKET.
        let mcs_data = self
            .read_mcs_pdu()
            .await
            .context("Failed to read Client Info PDU")?;

        // Skip MCS Send Data Request header (variable length)
        let mcs_header_len: usize = if mcs_data.len() > 6 && mcs_data[6] & 0x80 == 0 {
            7
        } else {
            8
        };
        if mcs_data.len() < mcs_header_len + 4 {
            bail!("Client Info PDU too short");
        }

        // Skip security header (4 bytes of flags)
        let info_start = mcs_header_len + 4;
        if mcs_data.len() > info_start {
            let info_data = &mcs_data[info_start..];
            let (username, password) = parse_ts_info_packet(info_data);
            info!("Client login: user='{}'", username);

            // Validate credentials if authenticator is configured
            if let Some(ref authenticator) = self.authenticator {
                if !authenticator.authenticate(&username, &password) {
                    warn!("Authentication failed for user '{}'", username);
                    bail!("Authentication failed");
                }
            }
        }

        // Send Server License Error PDU (STATUS_VALID_CLIENT — no licensing required)
        let license_pdu =
            build_server_license_error_pdu().context("Failed to build Server License Error PDU")?;
        self.write_rdp_security_pdu(&license_pdu)
            .await
            .context("Failed to send Server License Error PDU")?;
        Ok(())
    }

    /// Handle Capabilities Exchange (Demand Active / Confirm Active)
    async fn handle_capabilities_exchange(&mut self) -> Result<()> {
        // Build Demand Active PDU using target_bpp for preferredBitsPerPixel
        let demand_active = DemandActivePdu::new_minimal(self.width, self.height, self.target_bpp);
        let demand_data = demand_active
            .encode()
            .context("Failed to encode Demand Active PDU")?;
        self.write_rdp_share_control_pdu(PDUTYPE_DEMANDACTIVEPDU, &demand_data)
            .await
            .context("Failed to send Demand Active PDU")?;

        // Wait for Confirm Active
        let (_pdu_type_code, confirm_data) = self
            .read_rdp_pdu()
            .await
            .context("Failed to read Confirm Active PDU")?;
        ConfirmActivePdu::decode(&confirm_data).context("Failed to decode Confirm Active PDU")?;

        Ok(())
    }

    /// Handle Finalization Sequence
    ///
    /// Per MS-RDPBCGR the finalization sequence is a PDU exchange:
    ///   Client -> Synchronize
    ///   Client -> Control Cooperate
    ///   Client -> Control Request (action=1)  <- server responds: Synchronize + Cooperate + GrantedControl
    ///   Client -> FontList (pduType2=39)       <- server responds: FontMap
    ///
    /// We read each client PDU and respond at the right trigger point.
    async fn handle_finalization(&mut self) -> Result<()> {
        info!("Waiting for client finalization sequence...");

        loop {
            let (pdu_type_code, body) = self
                .read_rdp_pdu()
                .await
                .context("Failed to read client finalization PDU")?;

            if pdu_type_code != (PDUTYPE_DATAPDU & 0x0F) {
                // Not a Data PDU — could be an echo of Confirm Active or similar
                debug!(
                    "Finalization: received non-data PDU type_code={}, ignoring",
                    pdu_type_code
                );
                continue;
            }

            // Parse TS_SHAREDATAHEADER from the body:
            //   shareId(4) + pad(1) + streamId(1) + uncompressedLength(2) + pduType2(1) + ...
            if body.len() < 9 {
                debug!(
                    "Finalization: DataPDU body too short ({} bytes), skipping",
                    body.len()
                );
                continue;
            }
            let pdu_type2 = body[8];

            match pdu_type2 {
                PDUTYPE2_SYNCHRONIZE => {
                    debug!("Finalization: received client Synchronize, no response yet");
                }
                PDUTYPE2_CONTROL => {
                    // TS_CONTROL_PDU payload starts at offset 12 in the body (after Share Data Hdr)
                    // action (u16 LE) is the first 2 bytes of the Control PDU payload
                    if body.len() < 14 {
                        debug!("Finalization: Control PDU body too short, skipping");
                        continue;
                    }
                    let action = u16::from_le_bytes([body[12], body[13]]);
                    match action {
                        CTRLACTION_COOPERATE => {
                            debug!("Finalization: received Control Cooperate, no response yet");
                        }
                        CTRLACTION_REQUEST_CONTROL => {
                            debug!(
                                "Finalization: received Control Request — sending Synchronize + Cooperate + GrantedControl"
                            );

                            // Synchronize
                            let sync_payload = build_finalization_pdu(
                                FinalizationPduType::Synchronize,
                                self.user_id,
                            )
                            .context("Failed to build Synchronize PDU")?;
                            self.write_rdp_data_pdu(PDUTYPE2_SYNCHRONIZE, &sync_payload)
                                .await
                                .context("Failed to send Synchronize PDU")?;
                            debug!("Sent Synchronize");

                            // Cooperate
                            let coop_payload = build_finalization_pdu(
                                FinalizationPduType::Cooperate,
                                self.user_id,
                            )
                            .context("Failed to build Cooperate PDU")?;
                            self.write_rdp_data_pdu(PDUTYPE2_CONTROL, &coop_payload)
                                .await
                                .context("Failed to send Cooperate PDU")?;
                            debug!("Sent Cooperate");

                            // Granted Control
                            let granted_payload = build_finalization_pdu(
                                FinalizationPduType::ControlGrantedControl,
                                self.user_id,
                            )
                            .context("Failed to build Granted Control PDU")?;
                            self.write_rdp_data_pdu(PDUTYPE2_CONTROL, &granted_payload)
                                .await
                                .context("Failed to send Granted Control PDU")?;
                            debug!("Sent GrantedControl");
                        }
                        other => {
                            debug!("Finalization: received Control action={}, ignoring", other);
                        }
                    }
                }
                PDUTYPE2_FONTLIST => {
                    debug!(
                        "Finalization: received FontList — sending FontMap and completing finalization"
                    );

                    let fontmap_payload =
                        build_finalization_pdu(FinalizationPduType::FontMap, self.user_id)
                            .context("Failed to build FontMap PDU")?;
                    self.write_rdp_data_pdu(PDUTYPE2_FONTMAP, &fontmap_payload)
                        .await
                        .context("Failed to send FontMap PDU")?;
                    debug!("Sent FontMap");

                    info!("Finalization complete");
                    break;
                }
                other => {
                    debug!("Finalization: ignoring pduType2={}", other);
                }
            }
        }

        Ok(())
    }

    /// Main event loop
    async fn main_loop(&mut self) -> Result<()> {
        info!("Entering main event loop - polling application output and client input");

        let content_notify = self.app.content_notify();

        let mut buf = vec![0u8; 8192];
        let mut packet_count = 0;
        let mut render_pending = false;
        let render_interval = tokio::time::Duration::from_millis(16); // ~60fps cap
        let mut render_timer = tokio::time::interval(render_interval);
        render_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Suppress rendering during shell startup to avoid capturing
        // transient output like zsh's PROMPT_SP '%' marker
        let startup = tokio::time::Instant::now();
        let startup_grace = tokio::time::Duration::from_millis(1500);

        loop {
            tokio::select! {
                // Branch 1: Client socket data
                result = self.stream.as_mut().unwrap().read(&mut buf) => {
                    let n = match result {
                        Ok(0) => {
                            info!("Client disconnected gracefully");
                            break;
                        }
                        Ok(n) => n,
                        Err(e) => {
                            warn!("Stream read error (disconnecting): {}", e);
                            break;
                        }
                    };

                    packet_count += 1;

                    // Check if this is fastpath (byte 0 != 0x03) or slow-path (TPKT)
                    if buf[0] != TPKT_VERSION {
                        // Fastpath input — parse directly
                        if let Err(e) = self.handle_fastpath_input(&buf[..n]).await {
                            warn!("Fastpath input error (continuing): {}", e);
                        }
                        continue;
                    }

                    // Slow-path: parse RDP PDU and handle input
                    match self.extract_rdp_data(&buf[..n]) {
                        Ok((pdu_type2, data)) => {
                            // pduType2=28 is PDUTYPE2_INPUT
                            if pdu_type2 == 28 {
                                match InputEvent::parse_input_events(&data) {
                                    Ok(events) => {
                                        for event in events {
                                            if let Err(e) = self.app.on_input(event) {
                                                warn!("Input event error: {}", e);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        debug!("Failed to parse slow-path input: {}", e);
                                    }
                                }
                            } else {
                                debug!("Slow-path PDU pdu_type2={} (ignored)", pdu_type2);
                            }
                        }
                        Err(e) => {
                            debug!("Failed to extract RDP data: {}", e);
                        }
                    }
                }

                // Branch 2: Application signals new content
                _ = content_notify.notified() => {
                    render_pending = true;
                }

                // Branch 3: Render timer — send accumulated changes to client
                _ = render_timer.tick(), if render_pending => {
                    // During startup grace period, keep buffering but don't send
                    if startup.elapsed() < startup_grace {
                        continue;
                    }
                    render_pending = false;

                    match self.app.render(&mut self.framebuffer) {
                        Ok(changed) => {
                            if changed {
                                if let Err(e) = self.send_screen_update().await {
                                    warn!("Screen update error (continuing): {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Render error (continuing): {}", e);
                        }
                    }
                }
            }
        }

        info!("Main event loop exited after {} packets", packet_count);
        Ok(())
    }

    /// Send screen update — only sends tiles that changed since last frame.
    /// All dirty tiles are batched into a single TCP write for minimum latency.
    async fn send_screen_update(&mut self) -> Result<()> {
        let rgba_data = self.framebuffer.as_rgba();
        let target_bpp = self.target_bpp;
        let w = self.width as usize;
        let h = self.height as usize;
        let tile_size: usize = 64;

        let is_first_frame = self.prev_frame.len() != rgba_data.len();

        // Phase 1: Build all dirty tile PDUs into a single write buffer
        let mut wire_buf: Vec<u8> = Vec::new();
        let mut tiles_sent = 0u32;

        let mut ty = 0usize;
        while ty < h {
            let th = tile_size.min(h - ty);
            let mut tx = 0usize;
            while tx < w {
                let tw = tile_size.min(w - tx);

                let dirty = if is_first_frame {
                    true
                } else {
                    let mut changed = false;
                    'outer: for row in ty..ty + th {
                        let row_start = (row * w + tx) * 4;
                        let row_end = row_start + tw * 4;
                        if row_end <= rgba_data.len()
                            && row_end <= self.prev_frame.len()
                            && rgba_data[row_start..row_end] != self.prev_frame[row_start..row_end]
                        {
                            changed = true;
                            break 'outer;
                        }
                    }
                    changed
                };

                if dirty {
                    let mut tile_rgba = Vec::with_capacity(tw * th * 4);
                    for row in ty..ty + th {
                        let row_start = (row * w + tx) * 4;
                        let row_end = row_start + tw * 4;
                        tile_rgba.extend_from_slice(&rgba_data[row_start..row_end]);
                    }

                    let rect = BitmapRectangle::from_rgba(
                        tx as u16, ty as u16, tw as u16, th as u16, &tile_rgba, target_bpp,
                    )?;
                    let tile_update = BitmapUpdate::new(rect);
                    let update_data = tile_update.encode()?;

                    // Build the full TPKT-wrapped MCS PDU for this tile
                    let pdu_bytes = self.build_rdp_data_pdu(PDUTYPE2_UPDATE, &update_data);
                    wire_buf.extend_from_slice(&pdu_bytes);
                    tiles_sent += 1;
                }

                tx += tile_size;
            }
            ty += tile_size;
        }

        // Phase 2: Single write + flush for all tiles
        if !wire_buf.is_empty() {
            let stream = self.stream.as_mut().unwrap();
            stream
                .write_all(&wire_buf)
                .await
                .context("Failed to write batched tile update")?;
            stream
                .flush()
                .await
                .context("Failed to flush tile update")?;
            debug!(
                "Screen update: {} dirty tiles sent ({} bytes, 1 write)",
                tiles_sent,
                wire_buf.len()
            );
        }

        self.prev_frame.clear();
        self.prev_frame.extend_from_slice(rgba_data);

        Ok(())
    }
}

/// Parse TS_INFO_PACKET (MS-RDPBCGR 2.2.1.11.1.1) to extract username and password.
///
/// Layout (18-byte header):
/// `codePage(4) + flags(4) + cbDomain(2) + cbUserName(2) + cbPassword(2) + cbAlternateShell(2) + cbWorkingDir(2)`
/// followed by: domain, userName, password (each null-terminated, sizes from cb fields).
///
/// If INFO_UNICODE (0x0010) is set in flags, strings are UTF-16LE; otherwise ANSI.
fn parse_ts_info_packet(data: &[u8]) -> (String, String) {
    if data.len() < 18 {
        return (String::new(), String::new());
    }

    let flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let is_unicode = (flags & 0x0010) != 0; // INFO_UNICODE

    let cb_domain = u16::from_le_bytes([data[8], data[9]]) as usize;
    let cb_username = u16::from_le_bytes([data[10], data[11]]) as usize;
    let cb_password = u16::from_le_bytes([data[12], data[13]]) as usize;

    // Strings start after the 18-byte header
    // Each string is cb* bytes + null terminator (2 bytes for Unicode, 1 for ANSI)
    let null_len = if is_unicode { 2 } else { 1 };
    let mut pos = 18;

    // Skip domain
    pos += cb_domain + null_len;
    if pos > data.len() {
        return (String::new(), String::new());
    }

    // Read username
    let username = if pos + cb_username <= data.len() {
        decode_rdp_string(&data[pos..pos + cb_username], is_unicode)
    } else {
        String::new()
    };
    pos += cb_username + null_len;

    // Read password
    let password = if pos + cb_password <= data.len() {
        decode_rdp_string(&data[pos..pos + cb_password], is_unicode)
    } else {
        String::new()
    };

    (username, password)
}

/// Decode an RDP string (UTF-16LE or ANSI) to a Rust String.
fn decode_rdp_string(data: &[u8], is_unicode: bool) -> String {
    if is_unicode {
        let u16s: Vec<u16> = data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u16s)
    } else {
        String::from_utf8_lossy(data).into_owned()
    }
    .trim_end_matches('\0')
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::pdu::{
        PDUTYPE_DATAPDU, PDUTYPE2_SYNCHRONIZE, PDUTYPE2_UPDATE, SHARE_ID, TS_PROTOCOL_VERSION,
    };

    #[test]
    fn test_build_share_data_pdu_structure() {
        let user_id: u16 = 1002;
        let pdu_type2: u8 = PDUTYPE2_UPDATE;
        let payload = vec![0xAA, 0xBB, 0xCC];

        let pdu = RdpSession::build_share_data_pdu(user_id, pdu_type2, &payload);

        // Total length = 18 (headers) + 3 (payload) = 21
        assert_eq!(pdu.len(), 21);

        // Share Control Header: total length (u16 LE)
        let total_len = u16::from_le_bytes([pdu[0], pdu[1]]);
        assert_eq!(total_len, 21);

        // PDU type: PDUTYPE_DATAPDU | TS_PROTOCOL_VERSION
        let pdu_type = u16::from_le_bytes([pdu[2], pdu[3]]);
        assert_eq!(pdu_type, PDUTYPE_DATAPDU | TS_PROTOCOL_VERSION);

        // PDU source = user_id
        let source = u16::from_le_bytes([pdu[4], pdu[5]]);
        assert_eq!(source, user_id);

        // Share Data Header: share ID (4 bytes)
        let share_id = u32::from_le_bytes([pdu[6], pdu[7], pdu[8], pdu[9]]);
        assert_eq!(share_id, SHARE_ID);

        // pdu_type2 is at offset 14 within the PDU
        assert_eq!(pdu[14], pdu_type2);

        // Payload at the end
        assert_eq!(&pdu[18..], &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_build_share_data_pdu_empty_payload() {
        let pdu = RdpSession::build_share_data_pdu(1002, PDUTYPE2_SYNCHRONIZE, &[]);

        // Total length = 18 (headers) + 0 (payload)
        assert_eq!(pdu.len(), 18);
        let total_len = u16::from_le_bytes([pdu[0], pdu[1]]);
        assert_eq!(total_len, 18);
    }

    #[test]
    fn test_build_share_data_pdu_large_payload() {
        let payload = vec![0xFF; 4096];
        let pdu = RdpSession::build_share_data_pdu(1002, PDUTYPE2_UPDATE, &payload);

        assert_eq!(pdu.len(), 18 + 4096);
        let total_len = u16::from_le_bytes([pdu[0], pdu[1]]);
        assert_eq!(total_len, (18 + 4096) as u16);

        // Verify payload is intact at the end
        assert_eq!(&pdu[18..], &payload[..]);
    }

    #[test]
    fn test_parse_ts_info_packet_unicode() {
        // Build a minimal TS_INFO_PACKET with Unicode strings
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0u32.to_le_bytes()); // codePage
        pkt.extend_from_slice(&0x0010u32.to_le_bytes()); // flags: INFO_UNICODE
        // domain = "" (0 bytes), user = "admin" (10 bytes UTF-16), password = "secret" (12 bytes)
        let user_utf16: Vec<u8> = "admin"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let pass_utf16: Vec<u8> = "secret"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        pkt.extend_from_slice(&0u16.to_le_bytes()); // cbDomain = 0
        pkt.extend_from_slice(&(user_utf16.len() as u16).to_le_bytes()); // cbUserName
        pkt.extend_from_slice(&(pass_utf16.len() as u16).to_le_bytes()); // cbPassword
        pkt.extend_from_slice(&0u16.to_le_bytes()); // cbAlternateShell
        pkt.extend_from_slice(&0u16.to_le_bytes()); // cbWorkingDir
        // domain (0 bytes + null terminator)
        pkt.extend_from_slice(&[0, 0]); // Unicode null
        // userName
        pkt.extend_from_slice(&user_utf16);
        pkt.extend_from_slice(&[0, 0]); // Unicode null
        // password
        pkt.extend_from_slice(&pass_utf16);
        pkt.extend_from_slice(&[0, 0]); // Unicode null

        let (user, pass) = parse_ts_info_packet(&pkt);
        assert_eq!(user, "admin");
        assert_eq!(pass, "secret");
    }

    #[test]
    fn test_parse_ts_info_packet_ansi() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0u32.to_le_bytes()); // codePage
        pkt.extend_from_slice(&0u32.to_le_bytes()); // flags: no INFO_UNICODE = ANSI
        let user = b"testuser";
        let pass = b"testpass";
        pkt.extend_from_slice(&0u16.to_le_bytes()); // cbDomain = 0
        pkt.extend_from_slice(&(user.len() as u16).to_le_bytes());
        pkt.extend_from_slice(&(pass.len() as u16).to_le_bytes());
        pkt.extend_from_slice(&0u16.to_le_bytes()); // cbAlternateShell
        pkt.extend_from_slice(&0u16.to_le_bytes()); // cbWorkingDir
        pkt.push(0); // domain null (ANSI)
        pkt.extend_from_slice(user);
        pkt.push(0); // null
        pkt.extend_from_slice(pass);
        pkt.push(0); // null

        let (u, p) = parse_ts_info_packet(&pkt);
        assert_eq!(u, "testuser");
        assert_eq!(p, "testpass");
    }

    #[test]
    fn test_parse_ts_info_packet_too_short() {
        let (u, p) = parse_ts_info_packet(&[0; 10]);
        assert_eq!(u, "");
        assert_eq!(p, "");
    }

    #[test]
    fn test_decode_rdp_string_unicode() {
        let data: Vec<u8> = "hello"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        assert_eq!(decode_rdp_string(&data, true), "hello");
    }

    #[test]
    fn test_decode_rdp_string_ansi() {
        assert_eq!(decode_rdp_string(b"world", false), "world");
    }
}
