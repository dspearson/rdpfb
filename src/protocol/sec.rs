/// Security Layer
///
/// Handles GCC (Generic Conference Control) data and security negotiation.
/// Reference: [MS-RDPBCGR] Section 2.2.1.3 Client MCS Connect Initial PDU with GCC Conference Create Request
///
/// RDP-level encryption is not used; transport security is provided by TLS.
use anyhow::{Context, Result, bail};
use bytes::{BufMut, BytesMut};
use tracing::{debug, error, info, warn};

use super::pdu::*;

/// Client information extracted from GCC data
#[derive(Debug, Default)]
pub struct ClientInfo {
    pub client_build: u32,
    pub client_name: String,
    pub desktop_width: u16,
    pub desktop_height: u16,
    pub color_depth: u16,
    pub keyboard_layout: u32,
    pub keyboard_type: u32,
    pub channels: Vec<ChannelDef>,
}

/// Virtual channel definition
#[derive(Debug, Clone)]
pub struct ChannelDef {
    pub name: String,
    pub options: u32,
    pub channel_id: u16,
}

/// Parse GCC Conference Create Request from client
pub fn parse_gcc_create_request(data: &[u8]) -> Result<ClientInfo> {
    debug!("parse_gcc_create_request: {} bytes", data.len());
    let mut info = ClientInfo::default();

    // Skip T.124 GCC header
    // Object identifier for ConnectPDU
    if data.len() < 23 {
        error!(
            "GCC data too short: {} bytes (need at least 23)",
            data.len()
        );
        bail!("GCC data too short");
    }

    debug!("GCC header (first 23 bytes): {:02X?}", &data[..23]);

    // Skip to user data (after ConnectPDU header)
    let mut pos = 23;
    debug!(
        "Skipped GCC header, parsing user data blocks from offset {}",
        pos
    );

    // Parse user data blocks
    let mut block_count = 0;
    while pos + 4 <= data.len() {
        // Read block type (u16 LE)
        let block_type = u16::from_le_bytes([data[pos], data[pos + 1]]);
        // Read block length (u16 LE)
        let block_length = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;

        block_count += 1;
        debug!(
            "GCC block #{}: type=0x{:04X}, length={} bytes at offset {}",
            block_count, block_type, block_length, pos
        );

        pos += 4;

        if pos + block_length - 4 > data.len() {
            warn!(
                "GCC block extends beyond data: type=0x{:04X}, length={}",
                block_type, block_length
            );
            break;
        }

        let block_data = &data[pos..pos + block_length - 4];

        match block_type {
            CS_CORE => {
                info!("Parsing CS_CORE (Client Core Data)");
                parse_cs_core(&mut info, block_data)?;
            }
            CS_SECURITY => {
                info!("Parsing CS_SECURITY (Client Security Data)");
                // RDP-level encryption methods are not used; TLS handles transport security
            }
            CS_NET => {
                info!("Parsing CS_NET (Client Network Data)");
                parse_cs_net(&mut info, block_data)?;
            }
            CS_CLUSTER => {
                info!("Received CS_CLUSTER (Client Cluster Data) - skipping");
            }
            CS_MONITOR => {
                info!("Received CS_MONITOR (Client Monitor Data) - skipping");
            }
            CS_MCS_MSGCHANNEL => {
                info!("Received CS_MCS_MSGCHANNEL - skipping");
            }
            CS_MONITOR_EX => {
                info!("Received CS_MONITOR_EX - skipping");
            }
            CS_MULTITRANSPORT => {
                info!("Received CS_MULTITRANSPORT - skipping");
            }
            _ => {
                warn!("Unknown GCC block type: 0x{:04X}", block_type);
            }
        }

        pos += block_length - 4;
    }

    debug!("Parsed {} GCC blocks total", block_count);
    info!(
        "GCC parsed - Client: {}x{} @ {}bpp, build {}, keyboard layout 0x{:08X}, {} channels",
        info.desktop_width,
        info.desktop_height,
        info.color_depth,
        info.client_build,
        info.keyboard_layout,
        info.channels.len()
    );

    Ok(info)
}

/// Parse CS_CORE block
fn parse_cs_core(info: &mut ClientInfo, data: &[u8]) -> Result<()> {
    debug!("parse_cs_core: {} bytes", data.len());
    if data.len() < 128 {
        error!(
            "CS_CORE data too short: {} bytes (need at least 128)",
            data.len()
        );
        bail!("CS_CORE block too short");
    }

    let mut pos = 0;

    // Version (u32 LE) - offset 0
    let _version = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;

    // Desktop width (u16 LE) - offset 4
    info.desktop_width = u16::from_le_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    // Desktop height (u16 LE) - offset 6
    info.desktop_height = u16::from_le_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    // Color depth (u16 LE) - offset 8
    let raw_color_depth = u16::from_le_bytes([data[pos], data[pos + 1]]);
    // Decode RDP color depth constants to actual BPP
    // RNS_UD_COLOR_4BPP = 0xCA00, RNS_UD_COLOR_8BPP = 0xCA01, etc.
    info.color_depth = match raw_color_depth {
        0xCA00 => 4,  // RNS_UD_COLOR_4BPP
        0xCA01 => 8,  // RNS_UD_COLOR_8BPP
        0xCA02 => 15, // RNS_UD_COLOR_16BPP_555
        0xCA03 => 16, // RNS_UD_COLOR_16BPP_565
        0xCA04 => 24, // RNS_UD_COLOR_24BPP
        _ => {
            debug!(
                "Unknown color depth encoding 0x{:04X}, defaulting to 16 bpp",
                raw_color_depth
            );
            16 // Default to 16 bpp
        }
    };
    pos += 2;

    // SAS sequence (u16 LE) - skip
    pos += 2;

    // Keyboard layout (u32 LE) - offset 12
    info.keyboard_layout =
        u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;

    // Client build (u32 LE) - offset 16
    info.client_build =
        u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;

    // Client name (32 bytes, null-terminated UTF-16LE) - offset 20
    let mut client_name_bytes = Vec::new();
    for i in 0..32 {
        if pos + i * 2 + 1 < data.len() {
            let c = u16::from_le_bytes([data[pos + i * 2], data[pos + i * 2 + 1]]);
            if c == 0 {
                break;
            }
            client_name_bytes.push(c);
        }
    }
    info.client_name = String::from_utf16_lossy(&client_name_bytes);
    pos += 64;

    // Keyboard type (u32 LE) - offset 84 (with current 64-byte clientName advance)
    if pos + 4 <= data.len() {
        info.keyboard_type =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    }

    // Three-stage colour depth resolution per MS-RDPBCGR
    //
    // CS_CORE layout (absolute offsets from block start):
    //   +128: postBeta2ColorDepth (u16 LE) — Stage 2
    //   +130: clientProductId (u16 LE)
    //   +132: serialNumber (u32 LE)
    //   +136: highColorDepth (u16 LE) — Stage 3
    //
    // Stage 1 already applied above (colorDepth field at offset +8).
    // Later stages override earlier ones if the block is long enough.

    // Stage 2: postBeta2ColorDepth at absolute offset 128
    const OFFSET_POST_BETA2: usize = 128;
    if data.len() >= OFFSET_POST_BETA2 + 2 {
        let raw = u16::from_le_bytes([data[OFFSET_POST_BETA2], data[OFFSET_POST_BETA2 + 1]]);
        let depth2 = match raw {
            0xCA00 => Some(4u16),
            0xCA01 => Some(8),
            0xCA02 => Some(15),
            0xCA03 => Some(16),
            0xCA04 => Some(24),
            _ => None,
        };
        if let Some(d) = depth2 {
            debug!(
                "CS_CORE Stage 2 (postBeta2ColorDepth=0x{:04X}): {} bpp overrides {} bpp",
                raw, d, info.color_depth
            );
            info.color_depth = d;
        }
    }

    // Stage 3: highColorDepth at absolute offset 136
    const OFFSET_HIGH_COLOR: usize = 136;
    if data.len() >= OFFSET_HIGH_COLOR + 2 {
        let high_color_depth =
            u16::from_le_bytes([data[OFFSET_HIGH_COLOR], data[OFFSET_HIGH_COLOR + 1]]);
        if high_color_depth != 0 {
            debug!(
                "CS_CORE Stage 3 (highColorDepth={}): overrides {} bpp",
                high_color_depth, info.color_depth
            );
            info.color_depth = high_color_depth;
        }
    }

    debug!(
        "CS_CORE: client={}, {}x{} @ {}bpp (3-stage resolved)",
        info.client_name, info.desktop_width, info.desktop_height, info.color_depth
    );

    Ok(())
}

/// Parse CS_NET block
fn parse_cs_net(info: &mut ClientInfo, data: &[u8]) -> Result<()> {
    if data.len() < 4 {
        return Ok(()); // No channels
    }

    let mut pos = 0;

    // Channel count (u32 LE)
    let channel_count =
        u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    pos += 4;

    debug!("CS_NET: {} channels requested", channel_count);

    // Parse channel definitions (12 bytes each)
    for i in 0..channel_count {
        if pos + 12 > data.len() {
            break;
        }

        // Channel name (8 bytes, null-terminated ASCII)
        let mut name_bytes = Vec::new();
        for j in 0..8 {
            let c = data[pos + j];
            if c == 0 {
                break;
            }
            name_bytes.push(c);
        }
        let name = String::from_utf8_lossy(&name_bytes).to_string();
        pos += 8;

        // Channel options (u32 LE)
        let options = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;

        // Assign channel ID (base + index)
        let channel_id = MCS_GLOBAL_CHANNEL + 1 + i as u16;

        info.channels.push(ChannelDef {
            name,
            options,
            channel_id,
        });

        debug!(
            "  Channel {}: name='{}', options=0x{:08X}, id={}",
            i, info.channels[i].name, info.channels[i].options, info.channels[i].channel_id
        );
    }

    Ok(())
}

/// Build GCC Conference Create Response for server
pub fn build_gcc_create_response(client_info: &ClientInfo) -> Result<Vec<u8>> {
    debug!(
        "build_gcc_create_response: building response for client {}x{} @ {}bpp",
        client_info.desktop_width, client_info.desktop_height, client_info.color_depth
    );
    let mut buf = BytesMut::with_capacity(512);

    // T.124 GCC ConnectData header
    // Minimal T.124 GCC ConnectData encoding (not full ASN.1)

    // Object identifier for T.124
    buf.put_slice(&[
        0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01, // ConnectPDU header
        0x2a, 0x14, 0x76, 0x0a, 0x01, 0x01, 0x00, 0x01, 0xc0, 0x00, // H.221 key
        0x4d, 0x63, 0x44, 0x6e, // "McDn" signature
    ]);
    debug!("Added T.124 GCC ConnectData header (21 bytes)");

    // Build server user data
    debug!("Building server user data blocks...");
    let server_data = build_server_data(client_info).context("Failed to build server data")?;
    debug!("Server data blocks: {} bytes", server_data.len());

    // Length of user data (PER encoded length determinant)
    // For lengths < 128: single byte
    // For lengths >= 128 and < 16384: high 2 bits = 10, followed by 14-bit length (big-endian)
    let user_data_len = server_data.len();
    if user_data_len < 128 {
        buf.put_u8(user_data_len as u8);
        debug!(
            "Added user data length: {} (single byte PER)",
            user_data_len
        );
    } else if user_data_len < 16384 {
        let encoded = (user_data_len as u16) | 0x8000;
        buf.put_u16(encoded); // Big-endian!
        debug!(
            "Added user data length: {} (2-byte PER: 0x{:04X})",
            user_data_len, encoded
        );
    } else {
        bail!("User data too large: {}", user_data_len);
    }

    // Append server data
    buf.extend_from_slice(&server_data);

    debug!(
        "GCC Conference Create Response built: {} bytes total",
        buf.len()
    );
    Ok(buf.to_vec())
}

/// Build server user data blocks
fn build_server_data(client_info: &ClientInfo) -> Result<Vec<u8>> {
    let mut buf = BytesMut::with_capacity(256);

    // SC_CORE - Server Core Data
    let sc_core = build_sc_core(client_info)?;
    buf.put_u16_le(SC_CORE);
    buf.put_u16_le((sc_core.len() + 4) as u16);
    buf.extend_from_slice(&sc_core);

    // SC_SECURITY - Server Security Data
    let sc_security = build_sc_security()?;
    buf.put_u16_le(SC_SECURITY);
    buf.put_u16_le((sc_security.len() + 4) as u16);
    buf.extend_from_slice(&sc_security);

    // SC_NET - Server Network Data
    if !client_info.channels.is_empty() {
        let sc_net = build_sc_net(client_info)?;
        buf.put_u16_le(SC_NET);
        buf.put_u16_le((sc_net.len() + 4) as u16);
        buf.extend_from_slice(&sc_net);
    }

    Ok(buf.to_vec())
}

/// Build SC_CORE
fn build_sc_core(_client_info: &ClientInfo) -> Result<Vec<u8>> {
    let mut buf = BytesMut::with_capacity(16);

    // Version (u32 LE) - RDP 5.0 = 0x00080001
    buf.put_u32_le(0x00080004); // RDP 5.2

    // Requested protocol
    buf.put_u32_le(PROTOCOL_RDP);

    // Early capability flags (u32 LE) - none
    buf.put_u32_le(0);

    debug!("SC_CORE: version=0x00080004, protocol=PROTOCOL_RDP");

    Ok(buf.to_vec())
}

/// Build SC_SECURITY
fn build_sc_security() -> Result<Vec<u8>> {
    let mut buf = BytesMut::with_capacity(8);

    // Encryption method (u32 LE) - NONE for no-encryption path
    buf.put_u32_le(0); // ENCRYPTION_METHOD_NONE

    // Encryption level (u32 LE) - NONE for no-encryption path
    buf.put_u32_le(0); // ENCRYPTION_LEVEL_NONE

    // Total body = 8 bytes; header (type u16 + length u16) = 4 bytes; total SC_SECURITY = 12 bytes

    debug!("SC_SECURITY: encryption=NONE, level=NONE (12 bytes total)");

    Ok(buf.to_vec())
}

/// Build SC_NET
fn build_sc_net(client_info: &ClientInfo) -> Result<Vec<u8>> {
    let mut buf = BytesMut::with_capacity(128);

    // MCS channel ID (u16 LE) - IO channel
    buf.put_u16_le(MCS_GLOBAL_CHANNEL);

    // Channel count (u16 LE)
    buf.put_u16_le(client_info.channels.len() as u16);

    // Channel IDs
    for channel in &client_info.channels {
        buf.put_u16_le(channel.channel_id);
    }

    // Pad to multiple of 2
    if !buf.len().is_multiple_of(2) {
        buf.put_u8(0);
    }

    debug!("SC_NET: {} channels", client_info.channels.len());

    Ok(buf.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_gcc_response() {
        let client_info = ClientInfo {
            desktop_width: 1024,
            desktop_height: 768,
            color_depth: 16,
            ..Default::default()
        };

        let response = build_gcc_create_response(&client_info).unwrap();
        assert!(response.len() > 20);
    }
}
