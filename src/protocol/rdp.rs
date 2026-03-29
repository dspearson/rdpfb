/// RDP Protocol Layer
///
/// Implements RDP PDU processing, capability exchange, and finalization sequence.
/// Reference: [MS-RDPBCGR] Sections 1.3.1.1 (Connection Sequence), 2.2.1 (PDUs)
///
/// Connection flow after MCS:
/// 1. Client Info PDU (from client)
/// 2. Server Demand Active PDU (capabilities)
/// 3. Client Confirm Active PDU
/// 4. Finalization: Synchronize → Cooperate → Control → FontMap
use anyhow::{Context, Result, bail};
use bytes::{BufMut, BytesMut};
use tracing::{debug, error};

use super::pdu::*;

/// Server Demand Active PDU
///
/// Contains server capabilities and initiates capability exchange.
#[derive(Debug)]
pub struct DemandActivePdu {
    pub share_id: u32,
    pub source_descriptor: String,
    pub capabilities: Vec<CapabilitySet>,
}

impl DemandActivePdu {
    /// Create a new Demand Active PDU with required capabilities
    pub fn new_minimal(width: u16, height: u16, color_depth: u16) -> Self {
        let capabilities = vec![
            // CAPSTYPE_SHARE Capability Set (must be first)
            CapabilitySet::Share(ShareCapability {
                node_id: 1002,
                pad2octets: 0xB5E2,
            }),
            // General Capability Set
            CapabilitySet::General(GeneralCapability {
                os_major_type: 1, // Windows
                os_minor_type: 3,
                protocol_version: 0x0200,
                extra_flags: 0x0001, // FASTPATH_OUTPUT_SUPPORTED
            }),
            // Bitmap Capability Set
            CapabilitySet::Bitmap(BitmapCapability {
                preferred_bpp: color_depth,
                desktop_width: width,
                desktop_height: height,
                desktop_resize_flag: 0, // No resize
            }),
            // Order Capability Set (bitmap updates only, no drawing orders)
            CapabilitySet::Order(OrderCapability {
                support_flags: 0, // No order support
            }),
            // Pointer Capability Set
            CapabilitySet::Pointer(PointerCapability {
                color_pointer_flag: 1,
                color_pointer_cache_size: 25,
                pointer_cache_size: 25,
            }),
            // Input Capability Set
            CapabilitySet::Input(InputCapability {
                input_flags: INPUT_FLAG_SCANCODES | INPUT_FLAG_UNICODE,
                keyboard_layout: 0,
            }),
            // Font Capability Set (mandatory for most RDP clients)
            CapabilitySet::Font(FontCapability {
                font_support_flags: 1, // FONTSUPPORT_FONTLIST
            }),
        ];

        DemandActivePdu {
            share_id: 0x000103EA, // Arbitrary share ID
            source_descriptor: "rdpterm".to_string(),
            capabilities,
        }
    }

    /// Encode Demand Active PDU
    pub fn encode(&self) -> Result<Vec<u8>> {
        debug!(
            "DemandActivePdu::encode: share_id=0x{:08X}, source='{}', {} capabilities",
            self.share_id,
            self.source_descriptor,
            self.capabilities.len()
        );
        let mut buf = BytesMut::with_capacity(2048);

        // Share ID (u32 LE)
        buf.put_u32_le(self.share_id);

        // Length of source descriptor (u16 LE) - includes null terminator
        let source_bytes = self.source_descriptor.as_bytes();
        buf.put_u16_le((source_bytes.len() + 1) as u16);

        // lengthCombinedCapabilities (u16 LE) - placeholder, will fix later
        let combined_caps_len_pos = buf.len();
        buf.put_u16_le(0);

        // Source descriptor (null-terminated ASCII)
        buf.extend_from_slice(source_bytes);
        buf.put_u8(0); // Null terminator

        // Number of capabilities (u16 LE)
        buf.put_u16_le(self.capabilities.len() as u16);

        // pad2Octets (2 bytes) - required padding before capability sets
        buf.put_u16_le(0);

        // Mark start of capability sets for length calculation
        let caps_start = buf.len();

        // Capability sets
        for (i, cap) in self.capabilities.iter().enumerate() {
            debug!(
                "Encoding capability {}/{}: {:?}",
                i + 1,
                self.capabilities.len(),
                match cap {
                    CapabilitySet::Share(_) => "Share",
                    CapabilitySet::General(_) => "General",
                    CapabilitySet::Bitmap(_) => "Bitmap",
                    CapabilitySet::Order(_) => "Order",
                    CapabilitySet::Pointer(_) => "Pointer",
                    CapabilitySet::Input(_) => "Input",
                    CapabilitySet::Font(_) => "Font",
                }
            );
            let cap_data = cap
                .encode()
                .context(format!("Failed to encode capability {}", i + 1))?;
            debug!("Capability {} encoded: {} bytes", i + 1, cap_data.len());
            buf.extend_from_slice(&cap_data);
        }

        // Fix lengthCombinedCapabilities BEFORE adding sessionId
        // It includes: numberCapabilities (2) + pad2Octets (2) + capability sets (NOT sessionId)
        let combined_caps_len = buf.len() - caps_start + 4; // +4 for numberCapabilities + pad2Octets before caps_start
        buf[combined_caps_len_pos..combined_caps_len_pos + 2]
            .copy_from_slice(&(combined_caps_len as u16).to_le_bytes());

        // Session ID (u32 LE)
        buf.put_u32_le(0);

        debug!(
            "Demand Active PDU encoded: {} capabilities, {} bytes total, combined_caps_len={}",
            self.capabilities.len(),
            buf.len(),
            combined_caps_len
        );

        Ok(buf.to_vec())
    }
}

/// Capability Set types
#[derive(Debug)]
pub enum CapabilitySet {
    Share(ShareCapability),
    General(GeneralCapability),
    Bitmap(BitmapCapability),
    Order(OrderCapability),
    Pointer(PointerCapability),
    Input(InputCapability),
    Font(FontCapability),
}

impl CapabilitySet {
    /// Encode a capability set
    fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::with_capacity(128);

        match self {
            CapabilitySet::Share(cap) => {
                buf.put_u16_le(CAPSTYPE_SHARE);
                let start = buf.len();
                buf.put_u16_le(0); // Length placeholder

                buf.put_u16_le(cap.node_id);
                buf.put_u16_le(cap.pad2octets);

                // Fix length
                let length = buf.len() - start + 2;
                buf[start..start + 2].copy_from_slice(&(length as u16).to_le_bytes());
            }
            CapabilitySet::General(cap) => {
                buf.put_u16_le(CAPSTYPE_GENERAL);
                let start = buf.len();
                buf.put_u16_le(0); // Length placeholder

                buf.put_u16_le(cap.os_major_type);
                buf.put_u16_le(cap.os_minor_type);
                buf.put_u16_le(cap.protocol_version);
                buf.put_u16_le(0); // Pad
                buf.put_u16_le(0); // General compression types
                buf.put_u16_le(cap.extra_flags);
                buf.put_u16_le(0); // Update capability flag
                buf.put_u16_le(0); // Remote unshare flag
                buf.put_u16_le(0); // General compression level
                buf.put_u8(0); // Refresh rect support
                buf.put_u8(0); // Suppress output support

                // Fix length
                let length = buf.len() - start + 2;
                buf[start..start + 2].copy_from_slice(&(length as u16).to_le_bytes());
            }
            CapabilitySet::Bitmap(cap) => {
                buf.put_u16_le(CAPSTYPE_BITMAP);
                let start = buf.len();
                buf.put_u16_le(0); // Length placeholder

                buf.put_u16_le(cap.preferred_bpp);
                buf.put_u16_le(1); // Receive 1 BPP
                buf.put_u16_le(1); // Receive 4 BPP
                buf.put_u16_le(1); // Receive 8 BPP
                buf.put_u16_le(cap.desktop_width);
                buf.put_u16_le(cap.desktop_height);
                buf.put_u16_le(0); // pad2octets
                buf.put_u16_le(cap.desktop_resize_flag); // desktopResizeFlag
                buf.put_u16_le(1); // bitmapCompressionFlag
                buf.put_u8(0); // highColorFlags (u8, per MS-RDPBCGR 2.2.7.1.2)
                buf.put_u8(1); // drawingFlags (u8, DRAW_ALLOW_SKIP_ALPHA=1)
                buf.put_u16_le(1); // multipleRectangleSupport
                buf.put_u16_le(0); // pad2octetsBeta2

                // Fix length
                let length = buf.len() - start + 2;
                buf[start..start + 2].copy_from_slice(&(length as u16).to_le_bytes());
            }
            CapabilitySet::Order(cap) => {
                buf.put_u16_le(CAPSTYPE_ORDER);
                let start = buf.len();
                buf.put_u16_le(0); // Length placeholder

                // Terminal descriptor (16 bytes) - zeros
                buf.extend_from_slice(&[0u8; 16]);
                buf.put_u32_le(0); // Pad
                buf.put_u16_le(1); // Desktop save X granularity
                buf.put_u16_le(20); // Desktop save Y granularity
                buf.put_u16_le(0); // Pad
                buf.put_u16_le(1); // Maximum order level
                buf.put_u16_le(0); // Number of fonts
                buf.put_u16_le(cap.support_flags);
                // Order support (32 bytes) - no drawing orders supported
                buf.extend_from_slice(&[0u8; 32]);
                buf.put_u16_le(0); // Text flags
                buf.put_u16_le(0); // orderSupportExFlags
                buf.put_u32_le(0); // pad4octetsB
                buf.put_u32_le(0); // desktopSaveSize
                buf.put_u16_le(0); // pad2octetsC
                buf.put_u16_le(0); // pad2octetsD
                buf.put_u16_le(0); // textANSICodePage
                buf.put_u16_le(0); // pad2octetsE

                // Fix length
                let length = buf.len() - start + 2;
                buf[start..start + 2].copy_from_slice(&(length as u16).to_le_bytes());
            }
            CapabilitySet::Pointer(cap) => {
                buf.put_u16_le(CAPSTYPE_POINTER);
                let start = buf.len();
                buf.put_u16_le(0); // Length placeholder

                buf.put_u16_le(cap.color_pointer_flag);
                buf.put_u16_le(cap.color_pointer_cache_size);
                buf.put_u16_le(cap.pointer_cache_size); // pointerCacheSize (3rd field)

                // Fix length
                let length = buf.len() - start + 2;
                buf[start..start + 2].copy_from_slice(&(length as u16).to_le_bytes());
            }
            CapabilitySet::Input(cap) => {
                buf.put_u16_le(CAPSTYPE_INPUT);
                let start = buf.len();
                buf.put_u16_le(0); // Length placeholder

                buf.put_u16_le(cap.input_flags);
                buf.put_u16_le(0); // Pad
                buf.put_u32_le(cap.keyboard_layout);
                buf.put_u32_le(0); // Keyboard type
                buf.put_u32_le(0); // Keyboard subtype
                buf.put_u32_le(0); // Keyboard function key
                buf.put_bytes(0, 64); // imeFileName (64 bytes)

                // Fix length
                let length = buf.len() - start + 2;
                buf[start..start + 2].copy_from_slice(&(length as u16).to_le_bytes());
            }
            CapabilitySet::Font(cap) => {
                buf.put_u16_le(CAPSTYPE_FONT);
                let start = buf.len();
                buf.put_u16_le(0); // Length placeholder

                buf.put_u16_le(cap.font_support_flags);
                buf.put_u16_le(0); // Pad

                // Fix length
                let length = buf.len() - start + 2;
                buf[start..start + 2].copy_from_slice(&(length as u16).to_le_bytes());
            }
        }

        Ok(buf.to_vec())
    }
}

/// Share Capability Set (CAPSTYPE_SHARE = 9)
/// Reference: [MS-RDPBCGR] 2.2.7.1.9
#[derive(Debug)]
pub struct ShareCapability {
    pub node_id: u16,
    pub pad2octets: u16,
}

/// General Capability Set
#[derive(Debug)]
pub struct GeneralCapability {
    pub os_major_type: u16,
    pub os_minor_type: u16,
    pub protocol_version: u16,
    pub extra_flags: u16,
}

/// Bitmap Capability Set
#[derive(Debug)]
pub struct BitmapCapability {
    pub preferred_bpp: u16,
    pub desktop_width: u16,
    pub desktop_height: u16,
    pub desktop_resize_flag: u16,
}

/// Order Capability Set
#[derive(Debug)]
pub struct OrderCapability {
    pub support_flags: u16,
}

/// Pointer Capability Set
#[derive(Debug)]
pub struct PointerCapability {
    pub color_pointer_flag: u16,
    pub color_pointer_cache_size: u16,
    pub pointer_cache_size: u16, // Third field per MS-RDPBCGR 2.2.7.1.5
}

/// Input Capability Set
#[derive(Debug)]
pub struct InputCapability {
    pub input_flags: u16,
    pub keyboard_layout: u32,
}

/// Font Capability Set
#[derive(Debug)]
pub struct FontCapability {
    pub font_support_flags: u16,
}

/// Confirm Active PDU (from client)
#[derive(Debug, Default)]
pub struct ConfirmActivePdu {
    pub share_id: u32,
    pub source_descriptor: String,
}

impl ConfirmActivePdu {
    /// Parse Confirm Active PDU
    ///
    /// MS-RDPBCGR 2.2.1.13.2.1 field order (after Share Control Header is stripped):
    ///   offset 0:  shareId (u32 LE)
    ///   offset 4:  originatorId (u16 LE) — skip
    ///   offset 6:  lengthSourceDescriptor (u16 LE) → source_len
    ///   offset 8:  lengthCombinedCapabilities (u16 LE) — length field, NOT num_caps
    ///   offset 10: sourceDescriptor (source_len bytes) — skip
    ///   offset 10+source_len: numberCapabilities (u16 LE) — THIS is num_caps
    ///   offset 12+source_len: pad2octets (u16 LE) — skip
    ///   offset 14+source_len: capabilitySets — parse capabilities
    pub fn decode(data: &[u8]) -> Result<Self> {
        debug!("ConfirmActivePdu::decode: {} bytes", data.len());
        if data.len() < 10 {
            error!(
                "Confirm Active PDU too short: {} bytes (need at least 10)",
                data.len()
            );
            bail!("Confirm Active PDU too short");
        }

        let mut pos = 0;

        // offset 0: shareId (u32 LE)
        let share_id = read_u32_le(&data[pos..pos + 4])?;
        pos += 4;

        // offset 4: originatorId (u16 LE) — skip
        pos += 2;

        // offset 6: lengthSourceDescriptor (u16 LE)
        if pos + 2 > data.len() {
            bail!("Confirm Active PDU truncated at lengthSourceDescriptor");
        }
        let source_len = read_u16_le(&data[pos..pos + 2])? as usize;
        pos += 2;

        // offset 8: lengthCombinedCapabilities (u16 LE) — store for validation only
        if pos + 2 > data.len() {
            bail!("Confirm Active PDU truncated at lengthCombinedCapabilities");
        }
        let combined_caps_len = read_u16_le(&data[pos..pos + 2])?;
        pos += 2;

        // offset 10: sourceDescriptor (source_len bytes) — read and store, then skip
        let mut source_descriptor = String::new();
        if source_len > 0 {
            if pos + source_len > data.len() {
                bail!("Confirm Active PDU truncated in sourceDescriptor");
            }
            source_descriptor = String::from_utf8_lossy(&data[pos..pos + source_len])
                .trim_end_matches('\0')
                .to_string();
            pos += source_len;
        }

        // offset 10+source_len: numberCapabilities (u16 LE) — the REAL num_caps
        if pos + 2 > data.len() {
            bail!("Confirm Active PDU truncated at numberCapabilities");
        }
        let num_caps = read_u16_le(&data[pos..pos + 2])?;
        pos += 2;

        // offset 12+source_len: pad2octets (u16 LE) — skip
        if pos + 2 <= data.len() {
            pos += 2;
        }

        // offset 14+source_len: capabilitySets (remaining bytes, not parsed)
        let _remaining = data.len().saturating_sub(pos);

        debug!(
            "Confirm Active decoded: share_id=0x{:08X}, source='{}', num_caps={}, combined_caps_len={}, remaining_bytes={}",
            share_id, source_descriptor, num_caps, combined_caps_len, _remaining
        );

        Ok(ConfirmActivePdu {
            share_id,
            source_descriptor,
        })
    }
}

/// Finalization PDU types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FinalizationPduType {
    Synchronize,
    Cooperate,
    ControlGrantedControl,
    FontMap,
}

/// Build Server License Error PDU
///
/// Sends a license error with STATUS_VALID_CLIENT to indicate no licensing is required.
/// Reference: [MS-RDPELE] 2.2.1.12.1.3 Server License Error PDU - Valid Client
pub fn build_server_license_error_pdu() -> Result<Vec<u8>> {
    let mut buf = BytesMut::with_capacity(32);

    // Preamble (4 bytes)
    buf.put_u8(0xFF); // bMsgType: ERROR_ALERT (0xFF)
    buf.put_u8(0x03); // flags: PREAMBLE_VERSION_3_0 (0x03)
    buf.put_u16_le(16); // wMsgSize: 16 bytes (total size of error message including preamble)

    // Error message (12 bytes)
    buf.put_u32_le(0x00000007); // dwErrorCode: STATUS_VALID_CLIENT (0x07)
    buf.put_u32_le(0x00000002); // dwStateTransition: ST_NO_TRANSITION (0x02)
    buf.put_u32_le(0); // bbErrorInfo: no additional error info (length = 0)

    debug!(
        "Server License Error PDU: STATUS_VALID_CLIENT, {} bytes",
        buf.len()
    );

    Ok(buf.to_vec())
}

/// Build a finalization PDU
pub fn build_finalization_pdu(pdu_type: FinalizationPduType, user_id: u16) -> Result<Vec<u8>> {
    let mut buf = BytesMut::with_capacity(64);

    match pdu_type {
        FinalizationPduType::Synchronize => {
            // Synchronize PDU: just message type + target user
            buf.put_u16_le(1); // Message type (SYNCMSGTYPE_SYNC)
            buf.put_u16_le(user_id); // Target user (MCS channel ID)
        }
        FinalizationPduType::Cooperate => {
            // Control PDU - Cooperate: action + grant ID + control ID
            buf.put_u16_le(CTRLACTION_COOPERATE);
            buf.put_u16_le(0); // Grant ID
            buf.put_u32_le(0); // Control ID
        }
        FinalizationPduType::ControlGrantedControl => {
            // Control PDU - Granted Control
            buf.put_u16_le(CTRLACTION_GRANTED_CONTROL);
            buf.put_u16_le(user_id); // Grant ID
            buf.put_u32_le(0x000103EA); // Control ID (share ID)
        }
        FinalizationPduType::FontMap => {
            // Font Map PDU: number of entries + total size + sequence + flags
            buf.put_u16_le(0); // Number of fonts
            buf.put_u16_le(0); // Total number of fonts
            buf.put_u16_le(0x0003); // Sequence number (FONTMAP_LAST)
            buf.put_u16_le(0x0004); // Flags (FONTMAP_FIRST | FONTMAP_LAST)
        }
    }

    debug!("Finalization PDU: {:?}, {} bytes", pdu_type, buf.len());

    Ok(buf.to_vec())
}

/// Input Event types (fastpath events routed through handle_input_event)
#[derive(Debug)]
pub enum InputEvent {
    Scancode { flags: u16, scancode: u16 },
    Mouse { flags: u16, x: u16, y: u16 },
}

const INPUT_EVENT_SCANCODE: u16 = 4;
const INPUT_EVENT_MOUSE: u16 = 0x8001;

use super::pdu::{read_u16_le, read_u32_le};

impl InputEvent {
    /// Parse slow-path input events from TS_INPUT_PDU_DATA
    pub fn parse_input_events(data: &[u8]) -> Result<Vec<InputEvent>> {
        if data.len() < 4 {
            bail!("Input event PDU too short: {} bytes", data.len());
        }

        let mut events = Vec::new();
        let mut pos = 0;

        let num_events = read_u16_le(&data[pos..pos + 2])? as usize;
        pos += 2;
        pos += 2; // pad

        for _ in 0..num_events {
            if pos + 6 > data.len() {
                break;
            }
            let _event_time = read_u32_le(&data[pos..pos + 4])?;
            pos += 4;
            let msg_type = read_u16_le(&data[pos..pos + 2])?;
            pos += 2;

            match msg_type {
                INPUT_EVENT_SCANCODE => {
                    if pos + 4 > data.len() {
                        break;
                    }
                    let flags = read_u16_le(&data[pos..pos + 2])?;
                    let scancode = read_u16_le(&data[pos + 2..pos + 4])?;
                    pos += 4;
                    events.push(InputEvent::Scancode { flags, scancode });
                }
                INPUT_EVENT_MOUSE => {
                    if pos + 6 > data.len() {
                        break;
                    }
                    let flags = read_u16_le(&data[pos..pos + 2])?;
                    let x = read_u16_le(&data[pos + 2..pos + 4])?;
                    let y = read_u16_le(&data[pos + 4..pos + 6])?;
                    pos += 6;
                    events.push(InputEvent::Mouse { flags, x, y });
                }
                _ => {
                    // Skip unknown event types (4 bytes data assumed)
                    pos += 4;
                }
            }
        }

        Ok(events)
    }

    /// Convert scancode to ASCII character (US keyboard layout)
    pub fn scancode_to_char(scancode: u16, shift: bool) -> Option<char> {
        // US keyboard scancode mapping
        match scancode {
            0x1E => Some(if shift { 'A' } else { 'a' }),
            0x30 => Some(if shift { 'B' } else { 'b' }),
            0x2E => Some(if shift { 'C' } else { 'c' }),
            0x20 => Some(if shift { 'D' } else { 'd' }),
            0x12 => Some(if shift { 'E' } else { 'e' }),
            0x21 => Some(if shift { 'F' } else { 'f' }),
            0x22 => Some(if shift { 'G' } else { 'g' }),
            0x23 => Some(if shift { 'H' } else { 'h' }),
            0x17 => Some(if shift { 'I' } else { 'i' }),
            0x24 => Some(if shift { 'J' } else { 'j' }),
            0x25 => Some(if shift { 'K' } else { 'k' }),
            0x26 => Some(if shift { 'L' } else { 'l' }),
            0x32 => Some(if shift { 'M' } else { 'm' }),
            0x31 => Some(if shift { 'N' } else { 'n' }),
            0x18 => Some(if shift { 'O' } else { 'o' }),
            0x19 => Some(if shift { 'P' } else { 'p' }),
            0x10 => Some(if shift { 'Q' } else { 'q' }),
            0x13 => Some(if shift { 'R' } else { 'r' }),
            0x1F => Some(if shift { 'S' } else { 's' }),
            0x14 => Some(if shift { 'T' } else { 't' }),
            0x16 => Some(if shift { 'U' } else { 'u' }),
            0x2F => Some(if shift { 'V' } else { 'v' }),
            0x11 => Some(if shift { 'W' } else { 'w' }),
            0x2D => Some(if shift { 'X' } else { 'x' }),
            0x15 => Some(if shift { 'Y' } else { 'y' }),
            0x2C => Some(if shift { 'Z' } else { 'z' }),

            // Numbers
            0x02 => Some(if shift { '!' } else { '1' }),
            0x03 => Some(if shift { '@' } else { '2' }),
            0x04 => Some(if shift { '#' } else { '3' }),
            0x05 => Some(if shift { '$' } else { '4' }),
            0x06 => Some(if shift { '%' } else { '5' }),
            0x07 => Some(if shift { '^' } else { '6' }),
            0x08 => Some(if shift { '&' } else { '7' }),
            0x09 => Some(if shift { '*' } else { '8' }),
            0x0A => Some(if shift { '(' } else { '9' }),
            0x0B => Some(if shift { ')' } else { '0' }),

            // Special keys
            0x39 => Some(' '),    // Space
            0x1C => Some('\n'),   // Enter
            0x0E => Some('\x08'), // Backspace
            0x0F => Some('\t'),   // Tab
            0x0C => Some(if shift { '_' } else { '-' }),
            0x0D => Some(if shift { '+' } else { '=' }),
            0x33 => Some(if shift { '<' } else { ',' }),
            0x34 => Some(if shift { '>' } else { '.' }),
            0x35 => Some(if shift { '?' } else { '/' }),
            0x27 => Some(if shift { ':' } else { ';' }),
            0x28 => Some(if shift { '"' } else { '\'' }),
            0x1A => Some(if shift { '{' } else { '[' }),
            0x1B => Some(if shift { '}' } else { ']' }),
            0x2B => Some(if shift { '|' } else { '\\' }),
            0x29 => Some(if shift { '~' } else { '`' }),

            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_demand_active_encode() {
        let demand = DemandActivePdu::new_minimal(1024, 768, 16);
        let encoded = demand.encode().unwrap();
        assert!(encoded.len() > 50);
    }

    #[test]
    fn test_finalization_pdus() {
        let sync = build_finalization_pdu(FinalizationPduType::Synchronize, 1002).unwrap();
        assert!(!sync.is_empty());

        let coop = build_finalization_pdu(FinalizationPduType::Cooperate, 1002).unwrap();
        assert!(!coop.is_empty());
    }

    #[test]
    fn test_scancode_to_char() {
        assert_eq!(InputEvent::scancode_to_char(0x1E, false), Some('a'));
        assert_eq!(InputEvent::scancode_to_char(0x1E, true), Some('A'));
        assert_eq!(InputEvent::scancode_to_char(0x1C, false), Some('\n'));
        assert_eq!(InputEvent::scancode_to_char(0x39, false), Some(' '));
        // Terminal-critical scancodes: r (ls, clear), l (ls, kill), v (Ctrl+V coverage)
        assert_eq!(InputEvent::scancode_to_char(0x13, false), Some('r'));
        assert_eq!(InputEvent::scancode_to_char(0x26, false), Some('l'));
        assert_eq!(InputEvent::scancode_to_char(0x2F, false), Some('v'));
    }

    #[test]
    fn test_scancode_to_char_all_special_keys() {
        // Space
        assert_eq!(InputEvent::scancode_to_char(0x39, false), Some(' '));
        assert_eq!(InputEvent::scancode_to_char(0x39, true), Some(' '));
        // Enter
        assert_eq!(InputEvent::scancode_to_char(0x1C, false), Some('\n'));
        // Backspace
        assert_eq!(InputEvent::scancode_to_char(0x0E, false), Some('\x08'));
        // Tab
        assert_eq!(InputEvent::scancode_to_char(0x0F, false), Some('\t'));
        // Punctuation with shift
        assert_eq!(InputEvent::scancode_to_char(0x0C, false), Some('-'));
        assert_eq!(InputEvent::scancode_to_char(0x0C, true), Some('_'));
        assert_eq!(InputEvent::scancode_to_char(0x0D, false), Some('='));
        assert_eq!(InputEvent::scancode_to_char(0x0D, true), Some('+'));
        assert_eq!(InputEvent::scancode_to_char(0x1A, false), Some('['));
        assert_eq!(InputEvent::scancode_to_char(0x1A, true), Some('{'));
        assert_eq!(InputEvent::scancode_to_char(0x1B, false), Some(']'));
        assert_eq!(InputEvent::scancode_to_char(0x1B, true), Some('}'));
        assert_eq!(InputEvent::scancode_to_char(0x2B, false), Some('\\'));
        assert_eq!(InputEvent::scancode_to_char(0x2B, true), Some('|'));
        assert_eq!(InputEvent::scancode_to_char(0x29, false), Some('`'));
        assert_eq!(InputEvent::scancode_to_char(0x29, true), Some('~'));
    }

    #[test]
    fn test_scancode_to_char_unknown_returns_none() {
        assert_eq!(InputEvent::scancode_to_char(0x00, false), None);
        assert_eq!(InputEvent::scancode_to_char(0xFF, false), None);
        assert_eq!(InputEvent::scancode_to_char(0x80, true), None);
    }

    #[test]
    fn test_parse_input_events_scancode() {
        // Build a valid TS_INPUT_PDU_DATA with 1 scancode event
        let mut data = Vec::new();
        data.extend_from_slice(&1u16.to_le_bytes()); // numEvents = 1
        data.extend_from_slice(&0u16.to_le_bytes()); // pad
        // Event: time(4) + msgType(2) + scancode data(4)
        data.extend_from_slice(&0u32.to_le_bytes()); // eventTime
        data.extend_from_slice(&INPUT_EVENT_SCANCODE.to_le_bytes()); // msgType
        data.extend_from_slice(&0u16.to_le_bytes()); // flags = 0 (key down)
        data.extend_from_slice(&0x1Eu16.to_le_bytes()); // scancode = 'a'

        let events = InputEvent::parse_input_events(&data).unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            InputEvent::Scancode { flags, scancode } => {
                assert_eq!(*flags, 0);
                assert_eq!(*scancode, 0x1E);
            }
            _ => panic!("Expected Scancode event"),
        }
    }

    #[test]
    fn test_parse_input_events_mouse() {
        let mut data = Vec::new();
        data.extend_from_slice(&1u16.to_le_bytes()); // numEvents = 1
        data.extend_from_slice(&0u16.to_le_bytes()); // pad
        data.extend_from_slice(&0u32.to_le_bytes()); // eventTime
        data.extend_from_slice(&INPUT_EVENT_MOUSE.to_le_bytes()); // msgType
        data.extend_from_slice(&0x0001u16.to_le_bytes()); // flags
        data.extend_from_slice(&100u16.to_le_bytes()); // x
        data.extend_from_slice(&200u16.to_le_bytes()); // y

        let events = InputEvent::parse_input_events(&data).unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            InputEvent::Mouse { flags, x, y } => {
                assert_eq!(*flags, 0x0001);
                assert_eq!(*x, 100);
                assert_eq!(*y, 200);
            }
            _ => panic!("Expected Mouse event"),
        }
    }

    #[test]
    fn test_parse_input_events_empty() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u16.to_le_bytes()); // numEvents = 0
        data.extend_from_slice(&0u16.to_le_bytes()); // pad

        let events = InputEvent::parse_input_events(&data).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn test_parse_input_events_too_short() {
        let data = vec![0u8; 2]; // only 2 bytes, need at least 4
        assert!(InputEvent::parse_input_events(&data).is_err());
    }

    #[test]
    fn test_confirm_active_pdu_decode_too_short() {
        let data = vec![0u8; 5]; // way too short
        assert!(ConfirmActivePdu::decode(&data).is_err());
    }

    #[test]
    fn test_confirm_active_pdu_decode_valid() {
        let mut data = Vec::new();
        // shareId (u32 LE)
        data.extend_from_slice(&0x000103EAu32.to_le_bytes());
        // originatorId (u16 LE)
        data.extend_from_slice(&0u16.to_le_bytes());
        // lengthSourceDescriptor (u16 LE) = 5 (4 chars + null)
        data.extend_from_slice(&5u16.to_le_bytes());
        // lengthCombinedCapabilities (u16 LE)
        data.extend_from_slice(&8u16.to_le_bytes());
        // sourceDescriptor: "Test\0"
        data.extend_from_slice(b"Test\0");
        // numberCapabilities (u16 LE)
        data.extend_from_slice(&0u16.to_le_bytes());
        // pad2Octets
        data.extend_from_slice(&0u16.to_le_bytes());

        let pdu = ConfirmActivePdu::decode(&data).unwrap();
        assert_eq!(pdu.share_id, 0x000103EA);
        assert_eq!(pdu.source_descriptor, "Test");
    }

    #[test]
    fn test_build_server_license_error_pdu() {
        let pdu = build_server_license_error_pdu().unwrap();
        assert_eq!(pdu.len(), 16);
        // bMsgType = ERROR_ALERT (0xFF)
        assert_eq!(pdu[0], 0xFF);
        // flags = PREAMBLE_VERSION_3_0 (0x03)
        assert_eq!(pdu[1], 0x03);
        // wMsgSize = 16
        assert_eq!(u16::from_le_bytes([pdu[2], pdu[3]]), 16);
        // dwErrorCode = STATUS_VALID_CLIENT (0x07)
        assert_eq!(u32::from_le_bytes([pdu[4], pdu[5], pdu[6], pdu[7]]), 0x07);
        // dwStateTransition = ST_NO_TRANSITION (0x02)
        assert_eq!(u32::from_le_bytes([pdu[8], pdu[9], pdu[10], pdu[11]]), 0x02);
    }

    #[test]
    fn test_build_finalization_pdu_synchronize() {
        let pdu = build_finalization_pdu(FinalizationPduType::Synchronize, 1002).unwrap();
        assert_eq!(pdu.len(), 4);
        // Message type = 1 (SYNCMSGTYPE_SYNC)
        assert_eq!(u16::from_le_bytes([pdu[0], pdu[1]]), 1);
        // Target user
        assert_eq!(u16::from_le_bytes([pdu[2], pdu[3]]), 1002);
    }

    #[test]
    fn test_build_finalization_pdu_cooperate() {
        let pdu = build_finalization_pdu(FinalizationPduType::Cooperate, 1002).unwrap();
        assert_eq!(pdu.len(), 8);
        assert_eq!(u16::from_le_bytes([pdu[0], pdu[1]]), CTRLACTION_COOPERATE);
    }

    #[test]
    fn test_build_finalization_pdu_granted_control() {
        let pdu = build_finalization_pdu(FinalizationPduType::ControlGrantedControl, 1002).unwrap();
        assert_eq!(pdu.len(), 8);
        assert_eq!(
            u16::from_le_bytes([pdu[0], pdu[1]]),
            CTRLACTION_GRANTED_CONTROL
        );
        // Grant ID = user_id
        assert_eq!(u16::from_le_bytes([pdu[2], pdu[3]]), 1002);
    }

    #[test]
    fn test_build_finalization_pdu_font_map() {
        let pdu = build_finalization_pdu(FinalizationPduType::FontMap, 1002).unwrap();
        assert_eq!(pdu.len(), 8);
        // Number of fonts = 0
        assert_eq!(u16::from_le_bytes([pdu[0], pdu[1]]), 0);
        // Sequence = FONTMAP_LAST (3)
        assert_eq!(u16::from_le_bytes([pdu[4], pdu[5]]), 0x0003);
    }
}
