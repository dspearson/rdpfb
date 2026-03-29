/// Common PDU (Protocol Data Unit) types and structures
///
/// Definitions for RDP protocol structures used across layers.
/// Reference: [MS-RDPBCGR] Remote Desktop Protocol: Basic Connectivity and Graphics Remoting
use anyhow::{Result, bail};

/// TPKT version (always 3 for RDP)
pub const TPKT_VERSION: u8 = 3;

/// X.224 Connection Confirm
pub const X224_TPDU_CONNECTION_CONFIRM: u8 = 0xD0;

/// X.224 Data
pub const X224_TPDU_DATA: u8 = 0xF0;

/// RDP Negotiation Request (in X.224 CR)
pub const RDP_NEG_REQ: u8 = 0x01;

/// RDP Negotiation Response (in X.224 CC)
pub const RDP_NEG_RSP: u8 = 0x02;

/// Protocol Security Flags
pub const PROTOCOL_RDP: u32 = 0x00000000; // Standard RDP security
pub const PROTOCOL_SSL: u32 = 0x00000001; // TLS 1.0
pub const PROTOCOL_HYBRID: u32 = 0x00000002; // CredSSP (NLA)

/// MCS PDU types (PER encoding choice indices)
pub const MCS_ERECT_DOMAIN_REQUEST: u8 = 0x04;
pub const MCS_ATTACH_USER_REQUEST: u8 = 0x28;
pub const MCS_ATTACH_USER_CONFIRM: u8 = 0x2E;
pub const MCS_CHANNEL_JOIN_REQUEST: u8 = 0x38;
pub const MCS_CHANNEL_JOIN_CONFIRM: u8 = 0x3E;
pub const MCS_SEND_DATA_INDICATION: u8 = 0x68;

/// MCS Result enumeration
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum McsResult {
    Successful = 0,
}

/// RDP Share Control Header PDU types
pub const TS_PROTOCOL_VERSION: u16 = 0x0010; // RDP protocol version flag
pub const PDUTYPE_DEMANDACTIVEPDU: u16 = 1;
pub const PDUTYPE_DATAPDU: u16 = 7;

/// RDP Data PDU types (when PDUTYPE_DATAPDU)
pub const PDUTYPE2_UPDATE: u8 = 2;
pub const PDUTYPE2_CONTROL: u8 = 20;
pub const PDUTYPE2_SYNCHRONIZE: u8 = 31;
pub const PDUTYPE2_FONTLIST: u8 = 39;
pub const PDUTYPE2_FONTMAP: u8 = 40;

/// Control PDU actions
pub const CTRLACTION_REQUEST_CONTROL: u16 = 1;
pub const CTRLACTION_GRANTED_CONTROL: u16 = 2;
pub const CTRLACTION_COOPERATE: u16 = 4;

/// Keyboard flags
pub const KBD_FLAG_RELEASE: u16 = 0x8000;
pub const KBD_FLAG_EXTENDED: u16 = 0x0100;

/// GCC Create Conference Request/Response user data types
pub const CS_CORE: u16 = 0xC001; // Client Core Data
pub const CS_SECURITY: u16 = 0xC002; // Client Security Data
pub const CS_NET: u16 = 0xC003; // Client Network Data
pub const CS_CLUSTER: u16 = 0xC004; // Client Cluster Data
pub const CS_MONITOR: u16 = 0xC005; // Client Monitor Data
pub const CS_MCS_MSGCHANNEL: u16 = 0xC006; // Client Message Channel Data
pub const CS_MONITOR_EX: u16 = 0xC008; // Client Monitor Extended Data
pub const CS_MULTITRANSPORT: u16 = 0xC00A; // Client Multi-transport Channel Data

pub const SC_CORE: u16 = 0x0C01; // Server Core Data
pub const SC_SECURITY: u16 = 0x0C02; // Server Security Data
pub const SC_NET: u16 = 0x0C03; // Server Network Data

/// Capability set types
pub const CAPSTYPE_GENERAL: u16 = 1;
pub const CAPSTYPE_BITMAP: u16 = 2;
pub const CAPSTYPE_ORDER: u16 = 3;
pub const CAPSTYPE_POINTER: u16 = 8;
pub const CAPSTYPE_SHARE: u16 = 9;
pub const CAPSTYPE_INPUT: u16 = 13;
pub const CAPSTYPE_FONT: u16 = 14;

/// Channel IDs
pub const MCS_GLOBAL_CHANNEL: u16 = 1003;
pub const MCS_USERCHANNEL_BASE: u16 = 1001;

/// Share ID
pub const SHARE_ID: u32 = 0x000103EA;

/// Byte order helper functions
#[inline]
pub fn read_u16_le(buf: &[u8]) -> Result<u16> {
    if buf.len() < 2 {
        bail!("Buffer too small for u16");
    }
    Ok(u16::from_le_bytes([buf[0], buf[1]]))
}

#[inline]
pub fn read_u32_le(buf: &[u8]) -> Result<u32> {
    if buf.len() < 4 {
        bail!("Buffer too small for u32");
    }
    Ok(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
}

/// Input capability flags
pub const INPUT_FLAG_SCANCODES: u16 = 0x0001;
pub const INPUT_FLAG_UNICODE: u16 = 0x0010;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_u16_le_normal() {
        let buf = [0x34, 0x12];
        assert_eq!(read_u16_le(&buf).unwrap(), 0x1234);
    }

    #[test]
    fn test_read_u16_le_too_short() {
        let buf = [0x34];
        assert!(read_u16_le(&buf).is_err());
    }

    #[test]
    fn test_read_u16_le_empty() {
        let buf: [u8; 0] = [];
        assert!(read_u16_le(&buf).is_err());
    }

    #[test]
    fn test_read_u32_le_normal() {
        let buf = [0x78, 0x56, 0x34, 0x12];
        assert_eq!(read_u32_le(&buf).unwrap(), 0x12345678);
    }

    #[test]
    fn test_read_u32_le_too_short() {
        let buf = [0x78, 0x56, 0x34];
        assert!(read_u32_le(&buf).is_err());
    }

    #[test]
    fn test_read_u32_le_empty() {
        let buf: [u8; 0] = [];
        assert!(read_u32_le(&buf).is_err());
    }

    #[test]
    fn test_read_u16_le_zero() {
        let buf = [0x00, 0x00];
        assert_eq!(read_u16_le(&buf).unwrap(), 0);
    }

    #[test]
    fn test_read_u32_le_max() {
        let buf = [0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(read_u32_le(&buf).unwrap(), u32::MAX);
    }
}
