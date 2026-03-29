/// Protocol I/O helpers for RDP sessions
///
/// Low-level read/write operations for TPKT, MCS, and RDP PDU framing.
use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use crate::protocol::pdu::*;

impl super::RdpSession {
    /// Write TPKT-wrapped data
    pub(super) async fn write_tpkt(&mut self, data: &[u8]) -> Result<()> {
        let total_length = data.len() + 4;

        let mut pdu = Vec::with_capacity(total_length);
        pdu.push(TPKT_VERSION);
        pdu.push(0); // Reserved
        pdu.extend_from_slice(&(total_length as u16).to_be_bytes());
        pdu.extend_from_slice(data);

        let stream = self.stream.as_mut().unwrap();
        stream
            .write_all(&pdu)
            .await
            .context("Failed to write TPKT PDU to stream")?;
        stream.flush().await.context("Failed to flush stream")?;

        Ok(())
    }

    /// Read MCS PDU
    pub(super) async fn read_mcs_pdu(&mut self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; 8192];
        let n = self
            .stream
            .as_mut()
            .unwrap()
            .read(&mut buf)
            .await
            .context("Failed to read MCS PDU from stream")?;

        if n == 0 {
            bail!("Connection closed while reading MCS PDU");
        }

        // Validate TPKT header
        if buf[0] != TPKT_VERSION {
            bail!(
                "Invalid TPKT version in MCS PDU: {} (expected {})",
                buf[0],
                TPKT_VERSION
            );
        }

        // Strip TPKT header (4 bytes) and X.224 Data header (3 bytes)
        let payload = buf[7..n].to_vec();
        Ok(payload)
    }

    /// Write MCS PDU
    pub(super) async fn write_mcs_pdu(&mut self, data: &[u8]) -> Result<()> {
        let mut pdu = Vec::new();

        // X.224 Data TPDU (3 bytes)
        pdu.push(2); // LI
        pdu.push(X224_TPDU_DATA); // 0xF0
        pdu.push(0x80); // EOT

        // MCS data
        pdu.extend_from_slice(data);

        self.write_tpkt(&pdu).await
    }

    /// Read RDP PDU
    ///
    /// Returns `(pdu_type_code, body)` where pdu_type_code is the low 4 bits of the
    /// TS_SHARECONTROLHEADER pduType field, and body is the payload after the
    /// 6-byte Share Control Header.
    pub(super) async fn read_rdp_pdu(&mut self) -> Result<(u16, Vec<u8>)> {
        let mcs_data = self
            .read_mcs_pdu()
            .await
            .context("Failed to read MCS PDU for RDP data")?;

        // Parse variable-length MCS Send Data Request/Indication header.
        //
        // Layout (after TPKT + X.224 have already been stripped by read_mcs_pdu):
        //   byte 0:    MCS opcode (0x64 = SendDataRequest, 0x68 = SendDataIndication)
        //   bytes 1-2: initiator (u16 big-endian PER)
        //   bytes 3-4: channel_id (u16 big-endian PER)
        //   byte 5:    priority/segmentation flags (0x70 typically)
        //   byte 6+:   PER-encoded payload length:
        //              - if byte[6] & 0x80 == 0: 1-byte length  → mcs_header_len = 7
        //              - if byte[6] & 0x80 != 0: 2-byte length  → mcs_header_len = 8
        if mcs_data.len() < 8 {
            bail!(
                "MCS data too short ({} bytes) to parse MCS header",
                mcs_data.len()
            );
        }

        let mcs_header_len: usize = if mcs_data[6] & 0x80 == 0 { 7 } else { 8 };

        // After the MCS header follows the TS_SHARECONTROLHEADER (6 bytes):
        //   bytes 0-1: totalLength  (u16 LE)
        //   bytes 2-3: pduType      (u16 LE) — low 4 bits = pdu_type_code
        //   bytes 4-5: pduSource    (u16 LE)
        if mcs_data.len() < mcs_header_len + 6 {
            bail!(
                "MCS data too short ({} bytes) to parse Share Control Header (need {})",
                mcs_data.len(),
                mcs_header_len + 6
            );
        }

        let rdp_payload = &mcs_data[mcs_header_len..];
        let total_length = u16::from_le_bytes([rdp_payload[0], rdp_payload[1]]);
        let pdu_type = u16::from_le_bytes([rdp_payload[2], rdp_payload[3]]);
        let _pdu_source = u16::from_le_bytes([rdp_payload[4], rdp_payload[5]]);
        let pdu_type_code = pdu_type & 0x0F; // extract low 4 bits

        debug!(
            "read_rdp_pdu: mcs_header_len={}, totalLength={}, pduType=0x{:04X}, pdu_type_code={}",
            mcs_header_len, total_length, pdu_type, pdu_type_code
        );

        // Return the body after the 6-byte Share Control Header.
        let body = rdp_payload[6..].to_vec();
        Ok((pdu_type_code, body))
    }

    /// Extract RDP input-event payload from a raw buffer received in the main loop.
    ///
    /// Parses the full header stack and returns `(pdu_type2, payload)` after the
    /// TS_SHAREDATAHEADER, so the caller can dispatch on pduType2.
    ///
    /// Header layout:
    ///   TPKT (4)  + X.224 Data (3)  = 7 bytes fixed
    ///   MCS Send Data Request: opcode(1) + initiator(2) + channel(2) + priority(1) + PER-len(1-2)
    ///   TS_SHARECONTROLHEADER (6): totalLen(2) + pduType(2) + pduSource(2)
    ///   TS_SHAREDATAHEADER (12): shareId(4) + pad(1) + streamId(1) + uncompLen(2) + pduType2(1) + compType(1) + compLen(2)
    pub(super) fn extract_rdp_data(&self, buf: &[u8]) -> Result<(u8, Vec<u8>)> {
        // Step 1: TPKT header (4 bytes)
        if buf.len() < 4 {
            bail!("Buffer too short for TPKT header ({} bytes)", buf.len());
        }
        if buf[0] != TPKT_VERSION {
            bail!(
                "Invalid TPKT version: 0x{:02X} (expected 0x{:02X})",
                buf[0],
                TPKT_VERSION
            );
        }
        // buf[2-3] = total length (big-endian), but we trust buf.len() for the actual data

        // Step 2: X.224 Data header (3 bytes at offset 4)
        // byte 4: LI, byte 5: type (0xF0), byte 6: EOT
        if buf.len() < 7 {
            bail!(
                "Buffer too short for X.224 Data header ({} bytes)",
                buf.len()
            );
        }
        // buf[5] should be X224_TPDU_DATA (0xF0) but we don't enforce it here

        // Step 3: MCS Send Data Request header starting at offset 7
        // opcode(1) + initiator(2) + channel_id(2) + priority(1) + PER-length(1-2)
        if buf.len() < 7 + 7 {
            bail!("Buffer too short for MCS header ({} bytes)", buf.len());
        }
        let mcs_start = 7usize;
        let per_len_byte = buf[mcs_start + 6];
        let mcs_header_len: usize = if per_len_byte & 0x80 == 0 { 7 } else { 8 };
        let rdp_start = mcs_start + mcs_header_len;

        // Step 4: TS_SHARECONTROLHEADER (6 bytes)
        if buf.len() < rdp_start + 6 {
            bail!(
                "Buffer too short for Share Control Header ({} bytes)",
                buf.len()
            );
        }
        let pdu_type = u16::from_le_bytes([buf[rdp_start + 2], buf[rdp_start + 3]]);
        let pdu_type_code = pdu_type & 0x0F;

        // Step 5: If this is a DATAPDU, parse TS_SHAREDATAHEADER (12 bytes)
        let share_ctrl_end = rdp_start + 6;
        if pdu_type_code != PDUTYPE_DATAPDU {
            bail!(
                "extract_rdp_data: expected DATAPDU (7), got pdu_type_code={}",
                pdu_type_code
            );
        }
        if buf.len() < share_ctrl_end + 12 {
            bail!(
                "Buffer too short for Share Data Header ({} bytes)",
                buf.len()
            );
        }
        // TS_SHAREDATAHEADER layout (after Share Control Header):
        //   shareId(4) + pad(1) + streamId(1) + uncompressedLength(2) + pduType2(1) + ...
        let pdu_type2 = buf[share_ctrl_end + 8]; // offset 8 within Share Data Header
        let payload_start = share_ctrl_end + 12;

        debug!(
            "extract_rdp_data: pdu_type_code={}, pdu_type2={}, payload={} bytes",
            pdu_type_code,
            pdu_type2,
            buf.len().saturating_sub(payload_start)
        );

        Ok((pdu_type2, buf[payload_start..].to_vec()))
    }

    /// Write RDP Share Control PDU
    pub(super) async fn write_rdp_share_control_pdu(
        &mut self,
        pdu_type: u16,
        data: &[u8],
    ) -> Result<()> {
        let mut pdu = Vec::new();

        // Share Control Header
        let total_length = (data.len() + 6) as u16;
        // Combine PDU type with protocol version flag
        let pdu_type_with_version = pdu_type | TS_PROTOCOL_VERSION;

        pdu.extend_from_slice(&total_length.to_le_bytes()); // Total length
        pdu.extend_from_slice(&pdu_type_with_version.to_le_bytes()); // PDU type with protocol version
        pdu.extend_from_slice(&self.user_id.to_le_bytes()); // PDU source

        // Data
        pdu.extend_from_slice(data);

        self.write_rdp_pdu(&pdu).await
    }

    /// Write RDP Data PDU
    pub(super) async fn write_rdp_data_pdu(&mut self, pdu_type2: u8, data: &[u8]) -> Result<()> {
        let pdu = Self::build_share_data_pdu(self.user_id, pdu_type2, data);
        self.write_rdp_pdu(&pdu).await
    }

    /// Write RDP PDU (wrapped in MCS Send Data)
    /// NOTE: Per MS-RDPBCGR, when encryption level/method is NONE, the security header MUST NOT be included
    pub(super) async fn write_rdp_pdu(&mut self, data: &[u8]) -> Result<()> {
        let mcs_pdu = self.wrap_mcs_send_data(data, None);
        self.write_mcs_pdu(&mcs_pdu).await
    }

    /// Write RDP Security PDU (for licensing, etc.)
    pub(super) async fn write_rdp_security_pdu(&mut self, data: &[u8]) -> Result<()> {
        // Security header (flags = SEC_LICENSE_PKT = 0x80)
        let sec_header = 0x0080u32.to_le_bytes();
        let mcs_pdu = self.wrap_mcs_send_data(data, Some(&sec_header));
        self.write_mcs_pdu(&mcs_pdu).await
    }

    /// Build a complete TPKT-wrapped RDP Data PDU as bytes (for batching)
    pub(super) fn build_rdp_data_pdu(&self, pdu_type2: u8, data: &[u8]) -> Vec<u8> {
        let rdp = Self::build_share_data_pdu(self.user_id, pdu_type2, data);
        let mcs_pdu = self.wrap_mcs_send_data(&rdp, None);

        // X.224 Data header (3 bytes)
        let mut x224 = Vec::with_capacity(mcs_pdu.len() + 3);
        x224.push(2); // LI
        x224.push(0xF0); // X224_TPDU_DATA
        x224.push(0x80); // EOT
        x224.extend_from_slice(&mcs_pdu);

        // TPKT header (4 bytes)
        let total = x224.len() + 4;
        let mut tpkt = Vec::with_capacity(total);
        tpkt.push(TPKT_VERSION);
        tpkt.push(0);
        tpkt.extend_from_slice(&(total as u16).to_be_bytes());
        tpkt.extend_from_slice(&x224);

        tpkt
    }

    // ========== Private helpers ==========

    /// Build an MCS Send Data Indication wrapping `payload`, with an optional
    /// prefix inserted between the MCS header and the payload (used for security
    /// headers).  All three outbound PDU paths share this logic.
    fn wrap_mcs_send_data(&self, payload: &[u8], prefix: Option<&[u8]>) -> Vec<u8> {
        let prefix_len = prefix.map_or(0, |p| p.len());
        let mut mcs_pdu = Vec::with_capacity(8 + prefix_len + payload.len());

        // MCS Send Data Indication
        mcs_pdu.push(MCS_SEND_DATA_INDICATION);

        // Initiator (user ID) - PER integer16 with MCS_USERCHANNEL_BASE (1001) as min
        let initiator = self.user_id.wrapping_sub(MCS_USERCHANNEL_BASE);
        mcs_pdu.extend_from_slice(&initiator.to_be_bytes());

        // Channel ID - PER integer16 with min=0
        mcs_pdu.extend_from_slice(&MCS_GLOBAL_CHANNEL.to_be_bytes());

        mcs_pdu.push(0x70); // Priority / Segmentation

        // PER-encoded length (ITU-T X.691)
        let length = (prefix_len + payload.len()) as u16;
        if length > 0x7F {
            // Two-byte encoding: set bit 15, write as big-endian u16
            mcs_pdu.extend_from_slice(&(length | 0x8000).to_be_bytes());
        } else {
            // Single-byte encoding for lengths 0-127
            mcs_pdu.push(length as u8);
        }

        // Optional prefix (e.g. security header)
        if let Some(p) = prefix {
            mcs_pdu.extend_from_slice(p);
        }

        // Payload
        mcs_pdu.extend_from_slice(payload);

        mcs_pdu
    }

    /// Build a Share Control + Share Data header + payload (without MCS wrapping).
    /// Used by both `write_rdp_data_pdu` (async) and `build_rdp_data_pdu` (sync batching).
    pub(super) fn build_share_data_pdu(user_id: u16, pdu_type2: u8, data: &[u8]) -> Vec<u8> {
        let mut rdp = Vec::with_capacity(data.len() + 18);

        // Share Control Header (6 bytes)
        rdp.extend_from_slice(&((data.len() + 18) as u16).to_le_bytes()); // Total length
        rdp.extend_from_slice(&(PDUTYPE_DATAPDU | TS_PROTOCOL_VERSION).to_le_bytes()); // PDU type
        rdp.extend_from_slice(&user_id.to_le_bytes()); // PDU source

        // Share Data Header (12 bytes)
        rdp.extend_from_slice(&SHARE_ID.to_le_bytes()); // Share ID
        rdp.push(0); // pad
        rdp.push(1); // streamId
        rdp.extend_from_slice(&((data.len() + 6) as u16).to_le_bytes()); // Uncompressed length
        rdp.push(pdu_type2);
        rdp.push(0); // compressedType
        rdp.extend_from_slice(&0u16.to_le_bytes()); // compressedLength

        // Data
        rdp.extend_from_slice(data);

        rdp
    }
}
