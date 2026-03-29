/// MCS (Multipoint Communication Service) Layer
///
/// Implements [ITU-T T.125] MCS protocol for RDP connection establishment.
/// Reference: [MS-RDPBCGR] Section 1.3.1.1 Connection Sequence
///
/// The MCS layer handles:
/// - Connect-Initial/Response (BER-encoded)
/// - Domain attachment and user management
/// - Virtual channel joins
use anyhow::{Result, bail};
use bytes::{BufMut, BytesMut};
use tracing::{debug, error};

use super::ber::{BerDecoder, BerEncoder};
use super::pdu::*;

/// MCS Domain Parameters (standard RDP values)
#[derive(Debug, Clone)]
pub struct McsDomainParameters {
    pub max_channel_ids: i32,
    pub max_user_ids: i32,
    pub max_token_ids: i32,
    pub num_priorities: i32,
    pub min_throughput: i32,
    pub max_height: i32,
    pub max_mcs_pdu_size: i32,
    pub protocol_version: i32,
}

impl Default for McsDomainParameters {
    fn default() -> Self {
        McsDomainParameters {
            max_channel_ids: 34,
            max_user_ids: 2,
            max_token_ids: 0,
            num_priorities: 1,
            min_throughput: 0,
            max_height: 1,
            max_mcs_pdu_size: 65535,
            protocol_version: 2,
        }
    }
}

impl McsDomainParameters {
    /// Encode domain parameters as BER SEQUENCE
    pub fn encode(&self, encoder: &mut BerEncoder) {
        let start = encoder.start_sequence();
        encoder.write_integer(self.max_channel_ids);
        encoder.write_integer(self.max_user_ids);
        encoder.write_integer(self.max_token_ids);
        encoder.write_integer(self.num_priorities);
        encoder.write_integer(self.min_throughput);
        encoder.write_integer(self.max_height);
        encoder.write_integer(self.max_mcs_pdu_size);
        encoder.write_integer(self.protocol_version);
        encoder.end_sequence(start);
    }

    /// Decode domain parameters from BER SEQUENCE
    pub fn decode(decoder: &mut BerDecoder) -> Result<Self> {
        debug!("Decoding MCS Domain Parameters...");
        decoder.read_sequence()?;

        let max_channel_ids = decoder.read_integer()?;
        let max_user_ids = decoder.read_integer()?;
        let max_token_ids = decoder.read_integer()?;
        let num_priorities = decoder.read_integer()?;
        let min_throughput = decoder.read_integer()?;
        let max_height = decoder.read_integer()?;
        let max_mcs_pdu_size = decoder.read_integer()?;
        let protocol_version = decoder.read_integer()?;

        debug!(
            "MCS Domain Params: channels={}, users={}, max_pdu={}, version={}",
            max_channel_ids, max_user_ids, max_mcs_pdu_size, protocol_version
        );

        Ok(McsDomainParameters {
            max_channel_ids,
            max_user_ids,
            max_token_ids,
            num_priorities,
            min_throughput,
            max_height,
            max_mcs_pdu_size,
            protocol_version,
        })
    }
}

/// MCS Connect-Initial PDU
#[derive(Debug)]
pub struct McsConnectInitial {
    pub user_data: Vec<u8>, // GCC Conference Create Request
}

impl McsConnectInitial {
    /// Decode MCS Connect-Initial from BER-encoded data
    pub fn decode(data: &[u8]) -> Result<Self> {
        debug!("McsConnectInitial::decode: {} bytes", data.len());
        let mut decoder = BerDecoder::new(data);

        // Read outer application tag [APPLICATION 101]
        // In BER: 0x7F 0x65 means APPLICATION class, constructed, tag number 101
        let tag = decoder.read_tag()?;
        debug!("MCS Connect-Initial tag: 0x{:08X}", tag);

        // Extract tag number from the combined tag value
        let tag_number = tag & 0x00FFFFFF;
        if tag_number != 101 {
            error!(
                "Invalid MCS Connect-Initial tag number: {} (expected 101)",
                tag_number
            );
            bail!("Invalid MCS Connect-Initial tag number: {}", tag_number);
        }

        // Read the length of the Connect-Initial content
        let connect_initial_length = decoder.read_length()?;
        debug!("MCS Connect-Initial length: {}", connect_initial_length);

        // Read calling domain selector (OCTET STRING) - value not used, but must be read from stream
        let _calling_domain_selector = decoder.read_octet_string()?;

        // Read called domain selector (OCTET STRING) - value not used, but must be read from stream
        let _called_domain_selector = decoder.read_octet_string()?;

        // Read upward flag (BOOLEAN) - value not used, but must be read from stream
        let _upward_flag = decoder.read_boolean()?;

        // Read target parameters - must be read from stream
        McsDomainParameters::decode(&mut decoder)?;

        // Read minimum parameters - must be read from stream
        McsDomainParameters::decode(&mut decoder)?;

        // Read maximum parameters - must be read from stream
        McsDomainParameters::decode(&mut decoder)?;

        // Read user data (GCC Conference Create Request)
        let user_data = decoder.read_octet_string()?;
        debug!(
            "MCS Connect-Initial: user data length = {} bytes",
            user_data.len()
        );

        debug!("MCS Connect-Initial decoded successfully");

        Ok(McsConnectInitial { user_data })
    }
}

/// MCS Connect-Response PDU
#[derive(Debug)]
pub struct McsConnectResponse {
    pub result: McsResult,
    pub called_connect_id: i32,
    pub domain_parameters: McsDomainParameters,
    pub user_data: Vec<u8>, // GCC Conference Create Response
}

impl McsConnectResponse {
    /// Create a successful MCS Connect-Response
    pub fn new_success(user_data: Vec<u8>) -> Self {
        McsConnectResponse {
            result: McsResult::Successful,
            called_connect_id: 0,
            domain_parameters: McsDomainParameters::default(),
            user_data,
        }
    }

    /// Encode MCS Connect-Response to BER
    pub fn encode(&self) -> Result<Vec<u8>> {
        debug!(
            "McsConnectResponse::encode: result={:?}, user_data={} bytes",
            self.result,
            self.user_data.len()
        );
        let mut encoder = BerEncoder::with_capacity(512 + self.user_data.len());

        // Write outer application tag [APPLICATION 102] IMPLICIT SEQUENCE
        // This writes 0x7F 0x66 for APPLICATION class, tag number 102
        // The APPLICATION tag is IMPLICIT, replacing the SEQUENCE tag
        encoder.write_application_tag(102);
        debug!("Wrote MCS Connect-Response APPLICATION tag (102)");

        // We'll need to come back and fix the length
        let outer_len_pos = encoder.as_slice().len();
        encoder.write_length(0); // Placeholder

        // Write fields directly (no inner SEQUENCE since APPLICATION is IMPLICIT)
        // Write result (ENUMERATED)
        encoder.write_enumerated(self.result as u8);
        debug!("Wrote result: {:?}", self.result);

        // Write called connect ID (INTEGER)
        encoder.write_integer(self.called_connect_id);
        debug!("Wrote called connect ID: {}", self.called_connect_id);

        // Write domain parameters (SEQUENCE)
        self.domain_parameters.encode(&mut encoder);
        debug!("Encoded domain parameters");

        // Write user data (OCTET STRING)
        encoder.write_octet_string(&self.user_data);
        debug!("Wrote user data: {} bytes", self.user_data.len());

        // Fix outer length
        let total_len = encoder.as_slice().len();
        let result = encoder.finish();

        // Calculate length of everything after the outer length field
        let content_length = total_len - outer_len_pos - 1; // -1 for the length byte itself
        debug!(
            "Fixing outer length: total={}, content={}",
            total_len, content_length
        );

        // Re-encode with proper length
        let mut final_encoder = BerEncoder::with_capacity(total_len + 10);
        final_encoder.write_application_tag(102);
        final_encoder.write_length(content_length);

        // Copy the rest
        final_encoder
            .buffer
            .extend_from_slice(&result[outer_len_pos + 1..]);

        let encoded = final_encoder.finish();
        debug!("MCS Connect-Response encoded: {} bytes", encoded.len());
        Ok(encoded)
    }
}

/// MCS Erect Domain Request
#[derive(Debug)]
pub struct McsErectDomainRequest;

impl McsErectDomainRequest {
    /// Decode MCS Erect Domain Request
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 5 {
            bail!("MCS Erect Domain Request too short");
        }

        // First byte should be MCS_ERECT_DOMAIN_REQUEST (0x04)
        if data[0] != MCS_ERECT_DOMAIN_REQUEST {
            bail!("Invalid MCS Erect Domain Request tag: 0x{:02X}", data[0]);
        }

        debug!("MCS Erect Domain Request received");

        Ok(McsErectDomainRequest)
    }
}

/// MCS Attach User Request
#[derive(Debug)]
pub struct McsAttachUserRequest;

impl McsAttachUserRequest {
    /// Decode MCS Attach User Request
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            bail!("MCS Attach User Request too short");
        }

        // First byte should be MCS_ATTACH_USER_REQUEST (0x28)
        if data[0] != MCS_ATTACH_USER_REQUEST {
            bail!("Invalid MCS Attach User Request tag: 0x{:02X}", data[0]);
        }

        debug!("MCS Attach User Request received");

        Ok(McsAttachUserRequest)
    }
}

/// MCS Attach User Confirm
#[derive(Debug)]
pub struct McsAttachUserConfirm {
    pub result: McsResult,
    pub user_id: u16,
}

impl McsAttachUserConfirm {
    /// Create a successful Attach User Confirm
    pub fn new_success(user_id: u16) -> Self {
        McsAttachUserConfirm {
            result: McsResult::Successful,
            user_id,
        }
    }

    /// Encode MCS Attach User Confirm
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::with_capacity(8);

        // MCS Attach User Confirm tag
        buf.put_u8(MCS_ATTACH_USER_CONFIRM);

        // Result (enumerated, 1 byte)
        buf.put_u8(self.result as u8);

        // User ID: MCS Aligned Basic-PER fixed 2-byte big-endian value
        buf.put_u16(self.user_id);

        debug!("MCS Attach User Confirm: user_id={}", self.user_id);

        Ok(buf.to_vec())
    }
}

/// MCS Channel Join Request
#[derive(Debug)]
pub struct McsChannelJoinRequest {
    pub user_id: u16,
    pub channel_id: u16,
}

impl McsChannelJoinRequest {
    /// Decode MCS Channel Join Request
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 5 {
            bail!("MCS Channel Join Request too short: {} bytes", data.len());
        }

        let mut pos = 0;

        // First byte should be MCS_CHANNEL_JOIN_REQUEST (0x38)
        if data[pos] != MCS_CHANNEL_JOIN_REQUEST {
            bail!("Invalid MCS Channel Join Request tag: 0x{:02X}", data[pos]);
        }
        pos += 1;

        // Read user ID (u16 big-endian)
        if pos + 2 > data.len() {
            bail!("MCS Channel Join Request: not enough data for user_id");
        }
        let user_id = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        // Read channel ID (u16 big-endian)
        if pos + 2 > data.len() {
            bail!("MCS Channel Join Request: not enough data for channel_id");
        }
        let channel_id = u16::from_be_bytes([data[pos], data[pos + 1]]);

        debug!(
            "MCS Channel Join Request: user_id={}, channel_id={}",
            user_id, channel_id
        );

        Ok(McsChannelJoinRequest {
            user_id,
            channel_id,
        })
    }
}

/// MCS Channel Join Confirm
#[derive(Debug)]
pub struct McsChannelJoinConfirm {
    pub result: McsResult,
    pub user_id: u16,
    pub channel_id: u16,
}

impl McsChannelJoinConfirm {
    /// Create a successful Channel Join Confirm
    pub fn new_success(user_id: u16, channel_id: u16) -> Self {
        McsChannelJoinConfirm {
            result: McsResult::Successful,
            user_id,
            channel_id,
        }
    }

    /// Encode MCS Channel Join Confirm
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::with_capacity(16);

        // MCS Channel Join Confirm tag
        buf.put_u8(MCS_CHANNEL_JOIN_CONFIRM);

        // Result (enumerated, 1 byte)
        buf.put_u8(self.result as u8);

        // User ID (MCS PER encoding: u16 big-endian)
        buf.put_u16(self.user_id);

        // Requested Channel ID (MCS PER encoding: u16 big-endian)
        buf.put_u16(self.channel_id);

        // Actual Channel ID (same as requested for success, MCS PER encoding: u16 big-endian)
        buf.put_u16(self.channel_id);

        debug!(
            "MCS Channel Join Confirm: user_id={}, channel_id={}",
            self.user_id, self.channel_id
        );

        Ok(buf.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_parameters_encode_decode() {
        let params = McsDomainParameters::default();

        let mut encoder = BerEncoder::with_capacity(1024);
        params.encode(&mut encoder);
        let encoded = encoder.finish();

        let mut decoder = BerDecoder::new(&encoded);
        let decoded = McsDomainParameters::decode(&mut decoder).unwrap();

        assert_eq!(params.max_channel_ids, decoded.max_channel_ids);
        assert_eq!(params.max_user_ids, decoded.max_user_ids);
        assert_eq!(params.protocol_version, decoded.protocol_version);
    }

    #[test]
    fn test_attach_user_confirm_encode() {
        let confirm = McsAttachUserConfirm::new_success(1002);
        let encoded = confirm.encode().unwrap();

        assert_eq!(encoded[0], MCS_ATTACH_USER_CONFIRM);
        assert_eq!(encoded[1], McsResult::Successful as u8);
    }

    #[test]
    fn test_channel_join_confirm_encode() {
        let confirm = McsChannelJoinConfirm::new_success(1002, 1003);
        let encoded = confirm.encode().unwrap();

        assert_eq!(encoded[0], MCS_CHANNEL_JOIN_CONFIRM);
        assert_eq!(encoded[1], McsResult::Successful as u8);
    }
}
