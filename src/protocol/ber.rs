/// BER (Basic Encoding Rules) encoder/decoder
///
/// Implements ASN.1 BER encoding as required by [ITU-T X.690] for MCS PDUs.
/// Reference: [ITU-T T.125] Multipoint Communication Service Protocol Specification
///
/// MCS uses BER-encoded PDUs for connection establishment.
use anyhow::{Result, bail};
use bytes::{BufMut, BytesMut};

/// Common BER universal tags
const BER_TAG_BOOLEAN: u8 = 0x01;
const BER_TAG_INTEGER: u8 = 0x02;
const BER_TAG_OCTET_STRING: u8 = 0x04;
const BER_TAG_ENUMERATED: u8 = 0x0A;
const BER_TAG_SEQUENCE: u8 = 0x30;

/// BER primitive/constructed bit
const BER_CONSTRUCTED: u8 = 0x20;

/// BER encoder
pub struct BerEncoder {
    pub(crate) buffer: BytesMut,
}

impl BerEncoder {
    /// Create with specific capacity
    pub fn with_capacity(capacity: usize) -> Self {
        BerEncoder {
            buffer: BytesMut::with_capacity(capacity),
        }
    }

    /// Write a BER tag
    pub fn write_tag(&mut self, tag: u8) {
        self.buffer.put_u8(tag);
    }

    /// Write a multi-byte APPLICATION tag
    /// For APPLICATION class tags with tag number >= 31
    /// Encodes as: 0x7F (APPLICATION | CONSTRUCTED | 0x1F) followed by tag number bytes
    pub fn write_application_tag(&mut self, tag_number: u32) {
        // Write first byte: APPLICATION (0x40) | CONSTRUCTED (0x20) | MORE_FOLLOWS (0x1F)
        self.buffer.put_u8(0x7F);

        // Encode tag number in base-128 with high bit indicating more bytes
        if tag_number < 128 {
            // Single byte encoding
            self.buffer.put_u8(tag_number as u8);
        } else {
            // Multi-byte encoding - not commonly used for MCS which uses 101, 102, etc.
            let mut bytes = Vec::new();
            let mut n = tag_number;

            // Encode from least significant to most significant
            bytes.push((n & 0x7F) as u8);
            n >>= 7;

            while n > 0 {
                bytes.push(((n & 0x7F) | 0x80) as u8);
                n >>= 7;
            }

            // Write in reverse order (most significant first)
            for byte in bytes.iter().rev() {
                self.buffer.put_u8(*byte);
            }
        }
    }

    /// Write a BER length field
    ///
    /// BER length encoding:
    /// - Short form (< 128): single byte with length
    /// - Long form (>= 128): first byte = 0x80 + num_length_bytes, followed by length bytes
    pub fn write_length(&mut self, length: usize) {
        if length < 128 {
            // Short form
            self.buffer.put_u8(length as u8);
        } else if length < 256 {
            // Long form: 1 byte for length
            self.buffer.put_u8(0x81); // 0x80 | 1
            self.buffer.put_u8(length as u8);
        } else if length < 65536 {
            // Long form: 2 bytes for length
            self.buffer.put_u8(0x82); // 0x80 | 2
            self.buffer.put_u16(length as u16);
        } else {
            // Long form: 4 bytes for length (max we support)
            self.buffer.put_u8(0x84); // 0x80 | 4
            self.buffer.put_u32(length as u32);
        }
    }

    /// Write a BER integer (signed, big-endian)
    pub fn write_integer(&mut self, value: i32) {
        self.write_tag(BER_TAG_INTEGER);

        // Calculate minimum bytes needed
        let bytes = if value == 0 {
            vec![0]
        } else if value > 0 {
            let mut v = value;
            let mut bytes = Vec::new();
            while v > 0 {
                bytes.insert(0, (v & 0xFF) as u8);
                v >>= 8;
            }
            // Add leading zero if high bit is set (to keep it positive)
            if bytes[0] & 0x80 != 0 {
                bytes.insert(0, 0);
            }
            bytes
        } else {
            // Negative numbers (two's complement)
            let mut v = (!value) as u32;
            let mut bytes = Vec::new();
            while v > 0 {
                bytes.insert(0, !((v & 0xFF) as u8));
                v >>= 8;
            }
            bytes
        };

        self.write_length(bytes.len());
        self.buffer.extend_from_slice(&bytes);
    }

    /// Write a BER octet string
    pub fn write_octet_string(&mut self, data: &[u8]) {
        self.write_tag(BER_TAG_OCTET_STRING);
        self.write_length(data.len());
        self.buffer.extend_from_slice(data);
    }

    /// Write a BER enumerated value
    pub fn write_enumerated(&mut self, value: u8) {
        self.write_tag(BER_TAG_ENUMERATED);
        self.write_length(1);
        self.buffer.put_u8(value);
    }

    /// Start a constructed sequence (returns position for later length fixup)
    pub fn start_sequence(&mut self) -> usize {
        self.write_tag(BER_TAG_SEQUENCE);
        let pos = self.buffer.len();
        // Reserve space for length (we'll fix it later)
        self.buffer.put_u8(0);
        pos
    }

    /// End a sequence and fix up the length
    pub fn end_sequence(&mut self, start_pos: usize) {
        let content_length = self.buffer.len() - start_pos - 1;

        // Calculate how many bytes we need for the length
        let length_bytes = if content_length < 128 {
            vec![content_length as u8]
        } else if content_length < 256 {
            vec![0x81, content_length as u8]
        } else if content_length < 65536 {
            vec![
                0x82,
                (content_length >> 8) as u8,
                (content_length & 0xFF) as u8,
            ]
        } else {
            vec![
                0x84,
                (content_length >> 24) as u8,
                (content_length >> 16) as u8,
                (content_length >> 8) as u8,
                (content_length & 0xFF) as u8,
            ]
        };

        // If we need more than 1 byte, we need to shift everything
        if length_bytes.len() > 1 {
            let shift_amount = length_bytes.len() - 1;
            let old_len = self.buffer.len();
            self.buffer.resize(old_len + shift_amount, 0);

            // Shift content right
            for i in (start_pos + 1..old_len).rev() {
                self.buffer[i + shift_amount] = self.buffer[i];
            }
        }

        // Write the length bytes
        for (i, &byte) in length_bytes.iter().enumerate() {
            self.buffer[start_pos + i] = byte;
        }
    }

    /// Get the encoded bytes
    pub fn finish(self) -> Vec<u8> {
        self.buffer.to_vec()
    }

    /// Get a reference to the buffer
    pub fn as_slice(&self) -> &[u8] {
        &self.buffer
    }
}

/// BER decoder
pub struct BerDecoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BerDecoder<'a> {
    /// Create a new BER decoder
    pub fn new(data: &'a [u8]) -> Self {
        BerDecoder { data, pos: 0 }
    }

    /// Read a BER tag
    pub fn read_tag(&mut self) -> Result<u32> {
        if self.pos >= self.data.len() {
            bail!("BER: unexpected end of data reading tag");
        }
        let first_byte = self.data[self.pos];
        self.pos += 1;

        // Check if this is a multi-byte tag (low 5 bits = 0x1F)
        if (first_byte & 0x1F) == 0x1F {
            // Multi-byte tag number follows
            // Read subsequent bytes until we find one with bit 7 clear
            let mut tag_number = 0u32;
            loop {
                if self.pos >= self.data.len() {
                    bail!("BER: unexpected end of data reading multi-byte tag");
                }
                let byte = self.data[self.pos];
                self.pos += 1;

                tag_number = (tag_number << 7) | ((byte & 0x7F) as u32);

                // If bit 7 is clear, this is the last byte
                if (byte & 0x80) == 0 {
                    break;
                }
            }

            // Combine class/constructed bits from first byte with tag number
            // Keep the high 3 bits (class) and bit 5 (constructed) from first_byte
            Ok(((first_byte as u32 & 0xE0) << 24) | tag_number)
        } else {
            // Single-byte tag
            Ok(first_byte as u32)
        }
    }

    /// Read a BER length field
    pub fn read_length(&mut self) -> Result<usize> {
        if self.pos >= self.data.len() {
            bail!("BER: unexpected end of data reading length");
        }

        let first_byte = self.data[self.pos];
        self.pos += 1;

        if first_byte < 0x80 {
            // Short form
            Ok(first_byte as usize)
        } else {
            // Long form
            let num_bytes = (first_byte & 0x7F) as usize;
            if num_bytes == 0 || num_bytes > 4 {
                bail!("BER: invalid length encoding: {} bytes", num_bytes);
            }

            if self.pos + num_bytes > self.data.len() {
                bail!("BER: unexpected end of data reading length bytes");
            }

            let mut length = 0usize;
            for _ in 0..num_bytes {
                length = (length << 8) | (self.data[self.pos] as usize);
                self.pos += 1;
            }

            Ok(length)
        }
    }

    /// Read a BER integer
    pub fn read_integer(&mut self) -> Result<i32> {
        let tag = self.read_tag()?;
        if tag != BER_TAG_INTEGER as u32 {
            bail!("BER: expected INTEGER tag, got 0x{:08X}", tag);
        }

        let length = self.read_length()?;
        if length == 0 || length > 4 {
            bail!("BER: invalid integer length: {}", length);
        }

        if self.pos + length > self.data.len() {
            bail!("BER: unexpected end of data reading integer");
        }

        let mut value = 0i32;
        let is_negative = (self.data[self.pos] & 0x80) != 0;

        for i in 0..length {
            value = (value << 8) | (self.data[self.pos + i] as i32);
        }

        self.pos += length;

        // Handle sign extension for negative numbers
        if is_negative && length < 4 {
            let sign_extend = !((1 << (length * 8)) - 1);
            value |= sign_extend;
        }

        Ok(value)
    }

    /// Read a BER octet string
    pub fn read_octet_string(&mut self) -> Result<Vec<u8>> {
        let tag = self.read_tag()?;
        if tag != BER_TAG_OCTET_STRING as u32 {
            bail!("BER: expected OCTET STRING tag, got 0x{:08X}", tag);
        }

        let length = self.read_length()?;
        if self.pos + length > self.data.len() {
            bail!("BER: unexpected end of data reading octet string");
        }

        let data = self.data[self.pos..self.pos + length].to_vec();
        self.pos += length;

        Ok(data)
    }

    /// Read a BER boolean
    pub fn read_boolean(&mut self) -> Result<bool> {
        let tag = self.read_tag()?;
        if tag != BER_TAG_BOOLEAN as u32 {
            bail!("BER: expected BOOLEAN tag, got 0x{:08X}", tag);
        }

        let length = self.read_length()?;
        if length != 1 {
            bail!("BER: invalid boolean length: {}", length);
        }

        if self.pos >= self.data.len() {
            bail!("BER: unexpected end of data reading boolean");
        }

        let value = self.data[self.pos] != 0;
        self.pos += 1;

        Ok(value)
    }

    /// Read a BER sequence header (returns content length)
    pub fn read_sequence(&mut self) -> Result<usize> {
        let tag = self.read_tag()?;
        if tag != BER_TAG_SEQUENCE as u32 && tag != (BER_TAG_SEQUENCE | BER_CONSTRUCTED) as u32 {
            bail!("BER: expected SEQUENCE tag, got 0x{:08X}", tag);
        }

        self.read_length()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_integer() {
        let mut enc = BerEncoder::with_capacity(1024);
        enc.write_integer(42);
        enc.write_integer(-100);
        enc.write_integer(0);

        let bytes = enc.finish();
        let mut dec = BerDecoder::new(&bytes);

        assert_eq!(dec.read_integer().unwrap(), 42);
        assert_eq!(dec.read_integer().unwrap(), -100);
        assert_eq!(dec.read_integer().unwrap(), 0);
    }

    #[test]
    fn test_encode_decode_octet_string() {
        let mut enc = BerEncoder::with_capacity(1024);
        let data = b"Hello, BER!";
        enc.write_octet_string(data);

        let bytes = enc.finish();
        let mut dec = BerDecoder::new(&bytes);

        assert_eq!(dec.read_octet_string().unwrap(), data);
    }

    #[test]
    fn test_encode_sequence() {
        let mut enc = BerEncoder::with_capacity(1024);
        let start = enc.start_sequence();
        enc.write_integer(1);
        enc.write_integer(2);
        enc.write_integer(3);
        enc.end_sequence(start);

        let bytes = enc.finish();
        let mut dec = BerDecoder::new(&bytes);

        let len = dec.read_sequence().unwrap();
        assert!(len > 0);
        assert_eq!(dec.read_integer().unwrap(), 1);
        assert_eq!(dec.read_integer().unwrap(), 2);
        assert_eq!(dec.read_integer().unwrap(), 3);
    }
}
