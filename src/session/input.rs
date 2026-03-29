/// Input handling for RDP sessions
///
/// Handles fast-path keyboard/mouse input from the RDP client.
use anyhow::Result;
use tracing::{debug, warn};

use crate::protocol::pdu::*;
use crate::protocol::rdp::*;

impl super::RdpSession {
    /// Handle fastpath input PDU
    /// Format: fpInputHeader(1) + length(1-2) + fpInputEvents[]
    /// Each event: eventHeader(1) + eventData(variable)
    pub(super) async fn handle_fastpath_input(&mut self, buf: &[u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        let header = buf[0];
        let _num_events = (header >> 2) & 0x0F; // top 4 bits of action byte
        let _action = header & 0x03;

        // Parse length (1 or 2 bytes)
        let (data_start, _length) = if buf.len() < 2 {
            return Ok(());
        } else if buf[1] & 0x80 == 0 {
            (2usize, buf[1] as usize)
        } else if buf.len() >= 3 {
            (3usize, (((buf[1] & 0x7F) as usize) << 8) | buf[2] as usize)
        } else {
            return Ok(());
        };

        let mut pos = data_start;
        while pos < buf.len() {
            if pos >= buf.len() {
                break;
            }
            let event_header = buf[pos];
            pos += 1;

            // MS-RDPBCGR 2.2.8.1.2.2: eventCode = top 3 bits, eventFlags = bottom 5 bits
            let event_code = (event_header >> 5) & 0x07;
            let event_flags = event_header & 0x1F;

            match event_code {
                0 => {
                    // FASTPATH_INPUT_EVENT_SCANCODE
                    if pos >= buf.len() {
                        break;
                    }
                    let scancode = buf[pos] as u16;
                    pos += 1;

                    let is_release = (event_flags & 0x01) != 0;
                    let is_extended = (event_flags & 0x02) != 0;

                    let flags = if is_release { KBD_FLAG_RELEASE } else { 0 }
                        | if is_extended { KBD_FLAG_EXTENDED } else { 0 };

                    if let Err(e) = self
                        .app
                        .on_input(InputEvent::Scancode { flags, scancode })
                    {
                        warn!("Scancode input error: {}", e);
                    }
                }
                1 => {
                    // FASTPATH_INPUT_EVENT_MOUSE
                    if pos + 6 > buf.len() {
                        break;
                    }
                    let flags = u16::from_le_bytes([buf[pos], buf[pos + 1]]);
                    let x = u16::from_le_bytes([buf[pos + 2], buf[pos + 3]]);
                    let y = u16::from_le_bytes([buf[pos + 4], buf[pos + 5]]);
                    pos += 6;
                    if let Err(e) = self
                        .app
                        .on_input(InputEvent::Mouse { flags, x, y })
                    {
                        warn!("Mouse input error: {}", e);
                    }
                }
                2 => {
                    // FASTPATH_INPUT_EVENT_MOUSEX (extended mouse)
                    if pos + 6 > buf.len() {
                        break;
                    }
                    pos += 6;
                }
                3 => {
                    // FASTPATH_INPUT_EVENT_SYNC
                    // No additional data
                }
                4 => {
                    // FASTPATH_INPUT_EVENT_UNICODE
                    if pos + 2 > buf.len() {
                        break;
                    }
                    // Ignore unicode — handle via scancode only
                    pos += 2;
                }
                5 => {
                    // FASTPATH_INPUT_EVENT_QOE_TIMESTAMP
                    if pos + 4 > buf.len() {
                        break;
                    }
                    pos += 4;
                }
                _ => {
                    debug!("Unknown fastpath event code: {}", event_code);
                    break;
                }
            }
        }

        Ok(())
    }
}
