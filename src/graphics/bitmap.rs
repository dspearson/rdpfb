/// Bitmap Update Encoder
///
/// Converts framebuffer data to RDP Bitmap Update PDUs.
/// Reference: [MS-RDPBCGR] Section 2.2.9.1.1.3.1.2 Bitmap Update
///
/// Uncompressed bitmaps: 8-bit indexed, 16-bit RGB565, or 24-bit RGB888.
use anyhow::{Result, bail};
use bytes::{BufMut, BytesMut};
use tracing::debug;

/// Bitmap Update PDU type (UPDATE_TYPE_BITMAP from RDP spec)
const UPDATE_TYPE_BITMAP: u16 = 1;

/// Bitmap rectangle for update
#[derive(Debug, Clone)]
pub struct BitmapRectangle {
    pub left: u16,
    pub top: u16,
    pub width: u16,
    pub height: u16,
    pub bpp: u16,      // Bits per pixel (8, 16, or 24)
    pub data: Vec<u8>, // Bitmap data in bottom-up scanline order
}

impl BitmapRectangle {
    /// Create a new bitmap rectangle from RGBA framebuffer data
    ///
    /// Converts RGBA8888 to RGB565 or RGB888 and flips to bottom-up scanline order.
    pub fn from_rgba(
        left: u16,
        top: u16,
        width: u16,
        height: u16,
        rgba_data: &[u8],
        target_bpp: u16,
    ) -> Result<Self> {
        if rgba_data.len() != (width as usize * height as usize * 4) {
            bail!(
                "RGBA data size mismatch: expected {}, got {}",
                width as usize * height as usize * 4,
                rgba_data.len()
            );
        }

        let mut data = Vec::new();

        match target_bpp {
            8 => {
                // Convert RGBA8888 to 8-bit indexed colour (3-3-2 RGB palette)
                // RDP uses a 256-colour palette with 3 bits red, 3 bits green, 2 bits blue
                for y in (0..height).rev() {
                    for x in 0..width {
                        let offset = ((y as usize * width as usize) + x as usize) * 4;
                        let r = rgba_data[offset];
                        let g = rgba_data[offset + 1];
                        let b = rgba_data[offset + 2];
                        // A is ignored

                        // Convert to 3-3-2: 3 bits red, 3 bits green, 2 bits blue
                        let r3 = (r >> 5) & 0x07; // Top 3 bits
                        let g3 = (g >> 5) & 0x07; // Top 3 bits
                        let b2 = (b >> 6) & 0x03; // Top 2 bits
                        let index = (r3 << 5) | (g3 << 2) | b2;
                        data.push(index);
                    }

                    // Scanlines must be DWORD-aligned (4-byte boundary)
                    let scanline_bytes = width as usize;
                    let padding = (4 - (scanline_bytes % 4)) % 4;
                    data.extend(std::iter::repeat_n(0u8, padding));
                }
            }
            16 => {
                // Convert RGBA8888 to RGB565 (bottom-up scanlines)
                for y in (0..height).rev() {
                    for x in 0..width {
                        let offset = ((y as usize * width as usize) + x as usize) * 4;
                        let r = rgba_data[offset];
                        let g = rgba_data[offset + 1];
                        let b = rgba_data[offset + 2];
                        // A is ignored

                        // RGB565: 5 bits red, 6 bits green, 5 bits blue
                        let r5 = (r >> 3) as u16;
                        let g6 = (g >> 2) as u16;
                        let b5 = (b >> 3) as u16;
                        let rgb565 = (r5 << 11) | (g6 << 5) | b5;

                        // Little-endian
                        data.push((rgb565 & 0xFF) as u8);
                        data.push((rgb565 >> 8) as u8);
                    }
                }
            }
            24 => {
                // Convert RGBA8888 to RGB888/BGR888 (bottom-up scanlines)
                // RDP uses BGR order for 24-bit colour
                for y in (0..height).rev() {
                    for x in 0..width {
                        let offset = ((y as usize * width as usize) + x as usize) * 4;
                        let r = rgba_data[offset];
                        let g = rgba_data[offset + 1];
                        let b = rgba_data[offset + 2];
                        // A is ignored

                        // BGR order
                        data.push(b);
                        data.push(g);
                        data.push(r);
                    }

                    // Scanlines must be DWORD-aligned (4-byte boundary)
                    let scanline_bytes = width as usize * 3;
                    let padding = (4 - (scanline_bytes % 4)) % 4;
                    data.extend(std::iter::repeat_n(0u8, padding));
                }
            }
            _ => bail!(
                "Unsupported BPP: {} (only 8, 16, and 24 supported)",
                target_bpp
            ),
        }

        debug!(
            "Bitmap rectangle: {}x{} at ({},{}), {} bpp, {} bytes",
            width,
            height,
            left,
            top,
            target_bpp,
            data.len()
        );

        Ok(BitmapRectangle {
            left,
            top,
            width,
            height,
            bpp: target_bpp,
            data,
        })
    }

    /// Encode this bitmap rectangle, with optional RLE compression
    fn encode(&self) -> Result<Vec<u8>> {
        let bitmap_data = &self.data;
        let flags: u16 = 0x0000; // uncompressed

        let mut buf = BytesMut::with_capacity(bitmap_data.len() + 26);

        buf.put_u16_le(self.left);
        buf.put_u16_le(self.top);
        buf.put_u16_le(self.left + self.width - 1); // right (inclusive)
        buf.put_u16_le(self.top + self.height - 1); // bottom (inclusive)
        buf.put_u16_le(self.width);
        buf.put_u16_le(self.height);
        buf.put_u16_le(self.bpp);
        buf.put_u16_le(flags);
        buf.put_u16_le(bitmap_data.len() as u16);
        buf.extend_from_slice(bitmap_data);

        Ok(buf.to_vec())
    }
}

/// Bitmap Update PDU
#[derive(Debug)]
pub struct BitmapUpdate {
    pub rectangles: Vec<BitmapRectangle>,
}

impl BitmapUpdate {
    /// Create a new bitmap update with a single rectangle
    pub fn new(rectangle: BitmapRectangle) -> Self {
        BitmapUpdate {
            rectangles: vec![rectangle],
        }
    }

    /// Encode bitmap update as RDP Update PDU data
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::with_capacity(4096);

        // Update type (u16 LE) - UPDATE_TYPE_BITMAP
        buf.put_u16_le(UPDATE_TYPE_BITMAP);

        // Number of rectangles (u16 LE)
        buf.put_u16_le(self.rectangles.len() as u16);

        // Encode each rectangle
        for rect in &self.rectangles {
            let rect_data = rect.encode()?;
            buf.extend_from_slice(&rect_data);
        }

        debug!(
            "Bitmap update: {} rectangles, {} bytes total",
            self.rectangles.len(),
            buf.len()
        );

        Ok(buf.to_vec())
    }
}

#[cfg(test)]
fn create_fullscreen_update(
    width: u16,
    height: u16,
    rgba_data: &[u8],
    target_bpp: u16,
) -> Result<BitmapUpdate> {
    // Calculate max tile size to stay under 65KB limit
    // Leave some headroom for headers and padding
    const MAX_TILE_BYTES: usize = 60000;

    let bytes_per_pixel = match target_bpp {
        8 => 1,
        16 => 2,
        24 => 3,
        _ => bail!("Unsupported BPP: {}", target_bpp),
    };

    // Calculate tile dimensions (square tiles for simplicity)
    let max_pixels_per_tile = MAX_TILE_BYTES / bytes_per_pixel;
    let tile_size = (max_pixels_per_tile as f64).sqrt() as u16;
    // Align to 64 pixels for efficiency
    let tile_size = (tile_size / 64) * 64;

    debug!(
        "Tiling fullscreen {}x{} with tile size {}x{} ({} bpp)",
        width, height, tile_size, tile_size, target_bpp
    );

    let mut rectangles = Vec::new();

    // Split screen into tiles
    let mut y = 0;
    while y < height {
        let tile_height = (height - y).min(tile_size);
        let mut x = 0;

        while x < width {
            let tile_width = (width - x).min(tile_size);

            // Extract tile from full RGBA data
            let mut tile_rgba = Vec::with_capacity(tile_width as usize * tile_height as usize * 4);
            for ty in 0..tile_height {
                let src_y = y + ty;
                let src_offset = (src_y as usize * width as usize + x as usize) * 4;
                let src_end = src_offset + (tile_width as usize * 4);
                tile_rgba.extend_from_slice(&rgba_data[src_offset..src_end]);
            }

            let rectangle =
                BitmapRectangle::from_rgba(x, y, tile_width, tile_height, &tile_rgba, target_bpp)?;
            rectangles.push(rectangle);

            x += tile_width;
        }
        y += tile_height;
    }

    debug!("Created {} tiles for fullscreen update", rectangles.len());
    Ok(BitmapUpdate { rectangles })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitmap_rectangle_16bpp() {
        // Create a 2x2 red square
        let rgba = vec![
            255, 0, 0, 255, // Red
            255, 0, 0, 255, // Red
            255, 0, 0, 255, // Red
            255, 0, 0, 255, // Red
        ];

        let rect = BitmapRectangle::from_rgba(0, 0, 2, 2, &rgba, 16).unwrap();

        assert_eq!(rect.width, 2);
        assert_eq!(rect.height, 2);
        assert_eq!(rect.bpp, 16);

        // RGB565 red = 0xF800 (11111 000000 00000)
        // In little-endian: 0x00, 0xF8
        assert_eq!(rect.data.len(), 8); // 2x2 pixels * 2 bytes each
        assert_eq!(rect.data[0], 0x00);
        assert_eq!(rect.data[1], 0xF8);
    }

    #[test]
    fn test_bitmap_rectangle_24bpp() {
        // Create a 2x2 blue square
        let rgba = vec![
            0, 0, 255, 255, // Blue
            0, 0, 255, 255, // Blue
            0, 0, 255, 255, // Blue
            0, 0, 255, 255, // Blue
        ];

        let rect = BitmapRectangle::from_rgba(0, 0, 2, 2, &rgba, 24).unwrap();

        assert_eq!(rect.width, 2);
        assert_eq!(rect.height, 2);
        assert_eq!(rect.bpp, 24);

        // BGR order: blue=255, green=0, red=0
        // 2 pixels per scanline * 3 bytes = 6 bytes
        // Padding to DWORD: (4 - 6%4) % 4 = 2 bytes padding
        // Total per scanline: 8 bytes
        // 2 scanlines: 16 bytes
        assert_eq!(rect.data.len(), 16);
        assert_eq!(rect.data[0], 255); // B
        assert_eq!(rect.data[1], 0); // G
        assert_eq!(rect.data[2], 0); // R
    }

    #[test]
    fn test_bitmap_update_encode() {
        let rgba = vec![255, 0, 0, 255]; // Single red pixel
        let rect = BitmapRectangle::from_rgba(0, 0, 1, 1, &rgba, 16).unwrap();
        let update = BitmapUpdate::new(rect);

        let encoded = update.encode().unwrap();
        assert!(encoded.len() > 10);

        // Check update type
        assert_eq!(encoded[0], (UPDATE_TYPE_BITMAP & 0xFF) as u8);
        assert_eq!(encoded[1], (UPDATE_TYPE_BITMAP >> 8) as u8);

        // Check number of rectangles
        assert_eq!(encoded[2], 1);
        assert_eq!(encoded[3], 0);
    }

    #[test]
    fn test_fullscreen_update() {
        let width = 4;
        let height = 4;
        let rgba = vec![255u8; (width * height * 4) as usize];

        let update = create_fullscreen_update(width, height, &rgba, 16).unwrap();

        assert_eq!(update.rectangles.len(), 1);
        assert_eq!(update.rectangles[0].width, width);
        assert_eq!(update.rectangles[0].height, height);
    }

    #[test]
    fn test_bitmap_rectangle_8bpp() {
        // 2x2 pixels: red, green, blue, white
        let rgba = vec![
            255, 0, 0, 255, // Red
            0, 255, 0, 255, // Green
            0, 0, 255, 255, // Blue
            255, 255, 255, 255, // White
        ];

        let rect = BitmapRectangle::from_rgba(0, 0, 2, 2, &rgba, 8).unwrap();
        assert_eq!(rect.bpp, 8);
        assert_eq!(rect.width, 2);
        assert_eq!(rect.height, 2);

        // 2 pixels per scanline + 2 bytes padding to reach DWORD alignment = 4 bytes/scanline
        // 2 scanlines = 8 bytes
        assert_eq!(rect.data.len(), 8);

        // Verify 3-3-2 encoding for red pixel (bottom-up, so row 1 first)
        // Blue row (y=1) comes first in bottom-up: blue=(0,0,255), white=(255,255,255)
        // blue: r3=0, g3=0, b2=3 => 0x03
        assert_eq!(rect.data[0], 0x03);
        // white: r3=7, g3=7, b2=3 => (7<<5)|(7<<2)|3 = 224+28+3 = 0xFF
        assert_eq!(rect.data[1], 0xFF);
    }

    #[test]
    fn test_scanline_padding_odd_width_24bpp() {
        // 3 pixels wide, 1 pixel tall
        let rgba = vec![255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255];

        let rect = BitmapRectangle::from_rgba(0, 0, 3, 1, &rgba, 24).unwrap();

        // 3 pixels * 3 bytes = 9 bytes per scanline
        // Padding to DWORD: (4 - 9%4) % 4 = (4 - 1) % 4 = 3 bytes padding
        // Total: 12 bytes
        assert_eq!(rect.data.len(), 12);
    }

    #[test]
    fn test_from_rgba_mismatched_data_size() {
        // 2x2 requires 16 bytes of RGBA, but we provide only 8
        let rgba = vec![0u8; 8];
        let result = BitmapRectangle::from_rgba(0, 0, 2, 2, &rgba, 16);
        assert!(result.is_err());
    }

    #[test]
    fn test_bitmap_update_multiple_rectangles() {
        let rgba1 = vec![255, 0, 0, 255]; // 1x1 red
        let rgba2 = vec![0, 255, 0, 255]; // 1x1 green

        let rect1 = BitmapRectangle::from_rgba(0, 0, 1, 1, &rgba1, 16).unwrap();
        let rect2 = BitmapRectangle::from_rgba(1, 0, 1, 1, &rgba2, 16).unwrap();

        let update = BitmapUpdate {
            rectangles: vec![rect1, rect2],
        };

        let encoded = update.encode().unwrap();
        // Check number of rectangles in encoded output
        let num_rects = u16::from_le_bytes([encoded[2], encoded[3]]);
        assert_eq!(num_rects, 2);
    }
}
