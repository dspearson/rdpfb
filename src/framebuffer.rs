/// Framebuffer — RGBA pixel buffer for terminal rendering
///
/// Stores pixels as RGBA8888 internally so the RDP bitmap encoder
/// can read them directly without per-frame format conversion.
///
/// RGB colour (alpha is always 255 in the public API)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Color {
    pub fn new(r: u8, g: u8, b: u8) -> Self {
        Color { r, g, b }
    }
}

/// RGBA8888 pixel buffer
pub struct Framebuffer {
    width: usize,
    height: usize,
    pixels: Vec<u8>, // width * height * 4 (RGBA)
}

impl Framebuffer {
    pub fn new(width: usize, height: usize) -> Self {
        // Pre-fill with black, alpha=255
        let mut pixels = vec![0u8; width * height * 4];
        for chunk in pixels.chunks_exact_mut(4) {
            chunk[3] = 255;
        }
        Framebuffer {
            width,
            height,
            pixels,
        }
    }

    pub fn width(&self) -> usize {
        self.width
    }

    pub fn height(&self) -> usize {
        self.height
    }

    /// Direct access to the RGBA pixel buffer (read-only)
    pub fn as_rgba(&self) -> &[u8] {
        &self.pixels
    }

    pub fn clear(&mut self, color: Color) {
        for chunk in self.pixels.chunks_exact_mut(4) {
            chunk[0] = color.r;
            chunk[1] = color.g;
            chunk[2] = color.b;
            // chunk[3] is already 255
        }
    }

    #[inline]
    pub fn set_pixel(&mut self, x: usize, y: usize, color: Color) {
        if x >= self.width || y >= self.height {
            return;
        }
        let offset = (y * self.width + x) * 4;
        self.pixels[offset] = color.r;
        self.pixels[offset + 1] = color.g;
        self.pixels[offset + 2] = color.b;
        // alpha stays 255
    }

    pub fn get_pixel(&self, x: usize, y: usize) -> Option<Color> {
        if x >= self.width || y >= self.height {
            return None;
        }
        let offset = (y * self.width + x) * 4;
        Some(Color {
            r: self.pixels[offset],
            g: self.pixels[offset + 1],
            b: self.pixels[offset + 2],
        })
    }

    /// Fill a rectangle — uses direct slice writes, no per-pixel bounds checks
    pub fn fill_rect(&mut self, x: usize, y: usize, width: usize, height: usize, color: Color) {
        let x_end = (x + width).min(self.width);
        let y_end = (y + height).min(self.height);
        if x >= self.width || y >= self.height {
            return;
        }

        // Build one scanline of the fill colour
        let row_pixels = x_end - x;
        let mut row = vec![0u8; row_pixels * 4];
        for chunk in row.chunks_exact_mut(4) {
            chunk[0] = color.r;
            chunk[1] = color.g;
            chunk[2] = color.b;
            chunk[3] = 255;
        }

        for dy in y..y_end {
            let start = (dy * self.width + x) * 4;
            let end = start + row_pixels * 4;
            self.pixels[start..end].copy_from_slice(&row);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_framebuffer_creation() {
        let fb = Framebuffer::new(800, 600);
        assert_eq!(fb.width(), 800);
        assert_eq!(fb.height(), 600);
        assert_eq!(fb.as_rgba().len(), 800 * 600 * 4);
    }

    #[test]
    fn test_pixel_operations() {
        let mut fb = Framebuffer::new(10, 10);
        let red = Color::new(255, 0, 0);

        fb.set_pixel(5, 5, red);
        assert_eq!(fb.get_pixel(5, 5), Some(red));

        // Verify RGBA storage directly
        let offset = (5 * 10 + 5) * 4;
        assert_eq!(fb.as_rgba()[offset], 255); // R
        assert_eq!(fb.as_rgba()[offset + 1], 0); // G
        assert_eq!(fb.as_rgba()[offset + 2], 0); // B
        assert_eq!(fb.as_rgba()[offset + 3], 255); // A
    }

    #[test]
    fn test_fill_rect() {
        let mut fb = Framebuffer::new(10, 10);
        let blue = Color::new(0, 0, 255);
        fb.fill_rect(2, 2, 3, 3, blue);
        assert_eq!(fb.get_pixel(2, 2), Some(blue));
        assert_eq!(fb.get_pixel(4, 4), Some(blue));
        assert_eq!(fb.get_pixel(5, 5), Some(Color::new(0, 0, 0)));
    }

    #[test]
    fn test_fill_rect_clipping() {
        let mut fb = Framebuffer::new(10, 10);
        let red = Color::new(255, 0, 0);
        // Should not panic when rect extends beyond framebuffer
        fb.fill_rect(8, 8, 5, 5, red);
        assert_eq!(fb.get_pixel(9, 9), Some(red));
    }

    #[test]
    fn test_clear_sets_all_pixels() {
        let mut fb = Framebuffer::new(4, 4);
        let green = Color::new(0, 255, 0);
        fb.clear(green);

        for y in 0..4 {
            for x in 0..4 {
                assert_eq!(fb.get_pixel(x, y), Some(green));
            }
        }
    }

    #[test]
    fn test_as_rgba_length_and_alpha() {
        let fb = Framebuffer::new(3, 2);
        let rgba = fb.as_rgba();
        assert_eq!(rgba.len(), 3 * 2 * 4);

        // Every 4th byte (alpha channel) should be 255
        for chunk in rgba.chunks_exact(4) {
            assert_eq!(chunk[3], 255);
        }
    }

    #[test]
    fn test_set_pixel_out_of_bounds() {
        let mut fb = Framebuffer::new(5, 5);
        // These should silently do nothing, not panic
        fb.set_pixel(5, 0, Color::new(255, 0, 0));
        fb.set_pixel(0, 5, Color::new(255, 0, 0));
        fb.set_pixel(100, 100, Color::new(255, 0, 0));

        // Verify the framebuffer is unchanged (all black)
        assert_eq!(fb.get_pixel(4, 4), Some(Color::new(0, 0, 0)));
    }

    #[test]
    fn test_get_pixel_out_of_bounds() {
        let fb = Framebuffer::new(5, 5);
        assert_eq!(fb.get_pixel(5, 0), None);
        assert_eq!(fb.get_pixel(0, 5), None);
        assert_eq!(fb.get_pixel(100, 100), None);
    }

    #[test]
    fn test_zero_size_framebuffer() {
        let fb = Framebuffer::new(0, 0);
        assert_eq!(fb.width(), 0);
        assert_eq!(fb.height(), 0);
        assert_eq!(fb.as_rgba().len(), 0);
        assert_eq!(fb.get_pixel(0, 0), None);
    }

    #[test]
    fn test_fill_rect_zero_dimensions() {
        let mut fb = Framebuffer::new(10, 10);
        let red = Color::new(255, 0, 0);
        // Zero width/height should not change anything
        fb.fill_rect(5, 5, 0, 0, red);
        // The pixel at (5,5) should still be black
        assert_eq!(fb.get_pixel(5, 5), Some(Color::new(0, 0, 0)));
    }
}
