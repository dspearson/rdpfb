/// canvas — interactive drawing example for rdpfb
///
/// Demonstrates all RdpApplication trait methods:
/// - on_connect: sets up a canvas with a gradient background
/// - on_input: draws with the mouse, types text with keyboard
/// - render: animates a bouncing ball
/// - content_notify: ball animation triggers redraws
///
/// Run:   cargo run --example canvas
/// Connect: xfreerdp /v:localhost /size:800x600 /cert:ignore /u:test /p:test

use anyhow::Result;
use rdpfb::prelude::*;
use std::sync::Arc;
use tokio::sync::Notify;

struct Canvas {
    notify: Arc<Notify>,
    width: u16,
    height: u16,
    // Ball animation
    ball_x: f32,
    ball_y: f32,
    ball_dx: f32,
    ball_dy: f32,
    // Mouse drawing
    mouse_down: bool,
    mouse_x: u16,
    mouse_y: u16,
    draw_colour: Color,
    // Keyboard state
    shift: bool,
    pending_chars: Vec<char>,
    // Text cursor
    cursor_x: usize,
    cursor_y: usize,
}

impl Canvas {
    fn draw_ball(&self, fb: &mut Framebuffer) {
        let bx = self.ball_x as usize;
        let by = self.ball_y as usize;
        let radius = 15usize;
        let r2 = (radius * radius) as i32;

        for dy in 0..radius * 2 {
            for dx in 0..radius * 2 {
                let px = bx + dx;
                let py = by + dy;
                let cx = dx as i32 - radius as i32;
                let cy = dy as i32 - radius as i32;
                if cx * cx + cy * cy <= r2 {
                    fb.set_pixel(px, py, Color::new(255, 80, 80));
                }
            }
        }
    }

    fn draw_gradient_bg(&self, fb: &mut Framebuffer) {
        let w = self.width as usize;
        let h = self.height as usize;
        for y in 0..h {
            let r = (y * 40 / h) as u8;
            let g = (y * 60 / h) as u8;
            let b = 80 + (y * 40 / h) as u8;
            for x in 0..w {
                fb.set_pixel(x, y, Color::new(r, g, b));
            }
        }
    }

    fn draw_text_line(&self, fb: &mut Framebuffer, x: usize, y: usize, text: &str) {
        // Simple 5x7 bitmap font for basic ASCII — just enough to show text works
        let char_w = 6;
        for (i, ch) in text.chars().enumerate() {
            let cx = x + i * char_w;
            Self::draw_char(fb, cx, y, ch, Color::new(255, 255, 255));
        }
    }

    fn draw_char(fb: &mut Framebuffer, x: usize, y: usize, ch: char, colour: Color) {
        // Minimal 5x7 glyphs for printable ASCII
        let bitmap: [u8; 7] = match ch {
            'A' | 'a' => [0x20, 0x50, 0x88, 0x88, 0xF8, 0x88, 0x88],
            'B' | 'b' => [0xF0, 0x88, 0x88, 0xF0, 0x88, 0x88, 0xF0],
            'C' | 'c' => [0x70, 0x88, 0x80, 0x80, 0x80, 0x88, 0x70],
            'D' | 'd' => [0xF0, 0x88, 0x88, 0x88, 0x88, 0x88, 0xF0],
            'E' | 'e' => [0xF8, 0x80, 0x80, 0xF0, 0x80, 0x80, 0xF8],
            'F' | 'f' => [0xF8, 0x80, 0x80, 0xF0, 0x80, 0x80, 0x80],
            'H' | 'h' => [0x88, 0x88, 0x88, 0xF8, 0x88, 0x88, 0x88],
            'I' | 'i' => [0x70, 0x20, 0x20, 0x20, 0x20, 0x20, 0x70],
            'L' | 'l' => [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xF8],
            'M' | 'm' => [0x88, 0xD8, 0xA8, 0x88, 0x88, 0x88, 0x88],
            'N' | 'n' => [0x88, 0xC8, 0xA8, 0x98, 0x88, 0x88, 0x88],
            'O' | 'o' => [0x70, 0x88, 0x88, 0x88, 0x88, 0x88, 0x70],
            'P' | 'p' => [0xF0, 0x88, 0x88, 0xF0, 0x80, 0x80, 0x80],
            'R' | 'r' => [0xF0, 0x88, 0x88, 0xF0, 0xA0, 0x90, 0x88],
            'S' | 's' => [0x70, 0x88, 0x80, 0x70, 0x08, 0x88, 0x70],
            'T' | 't' => [0xF8, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20],
            'U' | 'u' => [0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x70],
            'V' | 'v' => [0x88, 0x88, 0x88, 0x88, 0x50, 0x50, 0x20],
            'W' | 'w' => [0x88, 0x88, 0x88, 0x88, 0xA8, 0xD8, 0x88],
            'X' | 'x' => [0x88, 0x88, 0x50, 0x20, 0x50, 0x88, 0x88],
            'Y' | 'y' => [0x88, 0x88, 0x50, 0x20, 0x20, 0x20, 0x20],
            'G' | 'g' => [0x70, 0x88, 0x80, 0xB8, 0x88, 0x88, 0x70],
            'K' | 'k' => [0x88, 0x90, 0xA0, 0xC0, 0xA0, 0x90, 0x88],
            ' ' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            '!' => [0x20, 0x20, 0x20, 0x20, 0x20, 0x00, 0x20],
            ':' => [0x00, 0x20, 0x20, 0x00, 0x20, 0x20, 0x00],
            '.' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20],
            '-' => [0x00, 0x00, 0x00, 0xF8, 0x00, 0x00, 0x00],
            _ => [0xF8, 0x88, 0x88, 0x88, 0x88, 0x88, 0xF8], // box for unknown
        };
        for (row, &bits) in bitmap.iter().enumerate() {
            for col in 0..5 {
                if bits & (0x80 >> col) != 0 {
                    fb.set_pixel(x + col, y + row, colour);
                }
            }
        }
    }
}

impl RdpApplication for Canvas {
    fn on_connect(
        &mut self,
        width: u16,
        height: u16,
        fb: &mut Framebuffer,
    ) -> Result<()> {
        self.width = width;
        self.height = height;
        self.ball_x = width as f32 / 2.0;
        self.ball_y = height as f32 / 2.0;
        self.cursor_x = 10;
        self.cursor_y = 10;

        // Draw gradient background
        self.draw_gradient_bg(fb);

        // Draw instructions
        self.draw_text_line(fb, 10, 10, "RDPFB CANVAS EXAMPLE");
        self.draw_text_line(fb, 10, 25, "DRAW WITH MOUSE");
        self.draw_text_line(fb, 10, 40, "TYPE TO WRITE TEXT");
        self.cursor_y = 65;

        // Start the animation task
        let notify = self.notify.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(16)).await;
                notify.notify_one();
            }
        });

        Ok(())
    }

    fn on_input(&mut self, event: InputEvent) -> Result<()> {
        match event {
            InputEvent::Mouse { flags, x, y } => {
                // MS-RDPBCGR 2.2.8.1.1.3.1.1 TS_POINTER_EVENT:
                //   PTRFLAGS_DOWN=0x8000, BUTTON1=0x1000, BUTTON2=0x2000, BUTTON3=0x4000
                // Press = DOWN | BUTTONn, release = BUTTONn without DOWN
                let has_button = (flags & 0x7000) != 0;
                let is_down = (flags & 0x8000) != 0;
                if has_button {
                    self.mouse_down = is_down;
                }
                self.mouse_x = x;
                self.mouse_y = y;
            }
            InputEvent::Scancode { flags, scancode } => {
                let is_release = (flags & 0x8000) != 0;

                if scancode == 0x2A || scancode == 0x36 {
                    self.shift = !is_release;
                    return Ok(());
                }

                if is_release {
                    return Ok(());
                }

                if let Some(ch) = InputEvent::scancode_to_char(scancode, self.shift) {
                    self.pending_chars.push(ch);
                }
            }
        }
        self.notify.notify_one();
        Ok(())
    }

    fn render(&mut self, fb: &mut Framebuffer) -> Result<bool> {
        // Clear old ball position (restore gradient)
        let old_bx = self.ball_x as usize;
        let old_by = self.ball_y as usize;
        let h = self.height as usize;
        for dy in 0..32 {
            for dx in 0..32 {
                let px = old_bx + dx;
                let py = old_by + dy;
                if px < self.width as usize && py < h {
                    let r = (py * 40 / h) as u8;
                    let g = (py * 60 / h) as u8;
                    let b = 80 + (py * 40 / h) as u8;
                    fb.set_pixel(px, py, Color::new(r, g, b));
                }
            }
        }

        // Advance ball
        self.ball_x += self.ball_dx;
        self.ball_y += self.ball_dy;
        if self.ball_x <= 15.0 || self.ball_x >= (self.width as f32 - 30.0) {
            self.ball_dx = -self.ball_dx;
        }
        if self.ball_y <= 15.0 || self.ball_y >= (self.height as f32 - 30.0) {
            self.ball_dy = -self.ball_dy;
        }
        self.draw_ball(fb);

        // Mouse drawing — paint brush at mouse position when button held
        if self.mouse_down {
            let cx = self.mouse_x as usize;
            let cy = self.mouse_y as usize;
            for dy in 0..6 {
                for dx in 0..6 {
                    fb.set_pixel(cx + dx, cy + dy, self.draw_colour);
                }
            }
        }

        // Draw any pending typed characters
        let chars: Vec<char> = self.pending_chars.drain(..).collect();
        for ch in chars {
            Self::draw_char(fb, self.cursor_x, self.cursor_y, ch, Color::new(255, 255, 255));
            self.cursor_x += 6;
            if self.cursor_x > self.width as usize - 10 {
                self.cursor_x = 10;
                self.cursor_y += 10;
            }
        }

        Ok(true)
    }

    fn content_notify(&self) -> Arc<Notify> {
        self.notify.clone()
    }
}

struct CanvasFactory;

impl RdpApplicationFactory for CanvasFactory {
    fn create(&self) -> Result<Box<dyn RdpApplication>> {
        Ok(Box::new(Canvas {
            notify: Arc::new(Notify::new()),
            width: 0,
            height: 0,
            ball_x: 100.0,
            ball_y: 100.0,
            ball_dx: 2.5,
            ball_dy: 1.8,
            mouse_down: false,
            mouse_x: 0,
            mouse_y: 0,
            draw_colour: Color::new(0, 255, 100),
            shift: false,
            pending_chars: Vec::new(),
            cursor_x: 10,
            cursor_y: 65,
        }))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    println!("rdpfb canvas example");
    println!("Connect with: xfreerdp /v:localhost /size:800x600 /cert:ignore /u:test /p:test");

    let config = RdpServerConfig {
        address: "0.0.0.0".into(),
        port: 3389,
        width: 800,
        height: 600,
        enable_tls: true,
        tls_config: Some(TlsConfig {
            cert_path: "certs/server.crt".into(),
            key_path: "certs/server.key".into(),
        }),
    };

    let server = RdpServer::new(config, Arc::new(CanvasFactory), None);
    server.run().await
}
