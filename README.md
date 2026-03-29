# rdpfb

Serve any framebuffer over RDP.

Implement the `RdpApplication` trait, hand it to `RdpServer`, and any
standard RDP client can connect and see your content. You render pixels;
rdpfb handles the protocol, TLS, input events, dirty-tile detection, and
wire encoding.

## Example

A complete interactive example is included — a canvas with a bouncing ball,
mouse drawing, and keyboard text input:

```sh
cargo run --example canvas
```

Then connect:
```sh
xfreerdp /v:localhost /size:800x600 /cert:ignore /u:test /p:test
```

## Minimal usage

```rust
use rdpfb::prelude::*;
use std::sync::Arc;
use tokio::sync::Notify;

struct MyApp { notify: Arc<Notify> }

impl RdpApplication for MyApp {
    fn on_connect(&mut self, w: u16, h: u16, fb: &mut Framebuffer) -> anyhow::Result<()> {
        fb.fill_rect(10, 10, 100, 100, Color::new(255, 0, 0));
        Ok(())
    }
    fn on_input(&mut self, _event: InputEvent) -> anyhow::Result<()> { Ok(()) }
    fn render(&mut self, _fb: &mut Framebuffer) -> anyhow::Result<bool> { Ok(false) }
    fn content_notify(&self) -> Arc<Notify> { self.notify.clone() }
}

struct Factory;
impl RdpApplicationFactory for Factory {
    fn create(&self) -> anyhow::Result<Box<dyn RdpApplication>> {
        Ok(Box::new(MyApp { notify: Arc::new(Notify::new()) }))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = RdpServerConfig {
        address: "0.0.0.0".into(),
        port: 3389,
        width: 1024,
        height: 768,
        enable_tls: true,
        tls_config: Some(TlsConfig {
            cert_path: "certs/server.crt".into(),
            key_path: "certs/server.key".into(),
        }),
    };
    RdpServer::new(config, Arc::new(Factory), None).run().await
}
```

## Traits

- **`RdpApplication`** — your application: `on_connect`, `on_input`, `render`, `content_notify`
- **`RdpApplicationFactory`** — creates one application instance per connection
- **`RdpAuthenticator`** — optional credential validation

## Features

- Full RDP 5.x protocol (TPKT, X.224, MCS/T.125, GCC, capabilities exchange)
- TLS 1.3 via rustls
- Fastpath and slow-path keyboard/mouse input
- RGBA framebuffer with dirty-tile tracking and batched wire writes
- 60fps frame rate cap
- Per-IP rate limiting and connection limiting

## Generating TLS certificates

```sh
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout certs/server.key -out certs/server.crt \
  -days 365 -subj "/CN=localhost"
```

## Licence

ISC
