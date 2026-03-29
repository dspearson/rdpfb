use tokio::io::{AsyncRead, AsyncWrite};
/// RDP stream abstraction
///
/// Wraps either a plain TCP or a TLS stream behind a single type that
/// implements `AsyncRead + AsyncWrite`.
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

/// Stream wrapper that can be either plain TCP or TLS
pub enum RdpStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for RdpStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            RdpStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            RdpStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for RdpStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            RdpStream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            RdpStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            RdpStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            RdpStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            RdpStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            RdpStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}
