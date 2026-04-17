//! # Relay HTTP client
//!
//! Minimal HTTP/1.1 client for talking to `liun-relay` servers.
//! Two operations: POST a share, GET a share.
//!
//! No TLS by design — shares are individually uniform-random, so individual
//! leakage reveals zero about the reconstructed PSK. Security comes from the
//! k-of-k XOR structure plus the assumption that ≥1 relay is unobserved.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BYTES: usize = 128 * 1024;

/// Errors returned by relay operations.
#[derive(Debug)]
pub enum RelayError {
    /// URL couldn't be parsed.
    BadUrl(String),
    /// TCP connect / read / write failed.
    Io(std::io::Error),
    /// Timed out.
    Timeout,
    /// Server returned a non-2xx status.
    Status { code: u16, body: String },
    /// Response couldn't be parsed as HTTP/1.1.
    MalformedResponse(String),
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadUrl(u) => write!(f, "bad url: {u}"),
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Timeout => write!(f, "timeout"),
            Self::Status { code, body } => write!(f, "http {code}: {}", body.trim()),
            Self::MalformedResponse(e) => write!(f, "malformed response: {e}"),
        }
    }
}

impl std::error::Error for RelayError {}

impl From<std::io::Error> for RelayError {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}

/// A parsed relay URL like `http://host:port/base_path`.
#[derive(Debug, Clone)]
struct ParsedUrl<'a> {
    host: &'a str,
    port: u16,
    base_path: &'a str,
}

fn parse_url(url: &str) -> Result<ParsedUrl<'_>, RelayError> {
    let rest = url.strip_prefix("http://").ok_or_else(|| RelayError::BadUrl(url.to_string()))?;
    let (authority, base_path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p.parse().map_err(|_| RelayError::BadUrl(url.to_string()))?;
            (h, port)
        }
        None => (authority, 80),
    };
    if host.is_empty() {
        return Err(RelayError::BadUrl(url.to_string()));
    }
    Ok(ParsedUrl { host, port, base_path })
}

/// POST a share to a relay.
///
/// `relay_url` is the relay's base URL (e.g. `http://relay.example:8080`).
/// `session_id` is the rendezvous key.
/// `share` is the raw bytes to store.
pub async fn post_share(relay_url: &str, session_id: &str, share: &[u8]) -> Result<(), RelayError> {
    let url = parse_url(relay_url)?;
    let path = format!("{}share/{}", ensure_trailing_slash(url.base_path), session_id);
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {}:{}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
        url.host, url.port, share.len()
    );

    let fut = async {
        let mut stream = tokio::time::timeout(CONNECT_TIMEOUT,
            TcpStream::connect((url.host, url.port))).await
            .map_err(|_| RelayError::Timeout)??;
        let _ = stream.set_nodelay(true);
        stream.write_all(req.as_bytes()).await?;
        stream.write_all(share).await?;
        let (code, body) = read_response(&mut stream).await?;
        if (200..300).contains(&code) {
            Ok(())
        } else {
            let body = String::from_utf8_lossy(&body).into_owned();
            Err(RelayError::Status { code, body })
        }
    };
    tokio::time::timeout(REQUEST_TIMEOUT, fut).await.map_err(|_| RelayError::Timeout)?
}

/// POST a share to a relay, advertising the caller's NodeId so the
/// relay can credit the session locally. No inline receipt exchange —
/// each side independently produces its session-level receipt at
/// epoch close and posts it out-of-band to the aggregator.
pub async fn post_share_as(
    relay_url: &str,
    session_id: &str,
    share: &[u8],
    client_node_id: &str,
) -> Result<(), RelayError> {
    let url = parse_url(relay_url)?;
    let path = format!("{}share/{}", ensure_trailing_slash(url.base_path), session_id);
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {}:{}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nX-Liun-Client-Id: {}\r\nConnection: close\r\n\r\n",
        url.host, url.port, share.len(), client_node_id
    );

    let fut = async {
        let mut stream = tokio::time::timeout(CONNECT_TIMEOUT,
            TcpStream::connect((url.host, url.port))).await
            .map_err(|_| RelayError::Timeout)??;
        let _ = stream.set_nodelay(true);
        stream.write_all(req.as_bytes()).await?;
        stream.write_all(share).await?;
        let (code, body) = read_response(&mut stream).await?;
        if (200..300).contains(&code) {
            Ok(())
        } else {
            let body = String::from_utf8_lossy(&body).into_owned();
            Err(RelayError::Status { code, body })
        }
    };
    tokio::time::timeout(REQUEST_TIMEOUT, fut).await.map_err(|_| RelayError::Timeout)?
}

/// GET a share from a relay. Returns the share bytes.
pub async fn get_share(relay_url: &str, session_id: &str) -> Result<Vec<u8>, RelayError> {
    let url = parse_url(relay_url)?;
    let path = format!("{}share/{}", ensure_trailing_slash(url.base_path), session_id);
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        url.host, url.port
    );

    let fut = async {
        let mut stream = tokio::time::timeout(CONNECT_TIMEOUT,
            TcpStream::connect((url.host, url.port))).await
            .map_err(|_| RelayError::Timeout)??;
        let _ = stream.set_nodelay(true);
        stream.write_all(req.as_bytes()).await?;
        let (code, body) = read_response(&mut stream).await?;
        if (200..300).contains(&code) {
            Ok(body)
        } else {
            let body_str = String::from_utf8_lossy(&body).into_owned();
            Err(RelayError::Status { code, body: body_str })
        }
    };
    tokio::time::timeout(REQUEST_TIMEOUT, fut).await.map_err(|_| RelayError::Timeout)?
}

fn ensure_trailing_slash(s: &str) -> String {
    if s.ends_with('/') { s.to_string() } else { format!("{s}/") }
}

/// Read an HTTP/1.1 response, return (status_code, body_bytes).
async fn read_response(stream: &mut TcpStream) -> Result<(u16, Vec<u8>), RelayError> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(RelayError::MalformedResponse("connection closed before headers".into()));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = i + 4;
            break;
        }
        if buf.len() > 16 * 1024 {
            return Err(RelayError::MalformedResponse("headers too large".into()));
        }
    }

    let header_str = std::str::from_utf8(&buf[..header_end - 4])
        .map_err(|_| RelayError::MalformedResponse("non-utf8 headers".into()))?;

    let mut lines = header_str.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    if parts.len() < 2 || !parts[0].starts_with("HTTP/1.") {
        return Err(RelayError::MalformedResponse(format!("bad status line: {status_line}")));
    }
    let code: u16 = parts[1].parse()
        .map_err(|_| RelayError::MalformedResponse(format!("bad status code: {}", parts[1])))?;

    let mut content_length: Option<usize> = None;
    for line in lines {
        if let Some((name, val)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = val.trim().parse().ok();
            }
        }
    }

    let body_in_buf = buf[header_end..].to_vec();
    let body = match content_length {
        Some(cl) if cl > MAX_RESPONSE_BYTES =>
            return Err(RelayError::MalformedResponse(format!("content-length too large: {cl}"))),
        Some(cl) => {
            let mut body = body_in_buf;
            while body.len() < cl {
                let take = (cl - body.len()).min(tmp.len());
                let n = stream.read(&mut tmp[..take]).await?;
                if n == 0 { break; }
                body.extend_from_slice(&tmp[..n]);
            }
            body.truncate(cl);
            body
        }
        None => {
            // No content-length: read until close.
            let mut body = body_in_buf;
            loop {
                let n = stream.read(&mut tmp).await?;
                if n == 0 { break; }
                body.extend_from_slice(&tmp[..n]);
                if body.len() > MAX_RESPONSE_BYTES {
                    return Err(RelayError::MalformedResponse("body too large".into()));
                }
            }
            body
        }
    };

    Ok((code, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_url_ok() {
        let u = parse_url("http://127.0.0.1:8080").unwrap();
        assert_eq!(u.host, "127.0.0.1");
        assert_eq!(u.port, 8080);
        assert_eq!(u.base_path, "/");

        let u = parse_url("http://relay.example.com").unwrap();
        assert_eq!(u.port, 80);

        let u = parse_url("http://host:1234/api/v1").unwrap();
        assert_eq!(u.base_path, "/api/v1");
    }

    #[test]
    fn test_parse_url_bad() {
        assert!(parse_url("https://nope.com").is_err());
        assert!(parse_url("http://").is_err());
        assert!(parse_url("http://:8080").is_err());
        assert!(parse_url("http://host:notaport").is_err());
    }
}
