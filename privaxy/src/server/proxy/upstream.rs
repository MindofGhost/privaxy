use http::header::HeaderValue;
use http::uri::Authority;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

#[derive(Clone, Debug)]
pub(crate) struct UpstreamProxy {
    authority: Authority,
    proxy_authorization: Option<HeaderValue>,
}

impl UpstreamProxy {
    pub(crate) fn parse(proxy_url: &str) -> Result<Self, String> {
        let url = Url::parse(proxy_url).map_err(|err| err.to_string())?;

        if url.scheme() != "http" {
            return Err("only http upstream proxies are supported".to_string());
        }

        let host = url
            .host_str()
            .ok_or_else(|| "upstream proxy host is missing".to_string())?;
        let port = url.port().unwrap_or(80);
        let host = if host.contains(':') {
            format!("[{}]", host)
        } else {
            host.to_string()
        };
        let authority = format!("{}:{}", host, port)
            .parse::<Authority>()
            .map_err(|err| err.to_string())?;

        let proxy_authorization = if url.username().is_empty() {
            None
        } else {
            let credentials = format!("{}:{}", url.username(), url.password().unwrap_or(""));
            let value = format!("Basic {}", base64::encode(credentials));
            Some(HeaderValue::from_str(&value).map_err(|err| err.to_string())?)
        };

        Ok(Self {
            authority,
            proxy_authorization,
        })
    }

    pub(crate) async fn connect_tunnel(&self, target: &Authority) -> io::Result<TcpStream> {
        let mut stream = TcpStream::connect(self.authority.to_string()).await?;
        let mut request = format!(
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: Keep-Alive\r\n"
        );

        if let Some(proxy_authorization) = &self.proxy_authorization {
            let proxy_authorization = proxy_authorization.to_str().map_err(|err| {
                io::Error::new(io::ErrorKind::InvalidInput, err.to_string())
            })?;
            request.push_str("Proxy-Authorization: ");
            request.push_str(proxy_authorization);
            request.push_str("\r\n");
        }

        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await?;

        let mut response = Vec::new();
        let mut buffer = [0; 1024];

        loop {
            let bytes_read = stream.read(&mut buffer).await?;
            if bytes_read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "upstream proxy closed CONNECT response",
                ));
            }

            response.extend_from_slice(&buffer[..bytes_read]);

            if response.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }

            if response.len() > 8192 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "upstream proxy CONNECT response is too large",
                ));
            }
        }

        let response = String::from_utf8_lossy(&response);
        let status_line = response.lines().next().unwrap_or_default();
        let status_code = status_line.split_whitespace().nth(1);

        if status_code == Some("200") {
            Ok(stream)
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("upstream proxy CONNECT failed: {}", status_line),
            ))
        }
    }
}
