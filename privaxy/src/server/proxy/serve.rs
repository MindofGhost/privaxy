use super::html_rewriter::Rewriter;
use super::upstream::UpstreamProxy;
use crate::blocker::AdblockRequester;
use crate::events::Event;
use crate::statistics::Statistics;
use adblock::blocker::BlockerResult;
use http::uri::{Authority, Scheme};
use http::{StatusCode, Uri};
use hyper::body::Bytes;
use hyper::client::HttpConnector;
use hyper::{http, Body, Request, Response};
use hyper_rustls::HttpsConnector;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve(
    adblock_requester: AdblockRequester,
    request: Request<Body>,
    hyper_client: hyper::Client<HttpsConnector<HttpConnector>>,
    client: reqwest::Client,
    authority: Authority,
    scheme: Scheme,
    broadcast_sender: broadcast::Sender<Event>,
    statistics: Statistics,
    client_ip_address: IpAddr,
    upstream_proxy: Option<UpstreamProxy>,
) -> Result<Response<Body>, hyper::Error> {
    let scheme_string = scheme.to_string();

    let uri = match http::uri::Builder::new()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(match request.uri().path_and_query() {
            Some(path_and_query) => path_and_query.as_str(),
            None => "/",
        })
        .build()
    {
        Ok(uri) => uri,
        Err(_err) => {
            return Ok(get_empty_response(http::StatusCode::BAD_REQUEST));
        }
    };

    if request.headers().contains_key(http::header::UPGRADE) {
        return Ok(match upstream_proxy {
            Some(upstream_proxy) => perform_proxied_upgrade(request, uri, upstream_proxy).await,
            None => perform_two_ends_upgrade(request, uri, hyper_client).await,
        });
    }

    let (mut parts, body) = request.into_parts();
    parts.uri = uri.clone();

    let (sender, new_body) = Body::channel();

    let req = Request::from_parts(parts, body);

    log::debug!("{} {}", req.method(), req.uri());

    statistics.increment_top_clients(client_ip_address);

    let (is_request_blocked, blocker_result) = adblock_requester
        .is_network_url_blocked(
            uri.to_string(),
            match req.headers().get(http::header::REFERER) {
                Some(referer) => referer.to_str().unwrap().to_string(),
                // When no referer, we default to `uri` as we otherwise may get many false
                // positives due to the blocker thinking it's third party requests.
                None => uri.to_string(),
            },
        )
        .await;

    let _result = broadcast_sender.send(Event {
        now: chrono::Utc::now(),
        method: req.method().to_string(),
        url: req.uri().to_string(),
        is_request_blocked,
    });

    if is_request_blocked {
        statistics.increment_blocked_requests();
        statistics.increment_top_blocked_paths(format!(
            "{}://{}{}",
            scheme_string,
            uri.host().unwrap(),
            uri.path()
        ));

        log::debug!("Blocked request: {}", uri);

        return Ok(get_blocked_by_privaxy_response(blocker_result));
    }

    let mut new_response = Response::new(new_body);

    let mut request_headers = req.headers().clone();
    request_headers.remove(http::header::CONNECTION);
    request_headers.remove(http::header::HOST);

    let mut response = match client
        .request(req.method().clone(), req.uri().to_string())
        .headers(request_headers)
        .body(req.into_body())
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => return Ok(get_informative_error_response(&err.to_string())),
    };

    statistics.increment_proxied_requests();

    *new_response.headers_mut() = response.headers().clone();

    let (mut parts, new_new_body) = new_response.into_parts();
    parts.status = response.status();

    let new_response = Response::from_parts(parts, new_new_body);

    if let Some(content_type) = response.headers().get(http::header::CONTENT_TYPE) {
        if let Ok(value) = content_type.to_str() {
            if value.contains("text/html") {
                let (sender_rewriter, receiver_rewriter) = crossbeam_channel::unbounded::<Bytes>();

                let rewriter = Rewriter::new(
                    uri.to_string(),
                    adblock_requester,
                    receiver_rewriter,
                    sender,
                    statistics,
                );

                tokio::task::spawn_blocking(|| rewriter.rewrite());

                while let Ok(Some(chunk)) = response.chunk().await {
                    if let Err(_err) = sender_rewriter.send(chunk) {
                        break;
                    }
                }

                return Ok(new_response);
            }
        }

        tokio::spawn(write_proxied_body(response, sender));

        return Ok(new_response);
    }

    tokio::spawn(write_proxied_body(response, sender));

    Ok(new_response)
}

fn get_informative_error_response(reason: &str) -> Response<Body> {
    let mut response_body = String::from(include_str!("../../resources/head.html"));
    response_body +=
        &include_str!("../../resources/error.html").replace("#{request_error_reson}#", reason);

    let mut response = Response::new(Body::from(response_body));
    *response.status_mut() = http::StatusCode::BAD_GATEWAY;

    response
}

fn get_blocked_by_privaxy_response(blocker_result: BlockerResult) -> Response<Body> {
    // We don't redirect to network urls due to security concerns.
    if let Some(resource) = blocker_result.redirect {
        let response = Response::new(Body::from(resource));

        return response;
    }

    let filter_information = match blocker_result.filter {
        Some(filter) => filter,
        None => "No information".to_string(),
    };

    let mut response_body = String::from(include_str!("../../resources/head.html"));
    response_body += &include_str!("../../resources/blocked_by_privaxy.html")
        .replace("#{matching_filter}#", &filter_information);

    let mut response = Response::new(Body::from(response_body));
    *response.status_mut() = http::StatusCode::FORBIDDEN;

    response
}

fn get_empty_response(status_code: http::StatusCode) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status_code;

    response
}

async fn write_proxied_body(mut response: reqwest::Response, mut sender: hyper::body::Sender) {
    while let Ok(Some(chunk)) = response.chunk().await {
        // The other end is broken, let's abort immediately.
        if let Err(_err) = sender.send_data(chunk).await {
            break;
        }
    }
}

/// When we receive a request to perform an upgrade, we need to initiate a bidirectional tunnel.
/// We upgrade the request towards the target server, towards the proxy end and we connect both through a duplex stream.
async fn perform_two_ends_upgrade(
    request: Request<Body>,
    uri: Uri,
    hyper_client: hyper::Client<HttpsConnector<HttpConnector>>,
) -> Response<Body> {
    let (mut duplex_client, mut duplex_server) = tokio::io::duplex(32);

    let mut new_request = Request::new(Body::empty());
    *new_request.headers_mut() = request.headers().clone();
    *new_request.uri_mut() = uri;

    tokio::spawn(async move {
        match hyper::upgrade::on(request).await {
            Ok(mut upgraded_client) => {
                let _result =
                    tokio::io::copy_bidirectional(&mut upgraded_client, &mut duplex_client).await;
            }
            Err(e) => {
                log::debug!("Unable to upgrade: {}", e)
            }
        }
    });

    let response = match hyper_client.request(new_request).await {
        Ok(response) => response,
        Err(_err) => return get_empty_response(http::StatusCode::BAD_REQUEST),
    };

    let mut new_response = get_empty_response(StatusCode::SWITCHING_PROTOCOLS);
    *new_response.headers_mut() = response.headers().clone();

    match hyper::upgrade::on(response).await {
        Ok(mut upgraded_server) => {
            tokio::spawn(async move {
                let _result =
                    tokio::io::copy_bidirectional(&mut upgraded_server, &mut duplex_server).await;
            });
        }
        Err(e) => {
            log::debug!("Unable to upgrade: {}", e)
        }
    }

    new_response
}

enum ServerStream {
    Tcp(TcpStream),
    Tls(TlsStream<TcpStream>),
}

impl AsyncRead for ServerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ServerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

async fn perform_proxied_upgrade(
    request: Request<Body>,
    uri: Uri,
    upstream_proxy: UpstreamProxy,
) -> Response<Body> {
    let authority = match authority_with_default_port(&uri) {
        Some(authority) => authority,
        None => return get_empty_response(http::StatusCode::BAD_REQUEST),
    };

    let mut server = match upstream_proxy.connect_tunnel(&authority).await {
        Ok(stream) => match uri.scheme() {
            Some(scheme) if scheme == &Scheme::HTTPS => {
                let host = match uri.host() {
                    Some(host) => host,
                    None => return get_empty_response(http::StatusCode::BAD_REQUEST),
                };

                match connect_tls(stream, host).await {
                    Ok(stream) => ServerStream::Tls(stream),
                    Err(err) => {
                        log::debug!("Unable to establish TLS through upstream proxy: {}", err);
                        return get_empty_response(http::StatusCode::BAD_GATEWAY);
                    }
                }
            }
            _ => ServerStream::Tcp(stream),
        },
        Err(err) => {
            log::debug!("Unable to CONNECT through upstream proxy: {}", err);
            return get_empty_response(http::StatusCode::BAD_GATEWAY);
        }
    };

    let mut upgrade_request = format!(
        "{} {} HTTP/1.1\r\n",
        request.method(),
        uri.path_and_query()
            .map(|path_and_query| path_and_query.as_str())
            .unwrap_or("/")
    );

    let mut has_host = false;
    for (name, value) in request.headers() {
        if name == http::header::HOST {
            has_host = true;
        }

        if name == http::header::PROXY_AUTHORIZATION {
            continue;
        }

        let value = match value.to_str() {
            Ok(value) => value,
            Err(_) => return get_empty_response(http::StatusCode::BAD_REQUEST),
        };

        upgrade_request.push_str(name.as_str());
        upgrade_request.push_str(": ");
        upgrade_request.push_str(value);
        upgrade_request.push_str("\r\n");
    }

    if !has_host {
        upgrade_request.push_str("Host: ");
        upgrade_request.push_str(authority.as_str());
        upgrade_request.push_str("\r\n");
    }

    upgrade_request.push_str("\r\n");

    if let Err(err) = server.write_all(upgrade_request.as_bytes()).await {
        log::debug!("Unable to send upgrade through upstream proxy: {}", err);
        return get_empty_response(http::StatusCode::BAD_GATEWAY);
    }

    let (response_bytes, pending_server_bytes) = match read_headers(&mut server).await {
        Ok(response) => response,
        Err(err) => {
            log::debug!("Unable to read upgrade response through upstream proxy: {}", err);
            return get_empty_response(http::StatusCode::BAD_GATEWAY);
        }
    };

    let new_response = match parse_upgrade_response(&response_bytes) {
        Ok(response) => response,
        Err(err) => {
            log::debug!("Unable to parse upgrade response through upstream proxy: {}", err);
            return get_empty_response(http::StatusCode::BAD_GATEWAY);
        }
    };

    tokio::spawn(async move {
        match hyper::upgrade::on(request).await {
            Ok(mut upgraded_client) => {
                if !pending_server_bytes.is_empty()
                    && upgraded_client.write_all(&pending_server_bytes).await.is_err()
                {
                    return;
                }

                let _result =
                    tokio::io::copy_bidirectional(&mut upgraded_client, &mut server).await;
            }
            Err(e) => {
                log::debug!("Unable to upgrade: {}", e)
            }
        }
    });

    new_response
}

async fn connect_tls(stream: TcpStream, host: &str) -> std::io::Result<TlsStream<TcpStream>> {
    let mut root_cert_store = rustls::RootCertStore::empty();

    for certificate in rustls_native_certs::load_native_certs()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?
    {
        let _result = root_cert_store.add(&rustls::Certificate(certificate.0));
    }

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(std::sync::Arc::new(config));
    let server_name = rustls::ServerName::try_from(host)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid DNS name"))?;

    connector.connect(server_name, stream).await
}

async fn read_headers(stream: &mut ServerStream) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let mut response = Vec::new();
    let mut buffer = [0; 1024];

    loop {
        let bytes_read = stream.read(&mut buffer).await?;
        if bytes_read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "server closed upgrade response",
            ));
        }

        response.extend_from_slice(&buffer[..bytes_read]);

        if let Some(header_end) = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
        {
            let pending_server_bytes = response.split_off(header_end);
            return Ok((response, pending_server_bytes));
        }

        if response.len() > 8192 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "upgrade response is too large",
            ));
        }
    }
}

fn parse_upgrade_response(response_bytes: &[u8]) -> Result<Response<Body>, String> {
    let response = std::str::from_utf8(response_bytes).map_err(|err| err.to_string())?;
    let mut lines = response.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| "upgrade response is empty".to_string())?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| "upgrade response status code is missing".to_string())?
        .parse::<u16>()
        .map_err(|err| err.to_string())?;

    let mut builder = Response::builder().status(status_code);

    for line in lines {
        if line.is_empty() {
            break;
        }

        let Some((name, value)) = line.split_once(':') else {
            continue;
        };

        builder = builder.header(name.trim(), value.trim());
    }

    builder.body(Body::empty()).map_err(|err| err.to_string())
}

fn authority_with_default_port(uri: &Uri) -> Option<Authority> {
    let authority = uri.authority()?;

    if authority.port().is_some() {
        return Some(authority.clone());
    }

    let port = match uri.scheme() {
        Some(scheme) if scheme == &Scheme::HTTPS => 443,
        _ => 80,
    };

    let host = if authority.host().contains(':') {
        format!("[{}]", authority.host())
    } else {
        authority.host().to_string()
    };

    format!("{}:{}", host, port).parse().ok()
}
