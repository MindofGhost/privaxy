use crate::configuration::{self, Configuration};
use crate::events::Event;
use crate::PrivaxyServer;
use hyper::body::Bytes;
use hyper::header::{HeaderValue, CONTENT_TYPE};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use serde::Deserialize;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const WEB_DIST_ENV: &str = "PRIVAXY_WEB_DIST";
const DEFAULT_WEB_DIST: &str = "/usr/local/share/privaxy/web";

#[derive(Clone)]
struct WebAdminState {
    privaxy_server: PrivaxyServer,
    http_client: reqwest::Client,
    web_dist: PathBuf,
}

#[derive(Deserialize)]
struct BlockingEnabledRequest {
    enabled: bool,
}

#[derive(Deserialize)]
struct FilterStatusChangeRequest {
    enabled: bool,
    file_name: String,
}

pub async fn start_web_admin(privaxy_server: PrivaxyServer, bind_addr: SocketAddr) {
    let http_client = configuration::build_http_client();
    let state = Arc::new(WebAdminState {
        privaxy_server,
        http_client,
        web_dist: std::env::var(WEB_DIST_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_WEB_DIST)),
    });

    let make_service = make_service_fn(move |_| {
        let state = state.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |request| {
                handle_request(request, state.clone())
            }))
        }
    });

    let server = Server::bind(&bind_addr).serve(make_service);
    tokio::spawn(server);
    log::info!("Web admin available at http://{}", bind_addr);
}

async fn handle_request(
    request: Request<Body>,
    state: Arc<WebAdminState>,
) -> Result<Response<Body>, Infallible> {
    let response = match (request.method(), request.uri().path()) {
        (&Method::GET, "/api/statistics") => {
            json_response(&state.privaxy_server.statistics.get_serialized())
        }
        (&Method::GET, "/api/blocking-enabled") => {
            let enabled = !*state
                .privaxy_server
                .blocking_disabled_store
                .0
                .read()
                .unwrap();
            json_response(&serde_json::json!({ "enabled": enabled }))
        }
        (&Method::POST, "/api/blocking-enabled") => {
            match json_body::<BlockingEnabledRequest>(request).await {
                Ok(payload) => {
                    *state
                        .privaxy_server
                        .blocking_disabled_store
                        .0
                        .write()
                        .unwrap() = !payload.enabled;
                    json_response(&serde_json::json!({ "enabled": payload.enabled }))
                }
                Err(response) => response,
            }
        }
        (&Method::GET, "/api/custom-filters") => {
            match read_configuration(&state.http_client).await {
                Ok(configuration) => text_response(configuration.custom_filters.join("\n")),
                Err(response) => response,
            }
        }
        (&Method::PUT, "/api/custom-filters") | (&Method::POST, "/api/custom-filters") => {
            match text_body(request).await {
                Ok(input) => update_custom_filters(state, input).await,
                Err(response) => response,
            }
        }
        (&Method::GET, "/api/exclusions") => match read_configuration(&state.http_client).await {
            Ok(configuration) => {
                text_response(Vec::from_iter(configuration.exclusions.into_iter()).join("\n"))
            }
            Err(response) => response,
        },
        (&Method::PUT, "/api/exclusions") | (&Method::POST, "/api/exclusions") => {
            match text_body(request).await {
                Ok(input) => update_exclusions(state, input).await,
                Err(response) => response,
            }
        }
        (&Method::GET, "/api/filters") => match read_configuration(&state.http_client).await {
            Ok(configuration) => json_response(&configuration.filters),
            Err(response) => response,
        },
        (&Method::POST, "/api/filters") => {
            match json_body::<Vec<FilterStatusChangeRequest>>(request).await {
                Ok(payload) => update_filters(state, payload).await,
                Err(response) => response,
            }
        }
        (&Method::GET, "/api/ca-certificate") => pem_response(
            state
                .privaxy_server
                .ca_certificate_pem
                .clone(),
        ),
        (&Method::GET, "/api/events") => events_response(state.privaxy_server.clone()),
        (&Method::GET, _) => static_response(request.uri().path(), &state.web_dist).await,
        _ => status_response(StatusCode::NOT_FOUND, "not found"),
    };

    Ok(response)
}

async fn static_response(path: &str, web_dist: &Path) -> Response<Body> {
    let path = path.trim_start_matches('/');

    if path.split('/').any(|segment| segment == "..") {
        return status_response(StatusCode::BAD_REQUEST, "bad path");
    }

    let mut file_path = if path.is_empty() {
        web_dist.join("index.html")
    } else {
        web_dist.join(path)
    };

    if tokio::fs::metadata(&file_path)
        .await
        .map(|metadata| metadata.is_dir())
        .unwrap_or(false)
    {
        file_path = file_path.join("index.html");
    }

    let bytes = match tokio::fs::read(&file_path).await {
        Ok(bytes) => bytes,
        Err(_) => match tokio::fs::read(web_dist.join("index.html")).await {
            Ok(bytes) => {
                file_path = web_dist.join("index.html");
                bytes
            }
            Err(_) => return status_response(StatusCode::NOT_FOUND, "not found"),
        },
    };

    let content_type = mime_guess::from_path(&file_path)
        .first_or_octet_stream()
        .to_string();
    let mut response = Response::new(Body::from(bytes));

    if let Ok(content_type) = HeaderValue::from_str(&content_type) {
        response.headers_mut().insert(CONTENT_TYPE, content_type);
    }

    response
}

async fn read_configuration(http_client: &reqwest::Client) -> Result<Configuration, Response<Body>> {
    Configuration::read_from_home(http_client.clone())
        .await
        .map_err(|err| status_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{:?}", err)))
}

async fn update_custom_filters(state: Arc<WebAdminState>, input: String) -> Response<Body> {
    let _guard = state.privaxy_server.configuration_save_lock.lock().await;
    let mut configuration = match read_configuration(&state.http_client).await {
        Ok(configuration) => configuration,
        Err(response) => return response,
    };

    if let Err(err) = configuration.set_custom_filters(&input).await {
        return status_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{:?}", err));
    }

    state
        .privaxy_server
        .configuration_updater_sender
        .send(configuration)
        .await
        .unwrap();

    text_response("ok")
}

async fn update_exclusions(state: Arc<WebAdminState>, input: String) -> Response<Body> {
    let _guard = state.privaxy_server.configuration_save_lock.lock().await;
    let mut configuration = match read_configuration(&state.http_client).await {
        Ok(configuration) => configuration,
        Err(response) => return response,
    };

    if let Err(err) = configuration
        .set_exclusions(&input, state.privaxy_server.local_exclusion_store.clone())
        .await
    {
        return status_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{:?}", err));
    }

    state
        .privaxy_server
        .configuration_updater_sender
        .send(configuration)
        .await
        .unwrap();

    text_response("ok")
}

async fn update_filters(
    state: Arc<WebAdminState>,
    payload: Vec<FilterStatusChangeRequest>,
) -> Response<Body> {
    let _guard = state.privaxy_server.configuration_save_lock.lock().await;
    let mut configuration = match read_configuration(&state.http_client).await {
        Ok(configuration) => configuration,
        Err(response) => return response,
    };

    for filter in payload {
        if let Err(err) = configuration
            .set_filter_enabled_status(&filter.file_name, filter.enabled)
            .await
        {
            return status_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{:?}", err));
        }
    }

    state
        .privaxy_server
        .configuration_updater_sender
        .send(configuration.clone())
        .await
        .unwrap();

    json_response(&configuration.filters)
}

fn events_response(privaxy_server: PrivaxyServer) -> Response<Body> {
    let (mut sender, body) = Body::channel();
    let mut receiver = privaxy_server.requests_broadcast_sender.subscribe();

    tokio::spawn(async move {
        loop {
            let event: Event = match receiver.recv().await {
                Ok(event) => event,
                Err(_) => break,
            };
            let payload = match serde_json::to_string(&event) {
                Ok(payload) => payload,
                Err(_) => continue,
            };

            if sender
                .send_data(Bytes::from(format!("data: {}\n\n", payload)))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let mut response = Response::new(body);
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    response.headers_mut().insert(
        hyper::header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache"),
    );
    response
}

async fn json_body<T: for<'de> Deserialize<'de>>(
    request: Request<Body>,
) -> Result<T, Response<Body>> {
    let body = hyper::body::to_bytes(request.into_body())
        .await
        .map_err(|err| status_response(StatusCode::BAD_REQUEST, &err.to_string()))?;
    serde_json::from_slice(&body)
        .map_err(|err| status_response(StatusCode::BAD_REQUEST, &err.to_string()))
}

async fn text_body(request: Request<Body>) -> Result<String, Response<Body>> {
    let body = hyper::body::to_bytes(request.into_body())
        .await
        .map_err(|err| status_response(StatusCode::BAD_REQUEST, &err.to_string()))?;
    String::from_utf8(body.to_vec())
        .map_err(|err| status_response(StatusCode::BAD_REQUEST, &err.to_string()))
}

fn text_response(body: impl Into<String>) -> Response<Body> {
    typed_response(body.into(), "text/plain; charset=utf-8")
}

fn pem_response(body: impl Into<String>) -> Response<Body> {
    typed_response(body.into(), "application/x-pem-file")
}

fn json_response<T: serde::Serialize>(payload: &T) -> Response<Body> {
    typed_response(
        serde_json::to_string(payload).unwrap(),
        "application/json; charset=utf-8",
    )
}

fn typed_response(body: String, content_type: &'static str) -> Response<Body> {
    let mut response = Response::new(Body::from(body));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

fn status_response(status: StatusCode, body: &str) -> Response<Body> {
    let mut response = text_response(body.to_string());
    *response.status_mut() = status;
    response
}
