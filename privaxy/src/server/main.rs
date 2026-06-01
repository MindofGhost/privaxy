use privaxy::{start_privaxy, web_admin::start_web_admin};
use std::net::SocketAddr;
use std::time::Duration;

const RUST_LOG_ENV_KEY: &str = "RUST_LOG";
const WEB_BIND_ENV_KEY: &str = "PRIVAXY_WEB_BIND";

#[tokio::main]
async fn main() {
    if std::env::var(RUST_LOG_ENV_KEY).is_err() {
        std::env::set_var(RUST_LOG_ENV_KEY, "privaxy=info");
    }

    env_logger::init();

    let privaxy_server = start_privaxy().await;

    if let Ok(web_bind) = std::env::var(WEB_BIND_ENV_KEY) {
        let web_bind = web_bind.parse::<SocketAddr>().unwrap_or_else(|err| {
            println!("Invalid {}: {:?}", WEB_BIND_ENV_KEY, err);
            std::process::exit(1)
        });
        start_web_admin(privaxy_server, web_bind).await;
    }

    loop {
        tokio::time::sleep(Duration::from_secs(3600 * 24 * 30 * 365)).await
    }
}
