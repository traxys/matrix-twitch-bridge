use std::{path::PathBuf, sync::Arc, time::Duration};

use axum::{response::IntoResponse, routing::post, Router};
use ruma::api::{appservice::ping::send_ping, client::appservice::request_ping};
use serde::{Deserialize, Serialize};
use tracing_subscriber::EnvFilter;

type HttpClient = ruma::client::http_client::Reqwest;

#[allow(dead_code)]
mod utils;

use utils::{RumaRequest, RumaResponse};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
struct Config {
    homeserver_url: String,
    registration_file: PathBuf,
}

impl Config {
    fn new() -> anyhow::Result<Self> {
        Ok(envious::Config::default()
            .with_prefix("MATRIX_TWITCH_")
            .case_sensitive(true)
            .build_from_env()?)
    }
}

async fn ping(request: RumaRequest<send_ping::v1::Request>) -> impl IntoResponse {
    tracing::trace!("Got ping: {request:?}");

    RumaResponse(send_ping::v1::Response::new()).into_response()
}

struct BridgeState {
    _client: ruma::Client<HttpClient>,
    hs_token: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(true)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = Config::new()?;

    let registration = std::fs::read_to_string(config.registration_file)?;
    let registration: ruma::api::appservice::Registration = serde_yml::from_str(&registration)?;

    let client = ruma::Client::builder()
        .homeserver_url(config.homeserver_url)
        .access_token(Some(registration.as_token))
        .build::<HttpClient>()
        .await?;

    let state = Arc::new(BridgeState {
        _client: client.clone(),
        hs_token: registration.hs_token,
    });

    let app = Router::new()
        .route("/_matrix/app/v1/ping", post(ping))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8009").await?;

    tokio::spawn(async move {
        loop {
            if let Err(e) = client
                .send_request(request_ping::v1::Request::new("twitch-bridge".into()))
                .await
            {
                tracing::error!("ping failed: {e:#?}");
                tokio::time::sleep(Duration::from_secs(3)).await;
                continue;
            }

            break;
        }
    });

    axum::serve(listener, app).await.map_err(|e| e.into())
}
