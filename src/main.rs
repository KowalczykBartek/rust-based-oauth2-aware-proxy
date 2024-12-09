use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use clap::Parser;
use config::{Config, File};
use log::{debug, info};
use pingora::prelude::Opt;
use pingora::server::Server;
use pingora::services::listening::Service;
use pingora::{prelude::HttpPeer,proxy::ProxyHttp};
use prometheus::register_int_counter;
use pingora::proxy::{http_proxy_service, Session};
use pingora::Result;
use reqwest::{Body, Client, Identity};
use serde::Deserialize;

#[async_trait]
impl ProxyHttp for RequestModificationService {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(
        &self,
        _: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // let addr = ("127.0.0.1", 9091);
        let state = self.state.clone();

        let addr = (&state.upstream_host[..], state.upstream_port);
        info!("connecting to {addr:?}");
        let peer = Box::new(HttpPeer::new(addr, state.upstream_tls, state.upstream_host.to_string()));
        Ok(peer)
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        _ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        debug!("received body chunk for session {} chunk {:?}", session.request_summary(), body);
        Ok(())
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        debug!("{:?}", session.req_header());
        
        let state = self.state.clone();
        let token = state.get_token().await.unwrap();
        let mutable_headers = session.req_header_mut();
        mutable_headers.append_header("Authorization", format!("Bearer {}", token)).unwrap();

        debug!("request {:?} enriched with token {:?}", session.request_summary(), token);
        self.req_metric.inc();
        
        Ok(false)
    }
}
pub struct RequestModificationService {
    req_metric: prometheus::IntCounter,
    state: Arc<ExtensionState>
}

#[derive(Clone)]
struct ExtensionState {
    //upstream destination configuration
    upstream_host: String,
    upstream_port: u16, 
    upstream_tls: bool,

    token_endpoint: String,
    client_id: String,
    client_secret: Option<String>,
    grace_period: u32,
    client: Client,
    token: Arc<Mutex<Option<ExpirableToken>>>,
}

#[derive(Debug, Deserialize)]
struct Token {
    access_token: String,
    // This property, according to RFC, is expected to be in seconds.
    expires_in: u32,
}

#[derive(Debug, Clone)]
struct ExpirableToken {
    access_token: String,
    expires_after_ms: u128,
}

#[derive(serde::Deserialize, Clone)]
struct Configuration {
    upstream_host: String,
    upstream_port: u16, 
    upstream_tls: bool,
    upstream_key_location: Option<String>,
    upstream_cert_location: Option<String>,
    listening_addr: String, 
    prometheus_addr: String, 
    token_endpoint: String,
    client_id: String,
    client_secret: Option<String>,
    grace_period: u32,
}

impl ExtensionState {
    /// Creates a new `OAuth2Extension`.
    fn new(
        upstream_host: String,
        upstream_port: u16, 
        upstream_tls: bool,
        token_endpoint: String,
        client_id: String,
        client_secret: Option<String>,
        grace_period: u32,
        client: Client,
    ) -> ExtensionState {
        let initial_empty_token = Arc::new(Mutex::new(None));
        ExtensionState {
            upstream_host,
            upstream_port,
            upstream_tls,
            token_endpoint,
            client_id,
            client_secret,
            grace_period,
            client,
            token: initial_empty_token,
        }
    }

    async fn get_token(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(token) = self.acquire_token_from_cache() {
            return Ok(token.access_token);
        }

        //no valid token in cache (or no token at all)
        let new_token = self.request_token().await?;
        let token_to_return = new_token.access_token.clone();
        self.save_into_cache(new_token);

        Ok(token_to_return)
    }

    fn acquire_token_from_cache(&self) -> Option<ExpirableToken> {
        let maybe_token = self.token.lock().expect("Poisoned token lock");
        match &*maybe_token {
            Some(token) => {
                let time_now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards");
                if time_now.as_millis() < token.expires_after_ms {
                    //we have token, token is valid for at least 1min, we can use it.
                    return Some(token.clone());
                }

                None
            }
            _ => None,
        }
    }

    fn save_into_cache(&self, token: ExpirableToken) {
        self.token
            .lock()
            .expect("Poisoned token lock")
            .replace(token);
    }

    async fn request_token(
        &self,
    ) -> Result<ExpirableToken, Box<dyn std::error::Error + Send + Sync>> {
        let token_endpoint = self.token_endpoint.clone();
        let mut request_body =
        format!("grant_type=client_credentials&client_id={}", self.client_id);

        if let Some(client_secret) = &self.client_secret {
            let secret_param = format!("&client_secret={}", client_secret);
            request_body.push_str(&secret_param);
        }

        let token : Token = self.client
            .post(token_endpoint)
            .body(Body::from(request_body))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap(); 

        let time_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        let token_will_expire_after_ms =
        ExtensionState::calculate_valid_until(time_now, self.grace_period, &token);

        Ok(ExpirableToken {
            access_token: token.access_token,
            expires_after_ms: token_will_expire_after_ms,
        })
    }

    const fn calculate_valid_until(now: Duration, grace_period: u32, token: &Token) -> u128 {
        // 'expires_in' means, in seconds, for how long it will be valid, lets say 5min,
        // to not cause some random 4xx, because token expired in the meantime, we will make some
        // room for token refreshing, this room is a grace_period.
        let (mut grace_period_seconds, overflow) = token.expires_in.overflowing_sub(grace_period);

        // If time for grace period exceed an expire_in, it basically means: always use new token.
        if overflow {
            grace_period_seconds = 0;
        }

        // We are multiplying by 1000 because expires_in field is in seconds(oauth standard), grace_period also,
        // but later we operate on milliseconds.
        let token_is_valid_until_ms: u128 = grace_period_seconds as u128 * 1000;
        let now_millis = now.as_millis();

        now_millis + token_is_valid_until_ms
    }
}

// RUST_LOG=INFO cargo run
fn main() {
    env_logger::init();
    let opt = Opt::parse();

    let s = Config::builder()
        .add_source(File::with_name("/tmp/proxyconfig/config.yaml"))
        .build()
        .unwrap();

    let config: Configuration = s.try_deserialize().unwrap();

    let mut server = Server::new(Some(opt)).unwrap();
    server.bootstrap();

    let mut client = reqwest::Client::builder().build().unwrap();

    if config.upstream_cert_location.is_some() && config.upstream_key_location.is_some() {
        let cert = std::fs::read_to_string(config.upstream_cert_location.unwrap()).unwrap();        
        let key = std::fs::read_to_string(config.upstream_key_location.unwrap()).unwrap();

        client = reqwest::Client::builder()
            .use_rustls_tls()
            .identity(Identity::from_pem(&vec![cert.as_bytes(),key.as_bytes()].concat()).unwrap())
            .build()
            .unwrap();
    } 

    let oauth2_extension = ExtensionState::new(
        config.upstream_host,
        config.upstream_port,
        config.upstream_tls,
        config.token_endpoint,
        config.client_id,
        config.client_secret,
        config.grace_period,
        client,
    );

    let oauth2_extension = Arc::new(oauth2_extension);
    let mut proxy = http_proxy_service(
        &server.configuration,
        RequestModificationService {
            req_metric: register_int_counter!("req_counter", "Number of proxied requests").unwrap(),
            state: oauth2_extension,
        },
    );

    proxy.add_tcp(&config.listening_addr);
    server.add_service(proxy);

    let mut prometheus_service_http =
        Service::prometheus_http_service();

    prometheus_service_http.add_tcp(&config.prometheus_addr);
    server.add_service(prometheus_service_http);
    server.run_forever();
}
