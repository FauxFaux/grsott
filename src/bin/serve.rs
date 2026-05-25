use anyhow::{Error, Result};
use axum::extract::Path;
use axum::http::{HeaderMap, header};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use base64::prelude::BASE64_STANDARD;
use base64::prelude::*;
use grsott::decode::{Direction, read_packets_from};
use log::warn;
use regex::Regex;
use std::fs;
use std::sync::LazyLock;
use time::format_description::well_known::Rfc3339;
use tower_default_headers::DefaultHeadersLayer;

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    let mut default_headers = HeaderMap::new();
    default_headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse()?);
    let app = Router::new()
        .route("/cap", get(list_files))
        .route("/cap/{path}", get(get_cap))
        .layer(DefaultHeadersLayer::new(default_headers));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:4444").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(serde::Serialize)]
struct JsPacket {
    ts: String,
    dir: String,
    header: [u8; 8],
    body: String,
}

// 1769828795237.49161.pcapng
fn is_cap_file(path: &str) -> bool {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^\d+\.\d+\.pcapng$").expect("static regex"));
    RE.is_match(path)
}

#[test]
fn test_is_cap_file() {
    assert!(is_cap_file("1769828795237.49161.pcapng"));
    assert!(!is_cap_file("../1769828795237.49161.pcapng"));
}

async fn list_files() -> impl IntoResponse {
    let paths = fs::read_dir(".")
        .expect("TODO: read dir")
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| is_cap_file(name))
        .collect::<Vec<_>>();

    Json(paths)
}

#[derive(Debug)]
#[allow(dead_code)]
enum GetCapError {
    BadFile(Error),
    BadParse(Error),
    BadTimestamp(Error),
}

impl IntoResponse for GetCapError {
    fn into_response(self) -> axum::response::Response {
        warn!("get_cap error: {self:?}");
        match self {
            GetCapError::BadFile(_) => {
                (axum::http::StatusCode::BAD_REQUEST, "bad file").into_response()
            }
            GetCapError::BadParse(_) => {
                (axum::http::StatusCode::BAD_REQUEST, "bad parse").into_response()
            }
            GetCapError::BadTimestamp(_) => {
                (axum::http::StatusCode::BAD_REQUEST, "bad timestamp").into_response()
            }
        }
    }
}

async fn get_cap(Path(path): Path<String>) -> Result<impl IntoResponse, GetCapError> {
    let file = fs::File::open(path).map_err(|e| GetCapError::BadFile(e.into()))?;
    let mut packets = Vec::with_capacity(128);
    read_packets_from(&mut packets, file).map_err(|e| GetCapError::BadParse(e.into()))?;
    let body = Json(
        packets
            .iter()
            .map(|p| -> Result<JsPacket, GetCapError> {
                Ok(JsPacket {
                    ts: p
                        .ts
                        .format(&Rfc3339)
                        .map_err(|e| GetCapError::BadTimestamp(e.into()))?,
                    dir: match p.dir {
                        Direction::ToInverter => "to_inverter".into(),
                        Direction::FromInverter => "from_inverter".into(),
                    },
                    header: p.header.into(),
                    body: BASE64_STANDARD.encode(&p.body),
                })
            })
            .collect::<Result<Vec<_>, GetCapError>>()?,
    );
    Ok(body)
}
