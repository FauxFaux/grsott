use anyhow::Result;
use axum::extract::Path;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use base64::prelude::BASE64_STANDARD;
use base64::prelude::*;
use grsott::decode::{Direction, read_packets_from};
use regex::Regex;
use std::fs;
use std::sync::LazyLock;
use time::format_description::well_known::Rfc3339;

#[tokio::main]
async fn main() -> Result<()> {
    let app = Router::new()
        .route("/cap", get(list_files))
        .route("/cap/{path}", get(get_cap));
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

    ([(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")], Json(paths))

}

async fn get_cap(Path(path): Path<String>) -> impl IntoResponse {
    let file = fs::File::open(path).expect("TODO: bad file");
    let mut packets = Vec::with_capacity(128);
    read_packets_from(&mut packets, file).expect("TODO: bad parse");
    let body = Json(
        packets
            .iter()
            .map(|p| JsPacket {
                ts: p.ts.format(&Rfc3339).expect("TODO: valid timestamp"),
                dir: match p.dir {
                    Direction::ToInverter => "to_inverter".into(),
                    Direction::FromInverter => "from_inverter".into(),
                },
                header: p.header,
                body: BASE64_STANDARD.encode(&p.body),
            })
            .collect::<Vec<_>>(),
    );
    ([(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")], body)
}
