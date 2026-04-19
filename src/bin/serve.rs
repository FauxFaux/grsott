use anyhow::Result;
use axum::extract::Path;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use base64::prelude::BASE64_STANDARD;
use base64::prelude::*;
use grsott::decode::{Direction, read_packets_from};
use std::fs;
use time::format_description::well_known::Rfc3339;

#[tokio::main]
async fn main() -> Result<()> {
    let app = Router::new().route("/cap/{path}", get(get_cap));
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
