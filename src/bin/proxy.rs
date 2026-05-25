use anyhow::{Context, Result};
use bunyarrs::{Bunyarr, vars};
use grsott::decode::Direction;
use grsott::hass_writer::HassWriter;
use grsott::pcap_writer::PcapWriter;
use mqtt_reeze::Mqtt;
use std::env;
use std::ops::DerefMut;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const LISTEN_PORT: u16 = 5279;

type Observers = Option<(PcapWriter, HassWriter)>;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let logger = Bunyarr::with_name("proxy");

    let destination = env::args()
        .nth(1)
        .context("Usage: proxy <destination_host:port>")?;

    let listener = TcpListener::bind(("0.0.0.0", LISTEN_PORT))
        .await
        .context("Failed to bind to port 5279")?;

    logger.info(vars! { destination }, "ready");

    loop {
        let (client_stream, client_addr) = listener.accept().await?;
        logger.info(vars! { client_addr }, "accepted connection");
        let destination = destination.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(client_stream, client_addr, &destination).await {
                // grumpy
                let logger = Bunyarr::with_name("spawn");
                let e = format!("{e:?}");

                logger.error(vars! { client_addr, e }, "handle error");
            }
        });
    }
}

async fn handle_connection(
    mut client_stream: TcpStream,
    client_addr: std::net::SocketAddr,
    destination: &str,
) -> Result<()> {
    let mut server_stream = TcpStream::connect(destination)
        .await
        .context(format!("Failed to connect to destination {}", destination))?;

    let logger = Bunyarr::with_name("handle");

    logger.info(vars! { client_addr, destination }, "established");

    let port = client_addr.port();
    let pcap = PcapWriter::new(port)?;
    let hass = HassWriter::new(Mqtt::new_from_env("grsott")?);
    let observer: Mutex<Observers> = Mutex::new(Some((pcap, hass)));

    let (mut client_read, mut client_write) = client_stream.split();
    let (mut server_read, mut server_write) = server_stream.split();

    let client_to_server = async {
        copy(
            &mut client_read,
            &mut server_write,
            &observer,
            Direction::FromInverter,
        )
        .await
    };

    let server_to_client = async {
        copy(
            &mut server_read,
            &mut client_write,
            &observer,
            Direction::ToInverter,
        )
        .await
    };

    // run server, then try flush, then return errors
    let server_result = tokio::select! {
        result = client_to_server => result,
        result = server_to_client => result,
    };

    let mut observer = observer.lock().await;
    let (mut pcap, hass) = observer
        .deref_mut()
        .take()
        .expect("observers should be present");
    let flush_pcap = pcap.flush().await;
    hass.finish().await?;
    flush_pcap?;

    logger.info(vars! { client_addr }, "closed");

    server_result
}

async fn copy<R, W>(
    reader: &mut R,
    writer: &mut W,
    observer: &Mutex<Observers>,
    direction: Direction,
) -> Result<()>
where
    R: io::AsyncRead + Unpin,
    W: io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 4096];
    loop {
        let n = reader.read(&mut buf).await?;
        let buf = &buf[..n];
        if buf.is_empty() {
            break;
        }

        {
            let mut observer = observer.lock().await;
            let (pcap, hass) = observer.as_mut().expect("observers should be present");
            pcap.observe(buf, direction).await?;
            hass.observe(buf, direction).await?;
        }

        writer.write_all(&buf[..n]).await?;
    }
    Ok(())
}
