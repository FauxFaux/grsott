use anyhow::{Context, Result};
use bunyarrs::{Bunyarr, vars};
use grsott::decode::Direction;
use grsott::observe::Observer;
use grsott::pcap_writer::PcapWriter;
use std::env;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const LISTEN_PORT: u16 = 5279;

type Observers = [Observer; 1];

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
    let observer = Mutex::new([Observer::Pcap(pcap)]);

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

    tokio::select! {
        result = client_to_server => {
            result?;
        }
        result = server_to_client => {
            result?;
        }
    }

    for observer in observer.lock().await.iter_mut() {
        observer.flush().await?;
    }

    logger.info(vars! { client_addr }, "closed");
    Ok(())
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
            for observer in observer.lock().await.iter_mut() {
                observer.observe(buf, direction).await?;
            }
        }

        writer.write_all(&buf[..n]).await?;
    }
    Ok(())
}
