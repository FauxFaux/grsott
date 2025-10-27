use anyhow::{Context, Result, anyhow};
use bunyarrs::{Bunyarr, vars};
use pcap_file::DataLink;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use std::io::Write;
use std::time::SystemTime;
use std::{env, fs};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const LISTEN_PORT: u16 = 5279;

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

    let path = format!(
        "{}.{}.pcapng",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_millis(),
        client_addr.port()
    );
    let pcap =
        fs::File::create(&path).context(format!("Failed to create pcapng file at {}", path))?;
    let mut pcap = PcapNgWriter::new(pcap)?;
    pcap.write_pcapng_block(InterfaceDescriptionBlock {
        linktype: DataLink::USER12,
        options: vec![],
        snaplen: 0xFFFF,
    })?;
    pcap.write_pcapng_block(InterfaceDescriptionBlock {
        linktype: DataLink::USER13,
        options: vec![],
        snaplen: 0xFFFF,
    })?;
    let pcap = Mutex::new(pcap);

    let (mut client_read, mut client_write) = client_stream.split();
    let (mut server_read, mut server_write) = server_stream.split();

    let client_to_server = async { copy(&mut client_read, &mut server_write, &pcap, 0).await };

    let server_to_client = async { copy(&mut server_read, &mut client_write, &pcap, 1).await };

    tokio::select! {
        result = client_to_server => {
            result?;
        }
        result = server_to_client => {
            result?;
        }
    }

    pcap.lock().await.get_mut().flush()?;

    logger.info(vars! { client_addr }, "closed");
    Ok(())
}

async fn copy<R, W>(
    reader: &mut R,
    writer: &mut W,
    pcap: &Mutex<PcapNgWriter<fs::File>>,
    iface: u32,
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

        write_pcap(pcap, buf, iface).await?;

        writer.write_all(&buf[..n]).await?;
    }
    Ok(())
}

async fn write_pcap(pcap: &Mutex<PcapNgWriter<fs::File>>, buf: &[u8], iface: u32) -> Result<()> {
    let mut packet = EnhancedPacketBlock::default();
    packet.timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("positive epoch");
    packet.original_len = buf.len() as u32;
    packet.data = std::borrow::Cow::Borrowed(buf);
    packet.interface_id = iface;

    let mut pcap = pcap.lock().await;
    let raw_result = pcap.write_pcapng_block(packet);
    raw_result
        .map_err(|e| anyhow!("{e:?}"))
        .context("Failed to write packet to pcapng")?;
    drop(pcap);
    Ok(())
}
