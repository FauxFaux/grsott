use anyhow::{Context, Result, anyhow};
use bunyarrs::{Bunyarr, vars};
use grsott::decode::Direction;
use grsott::hass_writer::HassWriter;
use grsott::pcap_writer::PcapWriter;
use mqtt_reeze::Mqtt;
use sd_notify::NotifyState;
use socket2::{SockRef, TcpKeepalive};
use std::env;
use std::time::Duration;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep_until, timeout};

const LISTEN_PORT: u16 = 5279;
const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(6 * 60);
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const KEEPALIVE_IDLE: Duration = Duration::from_secs(60);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const KEEPALIVE_RETRIES: u32 = 3;

type Observers = (PcapWriter, HassWriter);

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
    sd_notify::notify(&[NotifyState::Ready]).context("Failed to notify systemd of readiness")?;

    let mut watchdog = sd_notify::watchdog_enabled()
        .map(|period| tokio::time::interval((period / 2).max(Duration::from_millis(1))));
    let mut connections = JoinSet::new();

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (client_stream, client_addr) = accepted.context("Failed to accept connection")?;
                logger.info(vars! { client_addr }, "accepted connection");
                let destination = destination.clone();

                connections.spawn(async move {
                    (client_addr, handle_connection(client_stream, client_addr, &destination).await)
                });
            }
            joined = connections.join_next(), if !connections.is_empty() => {
                match joined.expect("nonempty connection set") {
                    Ok((client_addr, Err(e))) => {
                        let e = format!("{e:?}");
                        logger.error(vars! { client_addr, e }, "handle error");
                    }
                    Ok((_, Ok(()))) => {}
                    Err(e) => {
                        let e = format!("{e:?}");
                        logger.error(vars! { e }, "connection task failed");
                    }
                }
            }
            _ = async {
                if let Some(watchdog) = &mut watchdog {
                    watchdog.tick().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                sd_notify::notify(&[NotifyState::Watchdog])
                    .context("Failed to notify systemd watchdog")?;
            }
        }
    }
}

async fn handle_connection(
    mut client_stream: TcpStream,
    client_addr: std::net::SocketAddr,
    destination: &str,
) -> Result<()> {
    configure_keepalive(&client_stream).context("Failed to set client TCP keepalive")?;
    let mut server_stream = timeout(IO_TIMEOUT, TcpStream::connect(destination))
        .await
        .context("Timed out connecting to destination")?
        .with_context(|| format!("Failed to connect to destination {destination}"))?;
    configure_keepalive(&server_stream).context("Failed to set upstream TCP keepalive")?;

    let logger = Bunyarr::with_name("handle");

    logger.info(vars! { client_addr, destination }, "established");

    let port = client_addr.port();
    let pcap = PcapWriter::new(port)?;
    let hass = HassWriter::new(Mqtt::new_from_env(&format!("grsott-{port}"))?);
    let observer: Mutex<Observers> = Mutex::new((pcap, hass));
    let (activity_tx, mut activity_rx) = watch::channel(Instant::now());
    let upstream_activity = activity_tx.clone();

    let (mut client_read, mut client_write) = client_stream.split();
    let (mut server_read, mut server_write) = server_stream.split();

    let client_to_server = async {
        copy(
            &mut client_read,
            &mut server_write,
            &observer,
            Direction::FromInverter,
            upstream_activity,
        )
        .await
    };

    let server_to_client = async {
        copy(
            &mut server_read,
            &mut client_write,
            &observer,
            Direction::ToInverter,
            activity_tx,
        )
        .await
    };

    let connection_result = tokio::select! {
        result = client_to_server => result,
        result = server_to_client => result,
        result = wait_for_inactivity(&mut activity_rx, CONNECTION_IDLE_TIMEOUT) => result,
    };

    // Close both TCP legs before waiting for optional capture and MQTT cleanup.
    drop(client_stream);
    drop(server_stream);

    let (mut pcap, hass) = observer.into_inner();
    let flush_pcap = timeout(IO_TIMEOUT, pcap.flush())
        .await
        .context("Timed out flushing pcapng")
        .and_then(|result| result);
    let finish_hass = timeout(IO_TIMEOUT, hass.finish())
        .await
        .context("Timed out flushing MQTT")
        .and_then(|result| result);

    connection_result?;
    flush_pcap?;
    finish_hass?;
    logger.info(vars! { client_addr }, "closed");
    Ok(())
}

async fn wait_for_inactivity(
    activity: &mut watch::Receiver<Instant>,
    idle: Duration,
) -> Result<()> {
    loop {
        let deadline = *activity.borrow_and_update() + idle;
        tokio::select! {
            _ = sleep_until(deadline) => return Err(anyhow!("No traffic forwarded for {idle:?}")),
            changed = activity.changed() => changed.context("Activity channel closed")?,
        }
    }
}

fn configure_keepalive(stream: &TcpStream) -> Result<()> {
    let keepalive = TcpKeepalive::new()
        .with_time(KEEPALIVE_IDLE)
        .with_interval(KEEPALIVE_INTERVAL)
        .with_retries(KEEPALIVE_RETRIES);
    SockRef::from(stream).set_tcp_keepalive(&keepalive)?;
    Ok(())
}

async fn copy<R, W>(
    reader: &mut R,
    writer: &mut W,
    observer: &Mutex<Observers>,
    direction: Direction,
    activity: watch::Sender<Instant>,
) -> Result<()>
where
    R: io::AsyncRead + Unpin,
    W: io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 4096];
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .context("Failed to read TCP stream")?;
        let buf = &buf[..n];
        if buf.is_empty() {
            break;
        }

        {
            let mut observer = observer.lock().await;
            let (pcap, hass) = &mut *observer;
            timeout(IO_TIMEOUT, pcap.observe(buf, direction))
                .await
                .context("Timed out writing capture")??;
            timeout(IO_TIMEOUT, hass.observe(buf, direction))
                .await
                .context("Timed out publishing MQTT data")??;
        }

        timeout(IO_TIMEOUT, writer.write_all(buf))
            .await
            .context("Timed out writing TCP stream")??;
        activity.send_replace(Instant::now());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::advance;

    #[tokio::test(start_paused = true)]
    async fn inactivity_deadline_follows_forwarded_traffic() {
        let (activity_tx, mut activity_rx) = watch::channel(Instant::now());
        let monitor = tokio::spawn(async move {
            wait_for_inactivity(&mut activity_rx, Duration::from_secs(10)).await
        });
        tokio::task::yield_now().await;

        advance(Duration::from_secs(8)).await;
        activity_tx.send_replace(Instant::now());
        tokio::task::yield_now().await;
        advance(Duration::from_secs(8)).await;
        assert!(!monitor.is_finished());

        advance(Duration::from_secs(2)).await;
        assert!(monitor.await.unwrap().is_err());
    }
}
