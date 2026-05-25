use crate::decode::{Direction, frame_a_packet};
use crate::tables::{pkt_51_04, pkt_51_20};
use anyhow::Context;
use bunyarrs::{Bunyarr, vars};
use mqtt_reeze::{Mqtt, QoS, Topic};
use time::UtcDateTime;

pub struct HassWriter {
    inner: Mqtt,
    buf: Vec<u8>,
    logger: Bunyarr,
}

impl HassWriter {
    pub fn new(inner: Mqtt) -> Self {
        HassWriter {
            inner,
            buf: Vec::with_capacity(1024),
            logger: Bunyarr::with_name("hass_writer"),
        }
    }

    pub async fn observe(&mut self, buf: &[u8], dir: Direction) -> anyhow::Result<()> {
        match dir {
            Direction::FromInverter => (),
            Direction::ToInverter => return Ok(()),
        }

        self.buf.extend(buf);

        // plausibly an interesting packet
        while self.buf.len() >= 60 {
            let pkt = match frame_a_packet(dir, &self.buf, UtcDateTime::now()) {
                Ok((used_len, pkt)) => {
                    assert!(
                        used_len > 0,
                        "framing a packet should always consume at least one byte"
                    );
                    self.buf.drain(0..used_len);
                    pkt
                }
                Err(e) => {
                    self.logger
                        .info(vars! { e }, "Failed to frame a packet from the buffer");
                    // not a packet, drop the first byte and try again
                    self.buf.remove(0);
                    continue;
                }
            };

            let fields = match pkt.header.key() {
                [0x06, 0x51, 0x20] => pkt_51_20(),
                [0x06, 0x51, 0x04] => pkt_51_04(),
                _ => continue,
            };

            let (_logger, inverter) = pkt.serials()?;

            for field in fields.iter() {
                if !field.useful {
                    continue;
                }

                let v = match field.read_value(&pkt.body) {
                    Some(v) => v,
                    None => continue,
                };

                let topic_name = format!("inverter/{inverter}/{}", field.name);
                let topic = Topic::new(topic_name, QoS::AtLeastOnce, true);
                self.inner
                    .publish(&topic, v.to_string().into_bytes())
                    .await
                    .context("Failed to publish a field to mqtt")?;
            }
        }

        Ok(())
    }

    pub async fn finish(self) -> anyhow::Result<()> {
        self.inner.finish().await.context("Failed to flush mqtt")
    }
}
