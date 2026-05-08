use crate::decode::Direction;
use anyhow::Result;

pub enum Observer {
    Pcap(crate::pcap_writer::PcapWriter),
}

impl Observer {
    pub async fn observe(&mut self, buf: &[u8], dir: Direction) -> Result<()> {
        match self {
            Self::Pcap(pcap) => pcap.observe(buf, dir).await,
        }
    }

    pub async fn flush(&mut self) -> Result<()> {
        match self {
            Self::Pcap(pcap) => pcap.flush().await,
        }
    }
}
