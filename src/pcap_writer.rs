use crate::decode::Direction;
use anyhow::{Context, Result, anyhow};
use pcap_file::DataLink;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use std::fs::File;
use std::io::Write as _;
use std::time::SystemTime;

pub struct PcapWriter {
    inner: PcapNgWriter<File>,
}

impl PcapWriter {
    pub fn new(port: u16) -> anyhow::Result<Self> {
        Ok(Self {
            inner: make_writer(port)?,
        })
    }

    pub async fn observe(&mut self, buf: &[u8], dir: Direction) -> Result<()> {
        let mut packet = EnhancedPacketBlock::default();
        packet.timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("positive epoch");
        packet.original_len = buf.len() as u32;
        packet.data = std::borrow::Cow::Borrowed(buf);
        packet.interface_id = match dir {
            Direction::FromInverter => 0,
            Direction::ToInverter => 1,
        };

        let raw_result = self.inner.write_pcapng_block(packet);
        raw_result
            .map_err(|e| anyhow!("{e:?}"))
            .context("Failed to write packet to pcapng")?;
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<()> {
        self.inner
            .get_mut()
            .flush()
            .context("Failed to flush pcapng writer")
    }
}

fn make_writer(port: u16) -> Result<PcapNgWriter<File>> {
    let path = format!(
        "{}.{}.pcapng",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_millis(),
        port
    );
    let pcap =
        File::create(&path).with_context(|| format!("Failed to create pcapng file at {}", path))?;
    let mut pcap = PcapNgWriter::new(pcap)?;
    // 0th interface description block call: Direction::FromInverter
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

    Ok(pcap)
}
