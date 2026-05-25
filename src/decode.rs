use crate::crc::crc_suffixed;
use anyhow::{Context, Result, anyhow, bail};
use pcap_file::pcapng::Block::{EnhancedPacket, InterfaceDescription};
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use serde::Serialize;
use std::fs::File;
use time::UtcDateTime;

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum Direction {
    FromInverter,
    ToInverter,
}

#[derive(Copy, Clone, Debug)]
pub struct Header {
    pub u0: u8,
    pub seq: u8,
    pub u2: u8,
    pub major: u8,
    pub len1: u8,
    pub len0: u8,
    pub n0: u8,
    pub n1: u8,
}

pub struct Packet {
    pub ts: UtcDateTime,
    pub dir: Direction,
    pub header: Header,
    pub body: Box<[u8]>,
}

impl Packet {
    /** (logger, inverter) */
    pub fn serials(&self) -> Result<(&str, &str)> {
        if self.body.len() < 60 {
            return Err(anyhow!("packet body too short to contain serials"));
        }
        let logger_serial = std::str::from_utf8(&self.body[0..30])?.trim_end_matches(char::from(0));
        let inverter_serial =
            std::str::from_utf8(&self.body[30..60])?.trim_end_matches(char::from(0));

        Ok((logger_serial, inverter_serial))
    }

    pub fn i32_be_chunks(&self) -> Vec<i32> {
        if self.body.len() < 60 {
            return Vec::new();
        }

        self.body[60..]
            .chunks_exact(4)
            .map(|chunk| i32::from_be_bytes(chunk.try_into().expect("chunks exact")))
            .collect()
    }
}

impl Header {
    const BYTES: usize = 8;

    pub fn key(&self) -> [u8; 3] {
        [self.major, self.n0, self.n1]
    }

    pub fn expected_len(&self) -> usize {
        usize::from(self.len0) | usize::from(self.len1) << 8
    }
}

pub fn read_packets_from(packets: &mut Vec<Packet>, f: File) -> anyhow::Result<()> {
    let mut f = pcap_file::pcapng::PcapNgReader::new(f)?;
    let mut i = 0;
    while let Some(v) = f.next_block() {
        match v? {
            InterfaceDescription(_) => (),
            EnhancedPacket(packet) => {
                frame_packets_pcap(&packet, |p| packets.push(p))
                    .with_context(|| anyhow!("processing packet #{i}"))?;
            }
            v => bail!("unsupported packet {v:?}"),
        }
        i += 1;
    }
    Ok(())
}

fn frame_packets_pcap(
    packet: &EnhancedPacketBlock,
    yield_packet: impl FnMut(Packet) -> (),
) -> Result<()> {
    frame_packets(
        match packet.interface_id {
            0 => Direction::FromInverter,
            1 => Direction::ToInverter,
            v => bail!("unknown interface id {v}"),
        },
        &packet.data,
        yield_packet,
        UtcDateTime::from_unix_timestamp(packet.timestamp.as_secs() as i64)?
            + time::Duration::nanoseconds(packet.timestamp.subsec_nanos() as i64),
    )
}

fn frame_packets(
    dir: Direction,
    data: &[u8],
    mut yield_packet: impl FnMut(Packet) -> (),
    ts: UtcDateTime,
) -> Result<()> {
    let (used_len, packet) = frame_a_packet(dir, &data, ts)?;

    yield_packet(packet);

    if 0 != used_len {
        frame_packets(dir, &data[used_len..], yield_packet, ts).context("sub packet")?;
    }

    Ok(())
}

#[derive(Debug, thiserror::Error, Serialize)]
pub enum FrameError {
    #[error("data too short to contain header")]
    TooShort,

    #[error("data length {len} does not match header length {len0} {len1}")]
    LenPastEnd { len: usize, len0: u8, len1: u8 },

    #[error("CRC mismatch for frame")]
    IncorrectCrc,
}

pub fn frame_a_packet(
    dir: Direction,
    data: &[u8],
    ts: UtcDateTime,
) -> Result<(usize, Packet), FrameError> {
    if data.len() < 8 {
        return Err(FrameError::TooShort);
    }

    let (header, body) = data.split_at(Header::BYTES);
    let header: Header = header.try_into().expect("just split");

    let len = header.expected_len();

    let (body, _) = body
        .split_at_checked(len)
        .ok_or_else(|| FrameError::LenPastEnd {
            len,
            len0: header.len0,
            len1: header.len1,
        })?;
    let used_data = Header::BYTES + len;

    crc_suffixed(&data[..used_data]).ok_or(FrameError::IncorrectCrc)?;

    let packet = Packet {
        ts,
        dir,
        header: header.into(),
        body: decrypt(body).into(),
    };

    Ok((used_data, packet))
}

fn decrypt(body: &[u8]) -> Vec<u8> {
    let key = b"Growatt";
    let mut decrypted = key
        .iter()
        .cycle()
        .zip(body)
        .map(|(k, v)| *k ^ *v)
        .collect::<Vec<_>>();
    decrypted.pop();
    decrypted.pop();
    decrypted
}

impl TryFrom<&[u8]> for Header {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        let value: [u8; Header::BYTES] = value
            .try_into()
            .context("data too short to contain header")?;
        Ok(value.into())
    }
}

impl From<[u8; 8]> for Header {
    fn from(value: [u8; 8]) -> Self {
        let [u0, seq, u2, major, len1, len0, n0, n1] = value;
        Self {
            u0,
            seq,
            u2,
            major,
            len1,
            len0,
            n0,
            n1,
        }
    }
}

impl Into<[u8; 8]> for Header {
    fn into(self) -> [u8; 8] {
        let Self {
            u0,
            seq,
            u2,
            major,
            len1,
            len0,
            n0,
            n1,
        } = self;
        [u0, seq, u2, major, len1, len0, n0, n1]
    }
}
