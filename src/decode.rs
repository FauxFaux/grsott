use crate::crc::crc_suffixed;
use anyhow::{Context, Result, anyhow, bail};
use pcap_file::pcapng::Block::{EnhancedPacket, InterfaceDescription};
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use std::fs::File;
use std::time::Duration;
use time::UtcDateTime;

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum Direction {
    FromInverter,
    ToInverter,
}

type Header = [u8; 8];

pub struct Packet {
    pub ts: UtcDateTime,
    pub dir: Direction,
    pub header: Header,
    pub body: Box<[u8]>,
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
        packet.timestamp,
    )
}

fn frame_packets(
    dir: Direction,
    data: &[u8],
    mut yield_packet: impl FnMut(Packet) -> (),
    ts_clock: Duration,
) -> Result<()> {
    if data.len() < 8 {
        bail!("expected 8 byte header");
    }

    let (header, body) = data.split_at(8);
    let header: [u8; 8] = header.try_into().expect("just split");

    let [_u0, _seq, _u2, _major, len1, len0, _n0, _n1] = header;
    let len = (len0 as usize) | (len1 as usize) << 8;

    let (body, rest) = body
        .split_at_checked(len)
        .ok_or_else(|| anyhow!("incorrect computed len: {len} from {len0} {len1}"))?;

    crc_suffixed(&data[..len + header.len()]).ok_or_else(|| anyhow!("incorrect CRC"))?;

    yield_packet(Packet {
        ts: UtcDateTime::from_unix_timestamp(ts_clock.as_secs() as i64)?
            + time::Duration::nanoseconds(ts_clock.subsec_nanos() as i64),
        dir,
        header,
        body: decrypt(body).into(),
    });

    if !rest.is_empty() {
        frame_packets(dir, rest, yield_packet, ts_clock)
            .with_context(|| anyhow!("sub-packet after {len}"))?;
    }

    Ok(())
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
