use anyhow::{Context, Result, anyhow, bail, ensure};
use grsott::crc::crc_suffixed;
use grsott::tables::pkt_51_20;
use itertools::Itertools;
use pcap_file::pcapng::Block::{EnhancedPacket, InterfaceDescription};
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use std::collections::HashMap;
use std::io::Write;
use std::net::{Ipv4Addr, Shutdown, TcpStream};
use std::ops::Sub;
use std::time::Duration;
use std::{env, fs};

#[derive(Default)]
struct Group {
    inner: HashMap<(Direction, [u8; 3]), Vec<(Duration, Vec<u8>)>>,
}

type Columns = HashMap<usize, Vec<(Duration, i32)>>;

fn main() -> Result<()> {
    let forward = false;
    let mut group = Group::default();

    for arg in env::args().skip(1) {
        let f = fs::File::open(&arg)?;
        let mut f = pcap_file::pcapng::PcapNgReader::new(f)?;
        f.interfaces();
        let mut ref_dur = None;
        let mut i = 0;
        while let Some(v) = f.next_block() {
            match v? {
                InterfaceDescription(_) => (),
                EnhancedPacket(packet) => {
                    if forward {
                        let mut sock = TcpStream::connect((Ipv4Addr::LOCALHOST, 5279))?;
                        sock.shutdown(Shutdown::Read)?;
                        sock.write_all(&packet.data)?;
                    }
                    print_packet_pcap(&packet, &mut ref_dur, &mut group)
                        .with_context(|| anyhow!("processing packet #{i} in {arg:?}"))?;
                }
                v => bail!("unsupported packet {v:?}"),
            }
            i += 1;
        }
    }

    let mut columns = Columns::with_capacity(32);

    for ((dir, key), packets) in group.inner.iter() {
        match (dir, key) {
            // serials and date
            (Direction::FromInverter, [0x06, 0x51, 0x29]) => continue,
            // bunch of nulls and a 31
            (Direction::FromInverter, [0x06, 0x01, 0x18]) => continue,
            // two bytes, 04 / 21; 31 / 31
            (Direction::ToInverter, [0x06, 0x01, 0x19]) => continue,
            // bunch of nulls
            (_, [0x06, 0x01, 0x16]) => continue,
            // single-byte null ack
            (Direction::ToInverter, [0x06, 0x51, 0x04]) => continue,
            (Direction::ToInverter, [0x06, 0x51, 0x20]) => continue,
            (Direction::ToInverter, [0x06, 0x51, 0x50]) => continue,
            // time set?
            (Direction::ToInverter, [0x06, 0x01, 0x18]) => continue,
            (Direction::FromInverter, [0x06, 0x51, 0x20]) => (),
            // _ => (),
            _ => continue,
        }
        let counts = packets.iter().counts();
        println!(
            "=== {:?} major:{:02x} n0:{:02x} n1:{:02x} count:{} / {} ===",
            dir,
            key[0],
            key[1],
            key[2],
            packets.len(),
            counts.len()
        );

        for ((when, packet), count) in counts.iter().sorted_by(|(_, a), (_, b)| b.cmp(a)) {
            println!("{:4} {:4} {}", count, packet.len(), unambiguous(packet));
            match (dir, key) {
                (Direction::FromInverter, [0x06, 0x51, 0x20]) => {
                    print_51_20(packet, *when, &mut columns)?
                }
                _ => (),
            }
        }
    }

    for (col, entries) in columns.iter().sorted_by_key(|(col, _)| *col) {
        println!("=== column {} ===", col);
        // println!("{:?}", entries.iter().map(|(_, v)| *v).counts());
        ten_buckets(&entries.iter().map(|(_, v)| *v).collect::<Vec<_>>());
    }

    Ok(())
}

fn sparkline_counts(v: &[i32]) {
    let counts = v.iter().counts();
    let max_count = *counts.values().max().unwrap_or(&0) as f64;
    let spark_chars = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    for (value, count) in counts.iter().sorted_by_key(|(v, _)| *v) {
        let height =
            ((*count as f64) / max_count * (spark_chars.len() - 1) as f64).round() as usize;
        let spark_char = spark_chars[height];
        println!("{:19} | {:6} {}", value, count, spark_char);
    }
}

fn ten_buckets(v: &[i32]) {
    if v.iter().counts().len() < 10 {
        return sparkline_counts(v);
    }
    let mut v = v.to_vec();
    v.sort();
    let min = v[0];
    let max = v[v.len() - 1];
    for perc in 1..10 {
        let prev = (max - min) * (perc - 1) / 10 + min;
        let val = (max - min) * perc / 10 + min;
        let count = v.iter().filter(|&&x| x > prev && x <= val).count();
        println!("{:8} - {:8} | {:5}", prev + 1, val, count);
    }
}

fn print_51_20(packet: &[u8], when: Duration, columns: &mut Columns) -> Result<()> {
    ensure!(
        packet.len() == 228,
        "expected 228 byte packet for 51 20, not {}",
        packet.len()
    );
    let _logger_serial = std::str::from_utf8(&packet[0..30])?.trim_end_matches(char::from(0));
    let _inverter_serial = std::str::from_utf8(&packet[30..60])?.trim_end_matches(char::from(0));
    // println!("Logger Serial   : {}", logger_serial);
    // println!("Inverter Serial : {}", inverter_serial);
    let packet = &packet[60..];
    // println!("packet: {}", unambiguous(packet));
    let now = time::UtcDateTime::from_unix_timestamp(when.as_secs() as i64)?;
    println!("Timestamp       : {}", now);

    let chunks = packet
        .chunks_exact(4)
        .map(|chunk| i32::from_be_bytes(chunk.try_into().expect("chunks exact")))
        .collect_vec();
    for (i, chunk) in chunks.iter().copied().enumerate() {
        columns.entry(i).or_default().push((when, chunk));
    }
    if chunks.len() < 35 {
        return Ok(());
    }
    for field in pkt_51_20() {
        if !field.useful {
            continue;
        }
        let raw = chunks[usize::from(field.off)];
        match field.kind.divide() {
            Some(divide) => {
                let v = (raw as f64) / (divide as f64);
                println!("{:-20} - {:6.1}", field.name, v);
                continue;
            }
            None => {
                println!("{:-20} - {:4}", field.name, raw);
            }
        }
    }

    Ok(())
}

#[cfg(never)]
fn print_table(packet: &[u8], table: &[Field]) {
    for field in table.iter()
    // .filter(|f| f.useful)
    {
        let start = field.off as usize;
        let end = start + field.len as usize;
        if end > packet.len() {
            println!("  {:20} - out of bounds", field.name);
            continue;
        }
        let slice = &packet[start..end];
        match &field.kind {
            grsott::tables::FieldKind::Text => {
                if let Ok(s) = std::str::from_utf8(slice) {
                    println!(
                        "  {:20} - {}",
                        field.name,
                        s.trim_end_matches(char::from(0))
                    );
                } else {
                    println!("  {:20} - invalid utf8", field.name);
                }
            }
            grsott::tables::FieldKind::U16 { divide } => {
                if slice.len() != 2 {
                    println!(
                        "  {:20} - invalid length for u16 - {}",
                        field.name,
                        unambiguous(slice)
                    );
                    continue;
                }
                let v = u16::from_be_bytes([slice[0], slice[1]]);
                let v = (v as f64) / (*divide as f64);
                println!("  {:20} - {:.2}", field.name, v);
            }
            grsott::tables::FieldKind::I16 { divide } => {
                if slice.len() != 2 {
                    println!("  {:20} - invalid length for i16", field.name);
                    continue;
                }
                let v = i16::from_be_bytes([slice[0], slice[1]]);
                let v = (v as f64) / (*divide as f64);
                println!("  {:20} - {:.2}", field.name, v);
            }
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
enum Direction {
    FromInverter,
    ToInverter,
}

fn print_packet_pcap(
    packet: &EnhancedPacketBlock,
    ref_dur: &mut Option<Duration>,
    group: &mut Group,
) -> Result<()> {
    if ref_dur.is_none() {
        *ref_dur = Some(packet.timestamp);
    }
    let ref_dur = ref_dur.unwrap();
    print_packet(
        match packet.interface_id {
            0 => Direction::FromInverter,
            1 => Direction::ToInverter,
            v => bail!("unknown interface id {v}"),
        },
        packet.timestamp.sub(ref_dur),
        &packet.data,
        group,
        packet.timestamp,
    )
}

fn print_packet(
    dir: Direction,
    ts: Duration,
    data: &[u8],
    group: &mut Group,
    ts_clock: Duration,
) -> Result<()> {
    if data.len() < 8 {
        bail!("expected 8 byte header");
    }

    let (header, body) = data.split_at(8);
    let header: [u8; 8] = header.try_into().expect("just split");

    let [_u0, _seq, _u2, major, len1, len0, n0, n1] = header;
    let len = (len0 as usize) | (len1 as usize) << 8;

    let (body, rest) = body
        .split_at_checked(len)
        .ok_or_else(|| anyhow!("incorrect computed len: {len} from {len0} {len1}"))?;

    crc_suffixed(&data[..len + header.len()]).ok_or_else(|| anyhow!("incorrect CRC"))?;

    let key = b"Growatt";
    let mut decrypted = key
        .iter()
        .cycle()
        .zip(body)
        .map(|(k, v)| *k ^ *v)
        .collect::<Vec<_>>();
    decrypted.pop();
    decrypted.pop();
    let decrypted = decrypted;

    // println!("{:?} {:12} - major:{major:02x} n0:{n0:02x} n1:{n1:02x} len:{len}", ts.as_millis(), format!("{dir:?}"));
    // println!("{}", unambiguous(&decrypted));

    group
        .inner
        .entry((dir, [major, n0, n1]))
        .or_default()
        .push((ts_clock, decrypted));

    ensure!(_u0 == 0, "expected u0==0, not {header:?}");
    ensure!(_u2 == 0, "expected u2==0, not {header:?}");

    if !rest.is_empty() {
        print_packet(dir, ts, rest, group, ts_clock)
            .with_context(|| anyhow!("sub-packet after {len}"))?;
    }

    Ok(())
}

pub fn unambiguous(input: &[u8]) -> String {
    let mut buf = String::with_capacity(2 * input.len());
    for &c in input {
        if c.is_ascii_alphanumeric() || c.is_ascii_punctuation() {
            buf.push(char::from(c));
        } else {
            buf.push_str(&format!("[{c}]"));
        }
        buf.push(' ');
    }
    buf.pop();
    buf
}
