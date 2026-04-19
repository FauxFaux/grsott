use anyhow::{Context, Result, anyhow, ensure};
use grsott::decode::{Direction, Packet, read_packets_from};
use grsott::tables::pkt_51_20;
use itertools::Itertools;
use std::collections::HashMap;
use std::{env, fs};
use time::UtcDateTime;

#[derive(Default)]
struct Group {
    inner: HashMap<(Direction, [u8; 3]), Vec<(UtcDateTime, Vec<u8>)>>,
}

type Columns = HashMap<usize, Vec<(UtcDateTime, i32)>>;

fn main() -> Result<()> {
    let mut packets = Vec::with_capacity(4096);
    let mut file_id = Vec::with_capacity(32);
    for arg in env::args().skip(1) {
        file_id.push((arg.clone(), packets.len()));
        read_packets_from(&mut packets, fs::File::open(&arg)?)
            .with_context(|| anyhow!("Failed to read {}", arg))?;
    }

    packets.sort_by_key(|p| p.ts);

    headline_stats(&packets)?;

    if false {
        analyse_packets(&packets, &file_id)?;
    }

    Ok(())
}

fn headline_stats(packets: &[Packet]) -> Result<()> {
    for pkt in packets {
        let [_u0, _seq, _u2, major, len1, len0, n0, n1] = pkt.header;
        let key = [major, n0, n1];
        match (pkt.dir, key) {
            (Direction::FromInverter, [0x06, 0x51, 0x20]) => (),
            _ => continue,
        }

        let chunks = &pkt.body[60..]
            .chunks_exact(4)
            .map(|chunk| i32::from_be_bytes(chunk.try_into().expect("chunks exact")))
            .collect_vec();

        let (h, m, s) = pkt.ts.time().as_hms();
        print!("{} {h:02}:{m:02}:{s:02}", pkt.ts.date());
        for field in pkt_51_20() {
            if !field.useful {
                continue;
            }
            let div = field
                .kind
                .divide()
                .ok_or_else(|| anyhow!("only numerics"))?;
            let raw = chunks[usize::from(field.off)];
            let v = (raw as f64) / (div as f64);
            print!("{v:9.1}");
        }
        println!();
    }

    let mut i = 0;
    for field in pkt_51_20() {
        if !field.useful {
            continue;
        }
        i += 1;
        println!("              {}{} ", " ".repeat(i * 9), field.name);
    }

    Ok(())
}

fn analyse_packets(packets: &[Packet], file_id: &[(String, usize)]) -> Result<()> {
    let mut group = Group::default();

    for (idx, pkt) in packets.iter().enumerate() {
        group_up(pkt, &mut group).with_context(|| {
            let (file_name, file_start) = file_id
                .iter()
                .rev()
                .find(|(_, start)| *start <= idx)
                .expect("file id lookup");
            let packet_idx = idx - file_start;
            anyhow!("grouping packet #{packet_idx} in {file_name:?}")
        })?;
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

        for ((when, packet), count) in counts.iter().sorted_by(|(_, a), (_, b)| b.cmp(a)).take(10) {
            println!("{:4} {:4} {}", count, packet.len(), unambiguous(packet));
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

fn print_51_20(packet: &[u8], when: UtcDateTime, columns: &mut Columns) -> Result<()> {
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
    println!("Timestamp       : {}", when);

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

fn group_up(pkt: &Packet, group: &mut Group) -> Result<()> {
    let decrypted: &[u8] = &pkt.body;

    // println!("{:?} {:12} - major:{major:02x} n0:{n0:02x} n1:{n1:02x} len:{len}", ts.as_millis(), format!("{dir:?}"));
    // println!("{}", unambiguous(&decrypted));

    let [_u0, _seq, _u2, major, len1, len0, n0, n1] = pkt.header;

    group
        .inner
        .entry((pkt.dir, [major, n0, n1]))
        .or_default()
        .push((pkt.ts, decrypted.to_vec()));

    ensure!(_u0 == 0, "expected u0==0, not {:?}", pkt.header);
    ensure!(_u2 == 0, "expected u2==0, not {:?}", pkt.header);

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
