use anyhow::{Context, Result, anyhow};
use grsott::decode::{Direction, Packet, read_packets_from, unambiguous};
use grsott::tables::{Field, pkt_51_04, pkt_51_20};
use std::{env, fs};
use time::format_description::well_known::Rfc3339;

fn main() -> Result<()> {
    let mut packets = Vec::with_capacity(4096);
    let mut file_id = Vec::with_capacity(32);
    for arg in env::args().skip(1) {
        file_id.push((arg.clone(), packets.len()));
        read_packets_from(&mut packets, fs::File::open(&arg)?)
            .with_context(|| anyhow!("Failed to read {}", arg))?;
    }

    packets.sort_by_key(|p| p.ts);

    for pkt in packets {
        if pkt.dir != Direction::FromInverter {
            continue;
        }

        if pkt.body_len() < 60 {
            continue;
        }

        let [a, b, c] = pkt.header.key();
        let key = format!("{:02x}{:02x}{:02x}", a, b, c);

        let (_logger, inverter) = pkt.serials()?;
        if !inverter.starts_with("E") {
            continue;
        }

        let time = pkt.ts.format(&Rfc3339)?;

        match key.as_ref() {
            "065120" => {
                print_table(&pkt_51_20(), &pkt.body, format!("{time}\t{key}"))?;
            }
            "065104" => {
                print_table(&pkt_51_04(), &pkt.body, format!("{time}\t{key}"))?;
            }
            _ => {
                println!("{}\t{key}\t{}", time, unambiguous(&pkt.body));
            }
        };
    }

    Ok(())
}

fn print_table(fields: &[Field], body: &[u8], prefix: String) -> Result<()> {
    for field in fields {
        if !field.useful {
            continue;
        }

        let v = match field.read_value(body) {
            Some(v) => v,
            None => continue,
        };

        println!("{}\t{}\t{v}", prefix, field.name);
    }
    Ok(())
}
