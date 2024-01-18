use std::fs::File;

use clap::{arg, command, ArgAction};
use etherparse::{SlicedPacket, TransportSlice};
use pcap_file::pcap::PcapReader;
use price_quote::PriceQuote;

pub mod price_quote;

fn main() {
    let matches = command!() // uses metadata from Cargo.toml
        .about("PCap Parser")
        .arg(arg!([PATH] "Path to the pcap file").required(true))
        .arg(
            arg!(-r --sorted "Sort Quotes by Quote Accept Time")
                .default_value("false")
                .action(ArgAction::SetTrue),
        )
        .arg(
            // UNINPLEMENTED
            arg!(-b --big_file "Use this if pcap file is bigger than your ram")
                .action(ArgAction::SetTrue),
        )
        .arg(arg!(-s --only_one "Use this to try parsing just one").action(ArgAction::SetTrue))
        .get_matches();

    let path = matches.get_one::<String>("PATH").expect("no path provided");

    if *matches.get_one::<bool>("only_one").unwrap() {
        // load the one file, instantly parse as a price quote, and print it
        // this isnt a pcap file, just a single price quote in hex
        let dur = std::time::Duration::new(0, 0);
        let price_quote = PriceQuote::from_bytes(dur, &std::fs::read(path).unwrap()).unwrap();
        println!("{}", price_quote);
        return;
    }

    let (mut price_quotes, parse_stats) = parse_price_quotes_from_file(path);

    if *matches.get_one::<bool>("sorted").unwrap() {
        price_quotes.sort_by(|a, b| a.quote_accept_time.cmp(&b.quote_accept_time));
    }

    for price_quote in price_quotes {
        println!("{}", price_quote);
    }

    // print the parse stats
    println!("\n{}", parse_stats);
}

///////////////////////// PARSING /////////////////////////
pub struct PacketParseStats {
    pub parse_time: std::time::Duration,
    pub packet_count: u64,

    pub successfully_parsed: u64,
    pub rejected: u64,
    pub failed: u64,

    pub non_udp: u64,
    pub wrong_port: u64,
    pub not_a_price_quote: u64,
}

impl PacketParseStats {
    pub fn new() -> Self {
        PacketParseStats {
            parse_time: std::time::Duration::new(0, 0),
            packet_count: 0,

            successfully_parsed: 0,
            rejected: 0,
            failed: 0,

            non_udp: 0,
            wrong_port: 0,
            not_a_price_quote: 0,
        }
    }
}

impl Default for PacketParseStats {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for PacketParseStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let duration = self.parse_time.as_millis() as f64;
        let total = self.packet_count as f64;
        let successfully_parsed = self.successfully_parsed as f64;
        let rejected = self.rejected as f64;
        let failed = self.failed as f64;

        let non_udp = self.non_udp as f64;
        let wrong_port = self.wrong_port as f64;
        let not_a_price_quote = self.not_a_price_quote as f64;

        writeln!(f, "Packet Parse Stats:")?;
        writeln!(f, "  Parse Time: {:.2}ms", duration)?;
        writeln!(f, "  Total Packets: {}", self.packet_count)?;
        writeln!(
            f,
            "  Successfully Parsed: {} ({:.2}%)",
            successfully_parsed,
            successfully_parsed / total * 100.0
        )?;
        writeln!(
            f,
            "  Rejected: {} ({:.2}%)",
            rejected,
            rejected / total * 100.0
        )?;
        writeln!(f, "  Failed: {} ({:.2}%)", failed, failed / total * 100.0)?;
        writeln!(
            f,
            "  Non UDP: {} ({:.2}%)",
            non_udp,
            non_udp / total * 100.0
        )?;
        writeln!(
            f,
            "  Wrong Port: {} ({:.2}%)",
            wrong_port,
            wrong_port / total * 100.0
        )?;
        writeln!(
            f,
            "  Not a Price Quote: {} ({:.2}%)",
            not_a_price_quote,
            not_a_price_quote / total * 100.0
        )?;
        Ok(())
    }
}

pub fn parse_price_quotes_from_file(path: &str) -> (Vec<PriceQuote>, PacketParseStats) {
    let file = File::open(path).expect("couldn't read file");
    let mut reader = PcapReader::new(file).expect("failed to read pcap file");

    let start = std::time::Instant::now();
    let mut parse_stats = PacketParseStats::new();
    let mut price_quotes: Vec<PriceQuote> = vec![];
    while let Some(pcap_packet) = reader.next_packet() {
        parse_stats.packet_count += 1;

        // try to parse packet
        let pcap_packet = pcap_packet.expect("failed to get packet");
        let packet = pcap_packet.data;
        let parsed_packet = match SlicedPacket::from_ethernet(&packet) {
            Ok(packet) => packet,
            Err(err) => {
                eprintln!("Failed to parse packet: {:?}", err);
                continue;
            }
        };

        // skip if not udp
        let udp = if let Some(TransportSlice::Udp(udp)) = parsed_packet.transport {
            udp
        } else {
            parse_stats.non_udp += 1;
            parse_stats.rejected += 1;
            continue;
        };

        // skip if wrong port
        let destination_port = udp.destination_port();
        if destination_port != 15515 && destination_port != 15516 {
            parse_stats.wrong_port += 1;
            parse_stats.rejected += 1;
            continue;
        }

        // skip if its not a price quote
        let payload = parsed_packet.payload;
        const QUOTE_PACKET_PREFIX: &[u8; 5] = b"B6034";
        if !payload.starts_with(QUOTE_PACKET_PREFIX) {
            parse_stats.not_a_price_quote += 1;
            parse_stats.rejected += 1;
            continue;
        }

        // try to parse price quote
        let payload = parsed_packet.payload;
        let packet_received_time = pcap_packet.timestamp;
        match PriceQuote::from_bytes(packet_received_time, payload) {
            Ok(price_quote) => {
                price_quotes.push(price_quote);
            }
            Err(_) => {
                parse_stats.failed += 1;
            }
        }
    }
    parse_stats.parse_time = start.elapsed();

    parse_stats.successfully_parsed = price_quotes.len() as u64;

    (price_quotes, parse_stats)
}
