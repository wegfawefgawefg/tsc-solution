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
            arg!(-b --big_file "Use this if pcap file is bigger than your ram")
                .action(ArgAction::SetTrue),
        )
        .get_matches();

    let path = matches.get_one::<String>("PATH").expect("no path provided");
    let mut price_quotes = parse_price_quotes_from_file(path);

    if *matches.get_one::<bool>("sorted").unwrap() {
        price_quotes.sort_by(|a, b| a.quote_accept_time.cmp(&b.quote_accept_time));
    }

    for price_quote in price_quotes {
        println!("{}", price_quote);
    }
}

pub fn parse_price_quotes_from_file(path: &str) -> Vec<PriceQuote> {
    let file = File::open(path).expect("couldn't read file");
    let mut reader = PcapReader::new(file).expect("failed to read pcap file");

    let mut packet_count = 0;
    let mut non_udp = 0;
    let mut wrong_port = 0;
    let mut failed_to_parse_count = 0;
    let mut man_packets: Vec<PriceQuote> = vec![];

    while let Some(pcap_packet) = reader.next_packet() {
        packet_count += 1;
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
            non_udp += 1;
            continue;
        };

        // skip if wrong port
        let destination_port = udp.destination_port();
        if destination_port != 15515 && destination_port != 15516 {
            wrong_port += 1;
            continue;
        }

        let packet_received_time = pcap_packet.timestamp;
        let payload = parsed_packet.payload;
        match PriceQuote::from_bytes(packet_received_time, payload) {
            Ok(man_packet) => {
                man_packets.push(man_packet);
            }
            Err(_) => {
                failed_to_parse_count += 1;
            }
        }
    }

    println!("parsed: {}", man_packets.len());
    println!("total_packets: {}", packet_count);
    println!("failed_to_parse: {}", failed_to_parse_count);
    println!("non_udp: {}", non_udp);
    println!("wrong_port: {}", wrong_port);

    man_packets
}
