use std::fs;
use std::io::{Error as IOError, Write};
use std::path::Path;
use std::{
    fs::File,
    io::{Cursor, Read},
};

use byteorder::{BigEndian, ReadBytesExt};
use etherparse::{SlicedPacket, TransportSlice};
use pcap_file::pcap::PcapReader;

#[derive(Default, Debug)]
pub struct ManPacket {
    pub data_type: u16,
    pub information_type: u16,
    pub market_type: u8,
    pub issue_code: String,
    pub issue_seq_no: u32, // only 3 bytes
    pub market_status_type: u16,
    pub total_bid_quote_volume: u64,           // only 7 bytes
    pub best_bid_price_1st: u64,               // 5 bytes
    pub best_bid_quantity_1st: u64,            // 7 bytes
    pub best_bid_price_2nd: u64,               // 5 bytes
    pub best_bid_quantity_2nd: u64,            // 7 bytes
    pub best_bid_price_3rd: u64,               // 5 bytes
    pub best_bid_quantity_3rd: u64,            // 7 bytes
    pub best_bid_price_4th: u64,               // 5 bytes
    pub best_bid_quantity_4th: u64,            // 7 bytes
    pub best_bid_price_5th: u64,               // 5 bytes
    pub best_bid_quantity_5th: u64,            // 7 bytes
    pub total_ask_quote_volume: u64,           // 7 bytes
    pub best_ask_price_1st: u64,               // 5 bytes
    pub best_ask_quantity_1st: u64,            // 7 bytes
    pub best_ask_price_2nd: u64,               // 5 bytes
    pub best_ask_quantity_2nd: u64,            // 7 bytes
    pub best_ask_price_3rd: u64,               // 5 bytes
    pub best_ask_quantity_3rd: u64,            // 7 bytes
    pub best_ask_price_4th: u64,               // 5 bytes
    pub best_ask_quantity_4th: u64,            // 7 bytes
    pub best_ask_price_5th: u64,               // 5 bytes
    pub best_ask_quantity_5th: u64,            // 7 bytes
    pub no_of_best_bid_valid_quote_total: u64, // 5 bytes
    pub no_of_best_bid_quote_1st: u32,
    pub no_of_best_bid_quote_2nd: u32,
    pub no_of_best_bid_quote_3rd: u32,
    pub no_of_best_bid_quote_4th: u32,
    pub no_of_best_bid_quote_5th: u32,
    pub no_of_best_ask_valid_quote_total: u64, // 5 bytes
    pub no_of_best_ask_quote_1st: u32,
    pub no_of_best_ask_quote_2nd: u32,
    pub no_of_best_ask_quote_3rd: u32,
    pub no_of_best_ask_quote_4th: u32,
    pub no_of_best_ask_quote_5th: u32,
    pub quote_accept_time: u64,
}

impl ManPacket {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IOError> {
        let mut rdr = Cursor::new(bytes);

        Ok(ManPacket {
            data_type: rdr.read_u16::<BigEndian>()?,
            information_type: rdr.read_u16::<BigEndian>()?,
            market_type: rdr.read_u8()?,
            issue_code: {
                let mut buf = [0; 12]; // Adjust size as per your data
                rdr.read_exact(&mut buf)?;
                String::from_utf8_lossy(&buf).into_owned()
            },
            issue_seq_no: {
                let mut buf = [0; 3];
                rdr.read_exact(&mut buf)?;
                (buf[0] as u32) << 16 | (buf[1] as u32) << 8 | buf[2] as u32
            },
            market_status_type: rdr.read_u16::<BigEndian>()?,
            total_bid_quote_volume: rdr.read_uint::<BigEndian>(7)?,
            best_bid_price_1st: rdr.read_uint::<BigEndian>(5)?,
            best_bid_quantity_1st: rdr.read_uint::<BigEndian>(7)?,
            best_bid_price_2nd: rdr.read_uint::<BigEndian>(5)?,
            best_bid_quantity_2nd: rdr.read_uint::<BigEndian>(7)?,
            best_bid_price_3rd: rdr.read_uint::<BigEndian>(5)?,
            best_bid_quantity_3rd: rdr.read_uint::<BigEndian>(7)?,
            best_bid_price_4th: rdr.read_uint::<BigEndian>(5)?,
            best_bid_quantity_4th: rdr.read_uint::<BigEndian>(7)?,
            best_bid_price_5th: rdr.read_uint::<BigEndian>(5)?,
            best_bid_quantity_5th: rdr.read_uint::<BigEndian>(7)?,
            total_ask_quote_volume: rdr.read_uint::<BigEndian>(7)?,
            best_ask_price_1st: rdr.read_uint::<BigEndian>(5)?,
            best_ask_quantity_1st: rdr.read_uint::<BigEndian>(7)?,
            best_ask_price_2nd: rdr.read_uint::<BigEndian>(5)?,
            best_ask_quantity_2nd: rdr.read_uint::<BigEndian>(7)?,
            best_ask_price_3rd: rdr.read_uint::<BigEndian>(5)?,
            best_ask_quantity_3rd: rdr.read_uint::<BigEndian>(7)?,
            best_ask_price_4th: rdr.read_uint::<BigEndian>(5)?,
            best_ask_quantity_4th: rdr.read_uint::<BigEndian>(7)?,
            best_ask_price_5th: rdr.read_uint::<BigEndian>(5)?,
            best_ask_quantity_5th: rdr.read_uint::<BigEndian>(7)?,
            no_of_best_bid_valid_quote_total: rdr.read_uint::<BigEndian>(5)?,
            no_of_best_bid_quote_1st: rdr.read_u32::<BigEndian>()?,
            no_of_best_bid_quote_2nd: rdr.read_u32::<BigEndian>()?,
            no_of_best_bid_quote_3rd: rdr.read_u32::<BigEndian>()?,
            no_of_best_bid_quote_4th: rdr.read_u32::<BigEndian>()?,
            no_of_best_bid_quote_5th: rdr.read_u32::<BigEndian>()?,
            no_of_best_ask_valid_quote_total: rdr.read_uint::<BigEndian>(5)?,
            no_of_best_ask_quote_1st: rdr.read_u32::<BigEndian>()?,
            no_of_best_ask_quote_2nd: rdr.read_u32::<BigEndian>()?,
            no_of_best_ask_quote_3rd: rdr.read_u32::<BigEndian>()?,
            no_of_best_ask_quote_4th: rdr.read_u32::<BigEndian>()?,
            no_of_best_ask_quote_5th: rdr.read_u32::<BigEndian>()?,
            quote_accept_time: rdr.read_u64::<BigEndian>()?,
        })
    }
}

fn main() {
    let path = "./mdf-kospi200.20110216-0.pcap";
    let file = File::open(path).expect("couldn't read file");
    let mut reader = PcapReader::new(file).expect("failed to read pcap file");

    let mut packet_count = 0;
    let mut non_udp = 0;
    let mut wrong_port = 0;
    let mut failed_to_parse_count = 0;
    let mut man_packets: Vec<ManPacket> = vec![];

    let mut failed_to_parse_packets = vec![];
    let mut some_good_packets = vec![];
    const MAX_GOOD_PACKETS: usize = 8;

    while let Some(pcap_packet) = reader.next_packet() {
        packet_count += 1;
        let packet = pcap_packet.expect("failed to get packet").data;
        match SlicedPacket::from_ethernet(&packet) {
            Ok(parsed_packet) => {
                if let Some(TransportSlice::Udp(udp)) = parsed_packet.transport {
                    let destination_port = udp.destination_port();
                    if destination_port == 15515 || destination_port == 15516 {
                        // Parse the ManPacket structure from the payload
                        let payload = parsed_packet.payload;
                        match ManPacket::from_bytes(payload) {
                            Ok(man_packet) => {
                                man_packets.push(man_packet);
                                if some_good_packets.len() < MAX_GOOD_PACKETS {
                                    some_good_packets.push((packet_count, payload.to_vec()));
                                }
                            }
                            Err(err) => {
                                failed_to_parse_packets.push((packet_count, payload.to_vec()));
                                failed_to_parse_count += 1;
                                eprintln!("Failed to parse ManPacket: {:?}", err);
                            }
                        }
                    } else {
                        wrong_port += 1;
                    }
                } else {
                    non_udp += 1;
                }
            }
            Err(err) => {
                eprintln!("Failed to parse packet: {:?}", err);
            }
        }
    }

    println!("{:?}", man_packets.first().unwrap());
    println!("parsed: {}", man_packets.len());
    println!("total_packets: {}", packet_count);
    println!("failed_to_parse: {}", failed_to_parse_count);
    println!("non_udp: {}", non_udp);
    println!("wrong_port: {}", wrong_port);

    // save failed_packets
    let dir_path = "failed_packets";
    if !Path::new(dir_path).exists() {
        fs::create_dir(dir_path).expect("Failed to create directory");
    }

    for (index, (count, payload)) in failed_to_parse_packets.iter().enumerate() {
        let filename = format!("{}/failed_payload_{}_{}.bin", dir_path, index, count);
        let mut file = File::create(&filename).expect("Failed to create file");

        file.write_all(payload)
            .expect("Failed to write payload to file");
    }

    println!(
        "Saved {} failed payloads in {}",
        failed_to_parse_packets.len(),
        dir_path
    );

    // save some good packets for comparison
    let dir_path = "good_packets";
    if !Path::new(dir_path).exists() {
        fs::create_dir(dir_path).expect("Failed to create directory");
    }

    for (index, (count, payload)) in some_good_packets.iter().enumerate() {
        let filename = format!("{}/success_payload_{}_{}.bin", dir_path, index, count);
        let mut file = File::create(&filename).expect("Failed to create file");

        file.write_all(payload)
            .expect("Failed to write payload to file");
    }

    println!(
        "Saved {} failed payloads in {}",
        some_good_packets.len(),
        dir_path
    );
}
