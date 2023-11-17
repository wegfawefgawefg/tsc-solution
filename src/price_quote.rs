use std::fmt;
use std::io::Error as IOError;
use std::io::{Cursor, Read};
use std::time::Duration;

use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use chrono::{TimeZone, Utc};
use colored::Colorize;

#[derive(Default, Debug, Clone, PartialEq, Eq, Hash)]
pub struct PriceQuote {
    pub packet_rcv_time: Duration,
    pub data_type: u16,
    pub information_type: u16,
    pub market_type: u8,
    pub issue_code: String,
    pub issue_seq_no: u32, // only 3 bytes
    pub market_status_type: u16,
    pub total_bid_quote_volume: u64, // only 7 bytes

    pub best_bid_price_1st: u64,     // 5 bytes
    pub best_bid_quantity_1st: u64,  // 7 bytes
    pub best_bid_price_2nd: u64,     // 5 bytes
    pub best_bid_quantity_2nd: u64,  // 7 bytes
    pub best_bid_price_3rd: u64,     // 5 bytes
    pub best_bid_quantity_3rd: u64,  // 7 bytes
    pub best_bid_price_4th: u64,     // 5 bytes
    pub best_bid_quantity_4th: u64,  // 7 bytes
    pub best_bid_price_5th: u64,     // 5 bytes
    pub best_bid_quantity_5th: u64,  // 7 bytes
    pub total_ask_quote_volume: u64, // 7 bytes
    pub best_ask_price_1st: u64,     // 5 bytes
    pub best_ask_quantity_1st: u64,  // 7 bytes
    pub best_ask_price_2nd: u64,     // 5 bytes
    pub best_ask_quantity_2nd: u64,  // 7 bytes
    pub best_ask_price_3rd: u64,     // 5 bytes
    pub best_ask_quantity_3rd: u64,  // 7 bytes
    pub best_ask_price_4th: u64,     // 5 bytes
    pub best_ask_quantity_4th: u64,  // 7 bytes
    pub best_ask_price_5th: u64,     // 5 bytes
    pub best_ask_quantity_5th: u64,  // 7 bytes

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

impl PriceQuote {
    pub fn from_bytes(rcv_time: Duration, bytes: &[u8]) -> Result<Self, IOError> {
        let mut rdr = Cursor::new(bytes);

        Ok(PriceQuote {
            packet_rcv_time: rcv_time,
            data_type: rdr.read_u16::<LittleEndian>()?,
            information_type: rdr.read_u16::<LittleEndian>()?,
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
            market_status_type: rdr.read_u16::<LittleEndian>()?,
            total_bid_quote_volume: rdr.read_uint::<LittleEndian>(7)?,

            best_bid_price_1st: rdr.read_uint::<LittleEndian>(5)?,
            best_bid_quantity_1st: rdr.read_uint::<LittleEndian>(7)?,
            best_bid_price_2nd: rdr.read_uint::<LittleEndian>(5)?,
            best_bid_quantity_2nd: rdr.read_uint::<LittleEndian>(7)?,
            best_bid_price_3rd: rdr.read_uint::<LittleEndian>(5)?,
            best_bid_quantity_3rd: rdr.read_uint::<LittleEndian>(7)?,
            best_bid_price_4th: rdr.read_uint::<LittleEndian>(5)?,
            best_bid_quantity_4th: rdr.read_uint::<LittleEndian>(7)?,
            best_bid_price_5th: rdr.read_uint::<LittleEndian>(5)?,
            best_bid_quantity_5th: rdr.read_uint::<LittleEndian>(7)?,

            total_ask_quote_volume: rdr.read_uint::<LittleEndian>(7)?,

            best_ask_price_1st: rdr.read_uint::<LittleEndian>(5)?,
            best_ask_quantity_1st: rdr.read_uint::<LittleEndian>(7)?,
            best_ask_price_2nd: rdr.read_uint::<LittleEndian>(5)?,
            best_ask_quantity_2nd: rdr.read_uint::<LittleEndian>(7)?,
            best_ask_price_3rd: rdr.read_uint::<LittleEndian>(5)?,
            best_ask_quantity_3rd: rdr.read_uint::<LittleEndian>(7)?,
            best_ask_price_4th: rdr.read_uint::<LittleEndian>(5)?,
            best_ask_quantity_4th: rdr.read_uint::<LittleEndian>(7)?,
            best_ask_price_5th: rdr.read_uint::<LittleEndian>(5)?,
            best_ask_quantity_5th: rdr.read_uint::<LittleEndian>(7)?,

            no_of_best_bid_valid_quote_total: rdr.read_uint::<LittleEndian>(5)?,
            no_of_best_bid_quote_1st: rdr.read_u32::<LittleEndian>()?,
            no_of_best_bid_quote_2nd: rdr.read_u32::<LittleEndian>()?,
            no_of_best_bid_quote_3rd: rdr.read_u32::<LittleEndian>()?,
            no_of_best_bid_quote_4th: rdr.read_u32::<LittleEndian>()?,
            no_of_best_bid_quote_5th: rdr.read_u32::<LittleEndian>()?,
            no_of_best_ask_valid_quote_total: rdr.read_uint::<LittleEndian>(5)?,
            no_of_best_ask_quote_1st: rdr.read_u32::<LittleEndian>()?,
            no_of_best_ask_quote_2nd: rdr.read_u32::<LittleEndian>()?,
            no_of_best_ask_quote_3rd: rdr.read_u32::<LittleEndian>()?,
            no_of_best_ask_quote_4th: rdr.read_u32::<LittleEndian>()?,
            no_of_best_ask_quote_5th: rdr.read_u32::<LittleEndian>()?,
            quote_accept_time: rdr.read_u64::<LittleEndian>()?,
        })
    }
}

impl fmt::Display for PriceQuote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // packet time
        let packet_time_result = Utc.timestamp_opt(
            self.packet_rcv_time.as_secs() as i64,
            self.packet_rcv_time.subsec_nanos(),
        );
        let packet_time_fmt = match packet_time_result {
            chrono::LocalResult::Single(dt) => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
            _ => "Invalid time".to_string(),
        };

        // quote accept time is ascii for some reason
        let bytes = self.quote_accept_time.to_le_bytes();
        let quote_time_str = String::from_utf8_lossy(&bytes);
        let hours = &quote_time_str[0..2];
        let minutes = &quote_time_str[2..4];
        let seconds = &quote_time_str[4..6];
        let microseconds = &quote_time_str[6..8];
        let quote_time_fmt = format!("{}:{}:{}.{}", hours, minutes, seconds, microseconds).blue();
        write!(
            f,
            "{} {} {}",
            packet_time_fmt,
            quote_time_fmt,
            self.issue_code.yellow()
        )?;

        // display best bid prices and quantities
        let s = format_pairs(&[
            (self.best_bid_price_5th, self.best_bid_quantity_5th),
            (self.best_bid_price_4th, self.best_bid_quantity_4th),
            (self.best_bid_price_3rd, self.best_bid_quantity_3rd),
            (self.best_bid_price_2nd, self.best_bid_quantity_2nd),
            (self.best_bid_price_1st, self.best_bid_quantity_1st),
        ]);
        write!(f, " {}", s)?;

        // display best ask prices and quantities
        let s = format_pairs(&[
            (self.best_ask_price_1st, self.best_ask_quantity_1st),
            (self.best_ask_price_2nd, self.best_ask_quantity_2nd),
            (self.best_ask_price_3rd, self.best_ask_quantity_3rd),
            (self.best_ask_price_4th, self.best_ask_quantity_4th),
            (self.best_ask_price_5th, self.best_ask_quantity_5th),
        ]);
        write!(f, " {}", s)?;

        Ok(())
    }
}

pub fn format_pairs(pairs: &[(u64, u64)]) -> String {
    let mut result = String::new();

    for (val, qty) in pairs.iter() {
        // write!(f, " {}{}{}", qty_str, "@".red(), price_str)?;
        result.push_str(&format!(" {}{}{}", qty, "@".red(), val));
    }

    result
}
