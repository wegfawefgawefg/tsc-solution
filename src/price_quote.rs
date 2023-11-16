use std::fmt;
use std::io::Error as IOError;
use std::io::{Cursor, Read};
use std::time::Duration;

use byteorder::{BigEndian, ReadBytesExt};
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

impl PriceQuote {
    pub fn from_bytes(rcv_time: Duration, bytes: &[u8]) -> Result<Self, IOError> {
        let mut rdr = Cursor::new(bytes);

        Ok(PriceQuote {
            packet_rcv_time: rcv_time,
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

impl fmt::Display for PriceQuote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format packet receive time as a human-readable string
        let packet_time_secs = self.packet_rcv_time.as_secs();
        let packet_time_nano = self.packet_rcv_time.subsec_nanos();
        let packet_time_fmt = format!(
            "{:02}:{:02}:{:02}.{:09}",
            packet_time_secs / 3600,
            (packet_time_secs / 60) % 60,
            packet_time_secs % 60,
            packet_time_nano
        )
        .green();

        // Extracting time components from quote_accept_time using bit shifting
        let hours = (self.quote_accept_time >> 48) & 0xFFFF; // Extract hours (16 bits)
        let minutes = (self.quote_accept_time >> 32) & 0xFFFF; // Extract minutes (16 bits)
        let seconds = (self.quote_accept_time >> 16) & 0xFFFF; // Extract seconds (16 bits)
        let microseconds = self.quote_accept_time & 0xFFFF; // Extract microseconds (16 bits)

        // Formatting quote_accept_time
        let quote_time_fmt = format!(
            "{:02}:{:02}:{:02}.{:05}",
            hours, minutes, seconds, microseconds
        )
        .blue();

        write!(
            f,
            "{} {} {}",
            packet_time_fmt,
            quote_time_fmt,
            self.issue_code.yellow()
        )?;

        // Display best bid prices and quantities
        for (price, qty) in [
            (self.best_bid_price_5th, self.best_bid_quantity_5th),
            (self.best_bid_price_4th, self.best_bid_quantity_4th),
            (self.best_bid_price_3rd, self.best_bid_quantity_3rd),
            (self.best_bid_price_2nd, self.best_bid_quantity_2nd),
            (self.best_bid_price_1st, self.best_bid_quantity_1st),
        ]
        .iter()
        {
            write!(f, " {}{}{}", qty, "@".red(), price)?;
        }

        // Display best ask prices and quantities
        for (price, qty) in [
            (self.best_ask_price_5th, self.best_ask_quantity_5th),
            (self.best_ask_price_4th, self.best_ask_quantity_4th),
            (self.best_ask_price_3rd, self.best_ask_quantity_3rd),
            (self.best_ask_price_2nd, self.best_ask_quantity_2nd),
            (self.best_ask_price_1st, self.best_ask_quantity_1st),
        ]
        .iter()
        {
            write!(f, " {}{}{}", qty, "@".red(), price)?;
        }

        Ok(())
    }
}
