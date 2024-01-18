# tsc-solution
tsc-solution

## to run
cargo run --release mdf-kospi200.20110216-0.pcap 

## notes
- B6 packet data type mentioned here. related to order books https://www.eurexchange.com/resource/blob/2128190/1c3ff499decf4bc0516e5a0e6b2c1af9/data/T7_EOBI_Manual_v.8.1.1.pdf
- A3 packet data type mentioned here. related to derivatives. many failed packets are A3 type. could be results for different requests mixed in. https://www.eurex.com/resource/blob/2683898/4f5840e413b052823a11e6628f016032/data/T7_XML_Report_Reference_Manual_v.91.3.3.pdf 
- M4 looks like a different exchange. but these are all kospi. i dont get it.