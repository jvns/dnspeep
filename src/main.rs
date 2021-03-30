use dns_parser::rdata;
use dns_parser::Packet as DNSPacket;
use dns_parser::{RData, ResourceRecord, ResponseCode};
use etherparse::IpHeader;
use etherparse::PacketHeaders;
use eyre::{Result, WrapErr};
use futures::StreamExt;
use pcap::stream::{PacketCodec, PacketStream};
use pcap::{Active, Capture, Linktype, Packet};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str;
use std::sync::{Arc, Mutex};
use tokio::time::{delay_for, Duration};

struct OrigPacket {
    qname: String,
    typ: String,
    server_ip: String,
    report: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let map = Arc::new(Mutex::new(HashMap::new()));

    let stream = capture_stream(map.clone())?;
    println!(
        "{:5} {:30} {:20} {}",
        "query", "name", "server IP", "response"
    );
    tokio::join!(capture_packets(stream), track_no_responses(map));
    Ok(())
}

fn capture_stream(
    map: Arc<Mutex<HashMap<u16, OrigPacket>>>,
) -> Result<PacketStream<Active, PrintCodec>> {
    let mut cap = Capture::from_device("any")
        .wrap_err("Failed to find device 'any'")?
        .immediate_mode(true)
        .open()
        .wrap_err("Failed to start. You need to run this as root.")?
        .setnonblock()
        .wrap_err("Failed to set nonblocking")?;
    let linktype = cap.get_datalink();
    cap.filter("udp and port 53", true)
        .wrap_err("Failed to create BPF filter")?;
    cap.stream(PrintCodec { map, linktype })
        .wrap_err("Failed to create stream")
}

async fn capture_packets(mut stream: PacketStream<Active, PrintCodec>) {
    while stream.next().await.is_some() {}
}

pub struct PrintCodec {
    map: Arc<Mutex<HashMap<u16, OrigPacket>>>,
    linktype: Linktype,
}

impl PacketCodec for PrintCodec {
    type Type = ();

    fn decode(&mut self, packet: Packet) -> Result<(), pcap::Error> {
        let mut map = self.map.lock().unwrap();
        if let Err(e) = print_packet(packet, self.linktype, &mut *map) {
            // Continue if there's an error, but print a warning
            eprintln!("Error parsing DNS packet: {:#}", e);
        }
        Ok(())
    }
}

fn print_packet(
    orig_packet: Packet,
    linktype: Linktype,
    map: &mut HashMap<u16, OrigPacket>,
) -> Result<()> {
    // Strip the ethernet header
    let packet_data = match linktype {
        Linktype::ETHERNET => &orig_packet.data[14..],
        Linktype::LINUX_SLL => &orig_packet.data[16..],
        Linktype::IPV4 => &orig_packet.data,
        Linktype::IPV6 => &orig_packet.data,
        Linktype(12) => &orig_packet.data,
        Linktype(14) => &orig_packet.data,
        _ => panic!("unknown link type {:?}", linktype),
    };
    // Parse the IP header and UDP header
    let packet =
        PacketHeaders::from_ip_slice(packet_data).wrap_err("Failed to parse Ethernet packet")?;
    let (src_ip, dest_ip): (IpAddr, IpAddr) =
        match packet.ip.expect("Error: failed to parse IP address") {
            IpHeader::Version4(x) => (x.source.into(), x.destination.into()),
            IpHeader::Version6(x) => (x.source.into(), x.destination.into()),
        };
    // Parse DNS data
    let dns_packet = DNSPacket::parse(packet.payload).wrap_err("Failed to parse DNS packet")?;
    let question = &dns_packet.questions[0];
    let id = dns_packet.header.id;
    // This map is a list of requests that haven't gotten a response yet
    if !map.contains_key(&id) {
        map.insert(
            id,
            OrigPacket {
                typ: format!("{:?}", question.qtype),
                qname: question.qname.to_string(),
                server_ip: format!("{}", dest_ip),
                report: false,
            },
        );
        return Ok(());
    }
    // If it's the second time we're seeing it, it's a response, so remove it from the map
    map.remove(&id);
    // Format the response data
    let response = if !dns_packet.answers.is_empty() {
        format_answers(dns_packet.answers)
    } else {
        match dns_packet.header.response_code {
            ResponseCode::NoError => "NOERROR".to_string(),
            ResponseCode::FormatError => "FORMATERROR".to_string(),
            ResponseCode::ServerFailure => "SERVFAIL".to_string(),
            ResponseCode::NameError => "NXDOMAIN".to_string(),
            ResponseCode::NotImplemented => "NOTIMPLEMENTED".to_string(),
            ResponseCode::Refused => "REFUSED".to_string(),
            _ => "RESERVED".to_string(),
        }
    };
    println!(
        "{:5} {:30} {:20} {}",
        format!("{:?}", question.qtype),
        question.qname.to_string(),
        src_ip,
        response
    );
    Ok(())
}

fn format_answers(records: Vec<ResourceRecord>) -> String {
    let formatted: Vec<String> = records.iter().map(|x| format_record(&x.data)).collect();
    formatted.join(", ")
}

fn format_record(rdata: &RData) -> String {
    match rdata {
        RData::A(rdata::a::Record(addr)) => format!("A: {}", addr),
        RData::AAAA(rdata::aaaa::Record(addr)) => format!("AAAA: {}", addr),
        RData::CNAME(rdata::cname::Record(name)) => format!("CNAME: {}", name),
        RData::PTR(rdata::ptr::Record(name)) => format!("PTR: {}", name),
        RData::MX(rdata::mx::Record {
            preference,
            exchange,
        }) => format!("MX: {} {}", preference, exchange),
        RData::NS(rdata::ns::Record(name)) => format!("NS: {}", name),
        RData::SOA(x) => format!("SOA:{}...", x.primary_ns),
        RData::SRV(rdata::srv::Record {
            priority,
            weight,
            port,
            target,
        }) => format!("SRV: {} {} {} {}", priority, weight, port, target),
        RData::TXT(x) => {
            let parts: Vec<String> = x
                .iter()
                .map(|bytes| str::from_utf8(bytes).unwrap().to_string())
                .collect();
            format!("TXT: {}", parts.join(" "))
        }
        _ => panic!("I don't recognize that query type, {:?}", rdata),
    }
}

async fn track_no_responses(map: Arc<Mutex<HashMap<u16, OrigPacket>>>) {
    //if we don't see a response to a query within 1 second, print "<no response>"
    loop {
        delay_for(Duration::from_millis(1000)).await;
        let map = &mut *map.lock().unwrap();
        map.retain(|_, packet| {
            if packet.report {
                println!(
                    "{:5} {:30} {:20} <no response>",
                    packet.typ, packet.qname, packet.server_ip
                );
            }
            !packet.report
        });
        for (_, packet) in map.iter_mut() {
            (*packet).report = true
        }
    }
}
