use dns_parser::rdata;
use dns_parser::Packet as DNSPacket;
use dns_parser::{RData, ResourceRecord, ResponseCode};
use etherparse::IpHeader;
use etherparse::PacketHeaders;
use eyre::{Result, WrapErr};
use futures::StreamExt;
use getopts::Options;
use pcap::stream::{PacketCodec, PacketStream};
use pcap::{Active, Capture, Linktype, Packet};
use std::collections::HashMap;
use std::env;
use std::net::IpAddr;
use std::str;
use std::sync::{Arc, Mutex};
use tokio::time::{delay_for, Duration};

struct OrigPacket {
    qname: String,
    typ: String,
    server_ip: String,
    server_port: u16,
    report: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let map = Arc::new(Mutex::new(HashMap::new()));
    let source = parse_args()?.source;

    println!(
        "{:5} {:30} {:20} {}",
        "query", "name", "server IP", "response"
    );
    match source {
        Source::Port(port) => {
            let stream = capture_stream(map.clone(), port)?;
            tokio::join!(capture_packets(stream), track_no_responses(map));
        }
        Source::Filename(filename) => {
            capture_file(&filename)?;
        }
    };
    Ok(())
}

struct Opts {
    source: Source,
}

fn parse_args() -> Result<Opts> {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("p", "port", "port number to listen on", "PORT");
    opts.optopt("f", "file", "read packets from pcap file", "FILENAME");
    opts.optflag("h", "help", "print this help menu");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            panic!(f.to_string())
        }
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        std::process::exit(0);
    }
    let port_str = matches.opt_str("p").unwrap_or("53".to_string());
    if let Some(filename) = matches.opt_str("f") {
        Ok(Opts {
            source: Source::Filename(filename.to_string()),
        })
    } else if let Ok(port) = port_str.parse() {
        Ok(Opts {
            source: Source::Port(port),
        })
    } else {
        eprintln!("Invalid port number: {}", &port_str);
        std::process::exit(1);
    }
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
    println!("
What the output columns mean:
   query:     DNS query type (A, CNAME, etc)
   name:      Hostname the DNS query is requesting
   server IP: IP address of the DNS server the query was made to
   response:  Responses from the Answer section of the DNS response (or \"<no response>\" if none was found).
              Multiple responses are separated by commas.
");
}

enum Source {
    Port(u16),
    Filename(String),
}

fn capture_file(filename: &str) -> Result<()> {
    let mut map = HashMap::new();
    let mut cap = Capture::from_file(filename).wrap_err("Failed to start capture from file")?;
    let linktype = cap.get_datalink();
    while let Ok(packet) = cap.next() {
        if let Err(e) = print_packet(packet, linktype, &mut map) {
            // Continue if there's an error, but print a warning
            eprintln!("Error parsing DNS packet: {:#}", e);
        }
    }
    Ok(())
}

fn capture_stream(
    map: Arc<Mutex<HashMap<u16, OrigPacket>>>,
    port: u16,
) -> Result<PacketStream<Active, PrintCodec>> {
    let mut cap = Capture::from_device("any")
        .wrap_err("Failed to find device 'any'")?
        .immediate_mode(true)
        .open()
        .wrap_err("Failed to start. This may be because you need to run this as root.")?
        .setnonblock()
        .wrap_err("Failed to set nonblocking")?;
    let linktype = cap.get_datalink();
    cap.filter(format!("udp and port {}", port).as_str(), true)
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
        Linktype::LINUX_SLL2 => &orig_packet.data[20..],
        Linktype::IPV4 => &orig_packet.data,
        Linktype::IPV6 => &orig_packet.data,
        Linktype::NULL => &orig_packet.data[4..],
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
    let udp_header = packet
        .transport
        .expect("Error: Expected transport header")
        .udp()
        .expect("Error: Expected UDP packet");
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
                server_port: udp_header.destination_port,
                report: false,
            },
        );
        return Ok(());
    }
    let orig_packet = map.get(&id).unwrap(); // this unwrap() is ok because we know it's in the map
    if (format!("{}", src_ip).as_str(), udp_header.source_port)
        != (orig_packet.server_ip.as_str(), orig_packet.server_port)
    {
        // This packet isn't a response to the original packet, so we ignore it -- it's just a retry
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
            ResponseCode::ServerFailure => "SERVFAIL".to_string(),
            ResponseCode::NameError => "NXDOMAIN".to_string(),
            ResponseCode::Refused => "REFUSED".to_string(),
            // todo: not sure of the "right" way to represent formaterror / not implemented
            ResponseCode::FormatError => "FORMATERROR".to_string(),
            ResponseCode::NotImplemented => "NOTIMPLEMENTED".to_string(),
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
