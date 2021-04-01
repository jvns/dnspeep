use bytes::Bytes;
use dns_message_parser::rr::RR;
use dns_message_parser::DecodeError;
use dns_message_parser::Dns;
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

#[derive(Clone)]
struct OrigPacket {
    qname: String,
    typ: String,
    server_ip: String,
    server_port: u16,
    has_response: bool,
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
            capture_packets(stream).await;
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
        let map_clone = self.map.clone();
        match print_packet(packet, self.linktype, &mut *map) {
            Ok(Some(id)) => {
                // This means we just got a new query we haven't seen before.
                // After 1 second, remove from the map and print '<no response>' if there was no
                // response yet
                tokio::spawn(async move {
                    delay_for(Duration::from_millis(1000)).await;
                    let mut map = map_clone.lock().unwrap();
                    if let Some(packet) = map.get(&id) {
                        if packet.has_response == false {
                            println!(
                                "{:5} {:30} {:20} <no response>",
                                packet.typ, packet.qname, packet.server_ip
                            );
                        }
                    }
                    map.remove(&id);
                });
            }
            Err(e) => {
                // Continue if there's an error, but print a warning
                eprintln!("Error parsing DNS packet: {:#}", e);
            }
            _ => {}
        }
        Ok(())
    }
}

fn print_packet(
    orig_packet: Packet,
    linktype: Linktype,
    map: &mut HashMap<u16, OrigPacket>,
) -> Result<Option<u16>> {
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
    let dns_packet = match Dns::decode(Bytes::copy_from_slice(packet.payload)) {
        Ok(dns) => dns,
        Err(DecodeError::RemainingBytes(_, dns)) => dns,
        x => x.wrap_err("Failed to parse DNS packet")?,
    };
    let id = dns_packet.id;
    // The map is a list of queries we've seen in the last 1 second
    // Decide what to do depending on whether this is a query and whether we've seen that ID
    // recently
    match (dns_packet.flags.qr == false, map.contains_key(&id)) {
        (true, false) => {
            // It's a new query, track it
            let question = &dns_packet.questions[0];
            map.insert(
                id,
                OrigPacket {
                    typ: format!("{:?}", question.q_type),
                    qname: question.domain_name.to_string(),
                    server_ip: format!("{}", dest_ip),
                    server_port: udp_header.destination_port,
                    has_response: false,
                },
            );
            Ok(Some(id))
        }
        (true, true) => {
            // A query we've seen before is a retry, ignore it
            Ok(None)
        }
        (false, false) => {
            // A response we haven't seen the query for
            eprintln!("Warning: got response for unknown query ID {}", id);
            Ok(None)
        }
        (false, true) => {
            map.entry(id).and_modify(|e| e.has_response = true);
            // It's a response for a query we remember, so format it and print it out
            let orig_packet = map.get(&id).unwrap();
            let response = if !dns_packet.answers.is_empty() {
                format_answers(dns_packet.answers)
            } else {
                dns_packet.flags.rcode.to_string().to_uppercase()
            };
            println!(
                "{:5} {:30} {:20} {}",
                format!("{}", &orig_packet.typ),
                &orig_packet.qname,
                src_ip,
                response
            );
            Ok(None)
        }
    }
}

fn format_answers(records: Vec<RR>) -> String {
    let formatted: Vec<String> = records.iter().map(|x| format_record(&x)).collect();
    formatted.join(", ")
}

fn format_record(rdata: &RR) -> String {
    match rdata {
        RR::A(x) => format!("A: {}", x.ipv4_addr),
        RR::AAAA(x) => format!("AAAA: {}", x.ipv6_addr),
        RR::CNAME(x) => format!("CNAME: {}", x.c_name),
        RR::PTR(x) => format!("PTR: {}", x.ptr_d_name),
        RR::MX(x) => format!("MX: {} {}", x.preference, x.exchange),
        RR::NS(x) => format!("NS: {}", x.ns_d_name),
        RR::SOA(x) => format!("SOA:{}...", x.m_name),
        RR::SRV(x) => format!("SRV: {} {} {} {}", x.priority, x.weight, x.port, x.target),
        RR::URI(x) => format!("URI: {} {} {}", x.priority, x.weight, x.uri),
        RR::HINFO(x) => format!("URI: {} {}", x.cpu, x.os),
        RR::TXT(x) => format!("TXT: {}", x.string),
        _ => panic!("I don't recognize that query type, {:?}", rdata),
    }
}
