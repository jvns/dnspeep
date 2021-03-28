use dns_parser::Packet as DNSPacket;
use dns_parser::ResponseCode;
use etherparse::IpHeader;
use etherparse::PacketHeaders;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tokio::time::{delay_for, Duration};

use futures::StreamExt;
use pcap::stream::PacketCodec;
use pcap::{Capture, Error, Linktype, Packet};

struct OrigPacket {
    qname: String,
    typ: String,
    server_ip: String,
    report: bool,
}

#[tokio::main]
async fn main() {
    let map = Arc::new(Mutex::new(HashMap::new()));
    tokio::join!(capture_packets(map.clone()), track_no_responses(map));
}

async fn capture_packets(map: Arc<Mutex<HashMap<u16, OrigPacket>>>) {
    let mut cap = Capture::from_device("any")
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap()
        .setnonblock()
        .unwrap();
    let linktype = cap.get_datalink();
    cap.filter("udp and port 53").unwrap();
    let mut stream = cap.stream(PrintCodec { map, linktype }).unwrap();
    while stream.next().await.is_some() {}
}

pub struct PrintCodec {
    map: Arc<Mutex<HashMap<u16, OrigPacket>>>,
    linktype: Linktype,
}

impl PacketCodec for PrintCodec {
    type Type = ();

    fn decode(&mut self, packet: Packet) -> Result<(), Error> {
        let mut map = self.map.lock().unwrap();
        print(packet, self.linktype, &mut *map);
        Ok(())
    }
}

fn print(orig_packet: Packet, linktype: Linktype, map: &mut HashMap<u16, OrigPacket>) {
    // Strip the ethernet header
    let packet_data = match linktype {
        Linktype::ETHERNET => &orig_packet.data[14..],
        Linktype::LINUX_SLL => &orig_packet.data[16..],
        Linktype::IPV4 => &orig_packet.data,
        Linktype::IPV6 => &orig_packet.data,
        _ => panic!("unknown link type {:?}", linktype),
    };
    // Parse the IP header and UDP header
    let packet = PacketHeaders::from_ip_slice(packet_data).unwrap();
    let (src_ip, dest_ip): (IpAddr, IpAddr) = match packet.ip.unwrap() {
        IpHeader::Version4(x) => (x.source.into(), x.destination.into()),
        IpHeader::Version6(x) => (x.source.into(), x.destination.into()),
    };
    // Parse DNS data
    let dns_packet = DNSPacket::parse(packet.payload).unwrap();
    let question = &dns_packet.questions[0];
    let id = dns_packet.header.id;
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
        return;
    }
    map.remove(&id);
    let response = if !dns_packet.answers.is_empty() {
        let answer = &dns_packet.answers[0];
        format!("{:?}", answer.data)
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
