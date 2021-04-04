use super::packet::print_packet;
#[cfg(not(windows))]
use super::packet::OrigPacket;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use super::packet::PrintCodec;
use super::Opts;
use eyre::{Report, Result, WrapErr};
#[cfg(not(windows))]
use futures::StreamExt;
use pcap::{Capture, Device};

#[cfg(not(windows))]
use pcap::stream::{PacketCodec, PacketStream};
#[cfg(not(windows))]
use pcap::Active;

#[cfg(not(windows))]
pub fn capture_stream(
    opts: Opts,
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
    cap.stream(PrintCodec {
        map,
        linktype,
        opts,
    })
    .wrap_err("Failed to create stream")
}

#[cfg(not(windows))]
pub async fn capture_packets(mut stream: PacketStream<Active, PrintCodec>) {
    while stream.next().await.is_some() {}
}

pub fn capture_file(filename: &str, opts: Opts) -> Result<(), Report> {
    let mut map = HashMap::new();
    let mut cap = Capture::from_file(filename).wrap_err("Failed to start capture from file")?;
    let linktype = cap.get_datalink();
    while let Ok(packet) = cap.next() {
        if let Err(e) = print_packet(&opts, packet, linktype, &mut map) {
            // Continue if there's an error, but print a warning
            eprintln!("Error parsing DNS packet: {:#}", e);
        }
    }
    Ok(())
}

pub fn capture_interface(interface: Device, opts: Opts) -> Result<(), Report> {
    let mut cap = pcap::Capture::from_device(interface)
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();
    cap.filter(format!("udp and port {}", 53).as_str(), true)
        .expect("Failed to create BPF filter");

    let map = Arc::new(Mutex::new(HashMap::new()));

    #[cfg(not(windows))]
    let mut decoder = PrintCodec {
        map,
        linktype: cap.get_datalink(),
        opts,
    };

    #[cfg(windows)]
    let decoder = PrintCodec {
        map,
        linktype: cap.get_datalink(),
        opts,
    };

    while let Ok(packet) = cap.next() {
        decoder
            .decode(packet)
            .wrap_err("Encounter error while capturing packets from interface")?
    }

    Ok(())
}
