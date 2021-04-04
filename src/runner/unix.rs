use super::super::capturer::{capture_device, capture_file};
#[cfg(not(windows))]
use super::super::capturer::{capture_packets, capture_stream};
#[cfg(not(windows))]
use pcap::stream::{PacketCodec, PacketStream};
#[cfg(not(windows))]
use pcap::Active;
#[cfg(not(windows))]
use super::super::packet::Opts;

#[cfg(not(windows))]
pub async fn run_on_unix(opts: Opts) -> Result<()> {
    let source = opts.source;
    
    match source {
        Source::Device(device) => capture_device(device),
        Source::Port(port) => {
            let map = Arc::new(Mutex::new(HashMap::new()));
            let stream = capture_stream(map.clone(), port)?;
            capture_packets(stream).await;
        }
        Source::Filename(filename) => {
            capture_file(&filename)?;
        }
    };
    Ok(())
}