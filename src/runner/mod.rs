use pcap::Device;

#[derive(Clone)]
pub enum Source {
    Port(u16),
    Filename(String),
    Interface(Device),
}

#[cfg(windows)]
pub mod windows;

#[cfg(not(windows))]
pub mod unix;
