mod capturer;
mod packet;
mod runner;

use eyre::{Context, Report};
use getopts::Options;
use packet::OrigPacket;
#[cfg(not(windows))]
use runner::unix::run_on_unix;
#[cfg(windows)]
use runner::windows::run_on_windows;
use runner::Source;
use std::env;
use std::str;

#[derive(Clone)]
pub struct Opts {
    pub source: Source,
    pub timestamp: bool,
}

impl Opts {
    fn print_header(self: &Opts) {
        if self.timestamp {
            println!(
                "{:14} {:5} {:30} {:20} {:9} {}",
                "timestamp", "query", "name", "server IP", "elapsed", "response"
            );
        } else {
            println!(
                "{:5} {:30} {:20} {}",
                "query", "name", "server IP", "response"
            );
        }
    }
    fn print_response(self: &Opts, packet: &OrigPacket, elapsed_time: &str, response: &str) {
        if self.timestamp {
            println!(
                "{:14} {:5} {:30} {:20} {:9} {}",
                packet.timestamp.format("%H:%M:%S%.3f"),
                packet.typ,
                packet.qname,
                packet.server_ip,
                elapsed_time,
                response
            );
        } else {
            println!(
                "{:5} {:30} {:20} {}",
                packet.typ, packet.qname, packet.server_ip, response
            );
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Report> {
    let opts = parse_args()?;
    opts.print_header();

    #[cfg(not(windows))]
    run_on_unix(opts).await?;

    #[cfg(windows)]
    run_on_windows(opts)?;

    Ok(())
}

fn parse_args() -> Result<Opts, Report> {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("p", "port", "port number to listen on", "PORT");
    opts.optopt("f", "file", "read packets from pcap file", "FILENAME");
    opts.optflag(
        "t",
        "timestamp",
        "print timestamp and elapsed time for each query",
    );
    opts.optopt("i", "interface", "interface's ID", "INTERFACE_ID");
    opts.optflag("l", "list", "list all interfaces");
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

    if matches.opt_present("l") {
        list_all_interface()?;
        std::process::exit(0);
    }

    let mut opts = Opts {
        source: Source::Port(53),
        timestamp: matches.opt_present("t"),
    };

    if let Some(interface_id) = matches.opt_str("i") {
        let interface = pcap::Device::list()?
            .iter()
            .filter(|x| x.name.contains(&interface_id))
            .nth(0)
            .map(|d| d.to_owned());

        match interface {
            Some(interface) => {
                opts.source = Source::Interface(interface);
            }
            None => {
                eprintln!("Cannot find an interface with the id `{}`", &interface_id);
                std::process::exit(1);
            }
        }
    } else if let Some(filename) = matches.opt_str("f") {
        opts.source = Source::Filename(filename.to_string());
    } else if let Some(port_str) = matches.opt_str("p") {
        match port_str.parse() {
            Ok(port) => {
                opts.source = Source::Port(port);
            }
            Err(_) => {
                eprintln!("Invalid port number: {}", &port_str);
                std::process::exit(1);
            }
        }
    }
    Ok(opts)
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
    println!("
What the output columns mean:
   query:     DNS query type (A, CNAME, etc)
   name:      Hostname the DNS query is requesting
   server IP: IP address of the DNS server the query was made to
   elapsed:   How long the DNS response took to arrive
   response:  Responses from the Answer section of the DNS response (or \"<no response>\" if none was found).
              Multiple responses are separated by commas.
");
}

fn list_all_interface() -> Result<(), Report> {
    let empty_str = "".to_string();

    let interfaces =
        pcap::Device::list().wrap_err("Encounter error while listing interfaces on your device")?;
    println!("{:55} {}", "Interface", "Interface Description");
    interfaces.iter().for_each(|it| {
        let name = &it.name;
        let desc = it.desc.as_ref().unwrap_or(&empty_str);
        println!("{:55} {}", name, desc);
    });

    Ok(())
}
