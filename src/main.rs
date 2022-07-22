use pnet;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::Packet;
use pnet_datalink;
use pnet_datalink::NetworkInterface;
use pnet_transport::{self, icmp_packet_iter};
use rand::{self, Rng};
use std::net::ToSocketAddrs;
use std::panic;
use std::sync::Mutex;
use std::time::Duration;
use std::{
    env,
    net::{IpAddr, Ipv4Addr},
    sync::{mpsc, Arc},
    thread,
};

/// Struct for saving parsed arguments to
struct Parser {
    target_ip: Option<Ipv4Addr>,
    thread_count: Option<u8>,
    interface: Option<NetworkInterface>,
    source_ip: Option<Ipv4Addr>,
    verbose: Option<bool>,
    force_scan: Option<bool>,
    delay_in_nanos: Option<u64>,
}

impl Parser {
    /// Parses given arguments into the Config structure
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Config, &'static str> {
        let mut stored_args: Parser = Parser {
            target_ip: None,
            thread_count: Some(4),
            interface: None,
            source_ip: None,
            verbose: Some(false),
            force_scan: Some(false),
            delay_in_nanos: Some(110000),
        };
        args.next();
        loop {
            let parameter = match args.next() {
                Some(value) => value,
                None => break,
            };
            if parameter.contains("-h") || parameter.contains("--help") {
                return Err("HELP_USED");
            } else if parameter.contains("-t") || parameter.contains("--thread-count") {
                let thread_parameter = match args.next() {
                    Some(value) => value,
                    None => {
                        return Err("Please set amount of threads, for more information use --help")
                    }
                };
                stored_args.thread_count = Some(
                    if let Ok(amount) = (&thread_parameter).parse::<u8>() {
                        if amount == 0 {
                            eprintln!("There can't be 0 threads, using 1 thread instead...");
                            1
                        } else if amount > 20 {
                            eprintln!("Using more than 20 threads creates high load on the scan target, using 4 threads instead...");
                            4
                        } else {
                            amount
                        }
                    } else {
                        return Err("Error while parsing amount of threads, please specify valid number from 1 to 255 after -t parameter");
                    },
                );
            } else if parameter.contains("-i") || parameter.contains("--interface") {
                let interface_name = match args.next() {
                    Some(name) => name,
                    None => return Err("Please specify an interface"),
                };
                let interface = match pnet_datalink::interfaces()
                    .iter()
                    .filter(|iface| iface.name == interface_name)
                    .next()
                {
                    Some(iface) => iface.to_owned(),
                    None => return Err("Couldn't find interface with such name"),
                };
                // parse source ipv4 address from the given interface
                // works only with IPv4 addresses right now
                let ip: Ipv4Addr = match interface.ips.iter().find(|&entry| entry.is_ipv4()) {
                    Some(addr) => match addr.ip() {
                        IpAddr::V4(ipv4_addr) => ipv4_addr,
                        IpAddr::V6(_) => return Err("Error happened while looking for a valid Ipv4 address in the given interface")
                    }   ,
                    None => return Err("No valid IPv4 addresses found for the given interface"),
                };
                stored_args.source_ip = Some(ip);
                stored_args.interface = Some(interface);
            } else if parameter.contains("-v") || parameter.contains("--verbose") {
                stored_args.verbose = Some(true);
            } else if parameter.contains("--force-scan") {
                stored_args.force_scan = Some(true);
            } else if parameter.contains("--delay") {
                let delay_in_nanos = match args.next() {
                    Some(delay) => delay,
                    None => return Err("Please specify a delay between each packet")
                };
                let delay_in_nanos: u64 = match delay_in_nanos.parse() {
                    Ok(value) => value,
                    Err(_) => return Err("Unable to parse delay. Are you sure that you provided a valid non-negative number?")
                };
                stored_args.delay_in_nanos = Some(delay_in_nanos);
            } else if let Ok(addr) = (&parameter).parse::<Ipv4Addr>() {
                stored_args.target_ip = Some(addr);
            } else {
                let target_ip = match dns_lookup(&parameter) {
                    Ok(addr) => {
                        println!("DNS lookup results: {} is at {}", parameter, &addr);
                        addr
                    }
                    Err(e) => {
                        match e {
                            "LOOKUP_FAILED" => {
                                return Err("DNS lookup for the given hostname failed")
                            }
                            "IPV6_ONLY" => {
                                return Err("Only IPv6 address was found for the given hostname")
                            }
                            "NO_ADDRS_FOUND" => {
                                return Err("No addresses were found for the given hostname")
                            }
                            &_ => return Err("Unexpected error happened during DNS lookup"),
                        };
                    }
                };
                stored_args.target_ip = Some(target_ip);
            }
        }
        if stored_args.target_ip.is_none() || stored_args.interface.is_none() {
            return Err("Not enough arguments, for more information use --help");
        } else {
            let source_port = rand::thread_rng().gen_range(10000..=65535);
            Ok(Config {
                target_ip: stored_args.target_ip.unwrap(),
                thread_count: stored_args.thread_count.unwrap(),
                interface: stored_args.interface.unwrap(),
                source_ip: stored_args.source_ip.unwrap(),
                source_port,
                verbose: stored_args.verbose.unwrap(),
                force_scan: stored_args.force_scan.unwrap(),
                delay_in_nanos: stored_args.delay_in_nanos.unwrap(),
            })
        }
    }
}

/// Strcture for holding all the needed options/parameters
struct Config {
    target_ip: Ipv4Addr,
    thread_count: u8,
    interface: NetworkInterface,
    source_ip: Ipv4Addr,
    source_port: u16,
    verbose: bool,
    force_scan: bool,
    delay_in_nanos: u64,
}

/// Creates tcp packet with the SYN flag and given options
fn create_tcp_packet(
    buff: &mut [u8],
    source_port: u16,
    destination_port: u16,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> MutableTcpPacket {
    let mut packet = MutableTcpPacket::new(buff).unwrap();
    packet.set_flags(pnet::packet::tcp::TcpFlags::SYN);
    packet.set_source(source_port);
    packet.set_destination(destination_port);
    packet.set_window(1024);
    packet.set_data_offset(6);
    packet.set_sequence(rand::random::<u32>());
    packet.set_options(&[pnet::packet::tcp::TcpOption::mss(1460)]);
    packet.set_checksum(pnet::packet::tcp::ipv4_checksum(
        &packet.to_immutable(),
        &source_ip,
        &target_ip,
    ));
    packet
}

/// Sends packets to the given address from the given port
fn send_syn_packets(config: Arc<Config>, start_port: u16) -> Result<(), std::io::Error> {
    let channel_type = pnet_transport::TransportChannelType::Layer4(
        pnet_transport::TransportProtocol::Ipv4(pnet::packet::ip::IpNextHeaderProtocols::Tcp),
    );
    let (mut tx, _) = match pnet_transport::transport_channel(4096, channel_type) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(e),
    };
    let mut destination_port = start_port;
    let source_port: u16 = config.source_port;
    let source_ip = config.source_ip;
    let target_ip = config.target_ip;
    let thread_count = config.thread_count;
    let delay = config.delay_in_nanos;
    loop {
        let mut buff: [u8; 24] = [0; 24];
        let packet = create_tcp_packet(
            &mut buff,
            source_port,
            destination_port,
            source_ip,
            target_ip,
        );
        match tx.send_to(packet, IpAddr::V4(target_ip)) {
            Ok(_) => (),
            Err(e) => return Err(e),
        };
        if 65535 - destination_port < thread_count as u16 {
            break;
        };
        destination_port += thread_count as u16;
        thread::sleep(Duration::from_nanos(delay * thread_count as u64));
    }
    Ok(())
}

/// Checks all incoming packets and finds one's that are related to the scan
fn handle_scan_responses(
    tx: mpsc::Sender<u16>,
    config: Arc<Config>,
    is_finished: Arc<Mutex<bool>>,
) {
    let iface = &config.interface;
    let (_, mut receiver) = match pnet_datalink::channel(iface, Default::default()) {
        Ok(pnet_datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Wrong channel type"),
        Err(e) => panic!("Error while creating a channel on given interface: {}", e),
    };
    let source_port = config.source_port;
    let target_ip = config.target_ip;
    loop {
        if *is_finished.lock().unwrap() {
            break;
        }
        let buf = receiver.next().unwrap();
        let ethernet = pnet::packet::ethernet::EthernetPacket::new(&buf).unwrap();
        let ipv4 = pnet::packet::ipv4::Ipv4Packet::new(ethernet.payload()).unwrap();
        if ipv4.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Tcp {
            let tcp = pnet::packet::tcp::TcpPacket::new(ipv4.payload()).unwrap();
            if !(tcp.get_destination() == source_port && ipv4.get_source() == target_ip) {
                continue;
            } else {
                if tcp.get_flags()
                    == pnet::packet::tcp::TcpFlags::SYN + pnet::packet::tcp::TcpFlags::ACK
                {
                    let open_port = tcp.get_source();
                    if config.verbose {
                        println!("Discovered open port: {}/tcp", &open_port);
                    };
                    match tx.send(open_port) {
                        Ok(_) => (),
                        Err(e) => panic!("Error while writing to the Sender channel: {e}"),
                    };
                };
            };
        };
    }
}

/// Fills the given packet with the given info and sets checksum
fn populate_icmp_packet(
    icmp_packet: &mut MutableEchoRequestPacket,
    payload: &[u8],
    identifier: u16,
    sequence_number: u16,
) {
    icmp_packet.set_icmp_type(pnet::packet::icmp::IcmpTypes::EchoRequest);
    icmp_packet.set_icmp_code(pnet::packet::icmp::echo_request::IcmpCodes::NoCode);
    icmp_packet.set_payload(&payload);
    icmp_packet.set_sequence_number(sequence_number);
    icmp_packet.set_identifier(identifier);
    icmp_packet.set_checksum(pnet::packet::icmp::checksum(
        &pnet::packet::icmp::IcmpPacket::new(icmp_packet.packet()).unwrap(),
    ));
}

/// Sends ICMP packet to the given address and waits for the response
fn ping_target(target_ip: Ipv4Addr) -> Result<bool, std::io::Error> {
    let channel_type = pnet_transport::TransportChannelType::Layer4(
        pnet_transport::TransportProtocol::Ipv4(pnet::packet::ip::IpNextHeaderProtocols::Icmp),
    );
    let (mut tx, mut rx) = match pnet_transport::transport_channel(4096, channel_type) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(e),
    };
    let identifier: u16 = rand::thread_rng().gen_range(10000..65535);
    let sequence_number: u16 = rand::thread_rng().gen_range(10000..65535);
    let payload: Vec<u8> = vec![0; 56];
    let mut buff: Vec<u8> =
        vec![0; MutableEchoRequestPacket::minimum_packet_size() + payload.len()];
    let mut icmp_packet = MutableEchoRequestPacket::new(&mut buff).unwrap();
    populate_icmp_packet(&mut icmp_packet, &payload, identifier, sequence_number);
    match tx.send_to(icmp_packet, IpAddr::V4(target_ip)) {
        Ok(_) => (),
        Err(e) => return Err(e),
    };
    let mut packet_iter = icmp_packet_iter(&mut rx);
    loop {
        match packet_iter.next_with_timeout(Duration::from_secs(1)) {
            Ok(possible_response) => match possible_response {
                Some(packet_addr_pair) => {
                    if packet_addr_pair.0.get_icmp_type()
                        == pnet::packet::icmp::IcmpTypes::EchoReply
                        && packet_addr_pair.1 == IpAddr::V4(target_ip)
                    {
                        let echo_reply_packet =
                            pnet::packet::icmp::echo_reply::EchoReplyPacket::new(
                                packet_addr_pair.0.packet(),
                            )
                            .unwrap();
                        if echo_reply_packet.get_identifier() == identifier
                            && echo_reply_packet.get_sequence_number() == sequence_number
                        {
                            return Ok(true);
                        }
                    }
                }
                None => return Ok(false),
            },
            Err(_) => (),
        }
    }
}

/// Displays scan results
fn print_results(open_ports: &[u16]) {
    println!(
        "Stats: {} filtered/closed port(s) (RST or no response), {} open port(s)",
        65535 - open_ports.len(),
        open_ports.len()
    );
    println!("PORT\tSTATUS");
    for port in open_ports {
        println!("{port}\tOpen");
    }
}

/// Displays --help message
fn print_help_message() {
    println!(
        "Usage:
\tport-scanner [OPTIONS] [ADDRESS]\n
positional arguments:
\taddress\t\t\t\tTarget IPv4 address/Hostname\n
required options
\t-i,--interface <interface>\tNetwork interface on which to scan\n
optional arguments
\t-h,--help\t\t\tShow this message and exit
\t-t,--thread-count <amount>\tAmount of threads (from 1 to 20). Default is 4
\t-v,--verbose\t\t\tVerbose mode
\t--force-scan\t\t\tDo not ping the host before scan
\t--delay <delay>\t\t\tDelay in nanoseconds between sending packets in each thread. Default is 110000 nanoseconds"
    );
}

/// Makes a DNS lookup if user provided hostname instead of the valid IPv4 address
pub fn dns_lookup(hostname: &str) -> Result<Ipv4Addr, &'static str> {
    let mut lookup_results = match format!("{hostname}:8000").to_socket_addrs() {
        Ok(iter) => iter,
        Err(_) => return Err("LOOKUP_FAILED"),
    };
    let addr = match lookup_results.next() {
        Some(sock_addr) => match sock_addr.ip() {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => return Err("IPV6_ONLY"),
        },
        None => return Err("NO_ADDRS_FOUND"),
    };
    Ok(addr)
}

fn main() {
    let config: Arc<Config> = Arc::new(Parser::parse(env::args()).unwrap_or_else(|err| {
        if err.contains("HELP_USED") {
            print_help_message();
            std::process::exit(0);
        } else {
            println!("Error occured while parsing arguments: {}", err);
            std::process::exit(1);
        };
    }));
    if !config.force_scan {
        let ping_result = match ping_target(config.target_ip) {
            Ok(result) => result,
            Err(e) => {
                println!("Error while trying to ping the given address: {}", e);
                std::process::exit(1);
            }
        };
        if !ping_result {
            println!("Host seems down or it can be blocking pings. If you still want to scan for open ports even if the host seems to be down - use --force-scan flag");
            std::process::exit(0);
        } else {
            println!("Host is up, starting scan...");
        };
    };
    println!(
        "Scanning {} using SYN scan:\n *Interface: {}\n *Threads: {}\n *Port: {}\n---",
        &config.target_ip, &config.interface.name, &config.thread_count, &config.source_port
    );
    let conf_copy = Arc::clone(&config);
    let (tx, rx) = mpsc::channel::<u16>();
    let scan_finished = Arc::new(Mutex::new(false));
    let scan_finished_copy = Arc::clone(&scan_finished);
    let response_handler =
        thread::spawn(move || handle_scan_responses(tx, conf_copy, scan_finished_copy));
    let mut handles = vec![];
    for n in 1..=config.thread_count {
        let conf = Arc::clone(&config);
        let handle = thread::spawn(move || send_syn_packets(conf, n as u16));
        handles.push(handle);
    }
    for handle in handles {
        match handle.join() {
            Ok(result) => match result {
                Ok(_) => (),
                Err(e) => {
                    println!("Error in thread:\t{}: {}", e.kind(), e.to_string());
                    if e.to_string().contains("No buffer space") {
                        println!("Please, check the --help page and try setting a higher delay between packets")
                    };
                    std::process::exit(1);
                }
            },
            Err(_) => {
                println!("Thread panicked, exiting...");
                std::process::exit(1);
            }
        };
    }
    thread::sleep(Duration::from_millis(
        1000 + 100 * config.thread_count as u64,
    ));
    *scan_finished.lock().unwrap() = true;
    response_handler.join().unwrap();
    let mut open_ports = rx.iter().collect::<Vec<u16>>();
    open_ports.sort();
    print_results(&open_ports);
}
