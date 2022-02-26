extern crate dns_parser;
extern crate httparse;

use std::collections;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::sync;
use std::thread::{sleep, spawn, JoinHandle};
use std::time::Duration;

mod interfaces;

///
/// start an mDNS scanner thread
///
/// Setup a socket and send a question to the mDNS multicast address
/// requesting a unicast reply. The replies are gathered in a separate
/// thread and sent to a logging channel.
fn scan_mdns(
    local_ips: &[interfaces::InetAddr],
    channel: sync::mpsc::Sender<String>,
) -> std::io::Result<JoinHandle<()>> {
    //
    // Setup source/destination socket addresses
    //
    let mdns_v4_socket_addr = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353);
    let mdns_v6_socket_addr =
        SocketAddrV6::new(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb), 5353, 0, 0);

    let local_socket_addrs = local_ips.iter().map(|(ip, scope_id)| match ip.clone() {
        IpAddr::V4(addr) => SocketAddr::V4(SocketAddrV4::new(addr, 0)),
        IpAddr::V6(addr) => SocketAddr::V6(SocketAddrV6::new(addr, 0, 0, scope_id.unwrap())),
    });

    let senders: Vec<UdpSocket> = local_socket_addrs
        .filter_map(|addr| match UdpSocket::bind(addr) {
            Ok(socket) => Some(socket),
            Err(msg) => {
                eprintln!("skipped mDNS @ {} ({})", addr, msg);
                None
            }
        })
        .collect();

    let receivers: Vec<UdpSocket> = senders
        .iter()
        .map(|sender| {
            let receiver: UdpSocket = sender.try_clone().unwrap();
            receiver.set_nonblocking(true).unwrap();
            receiver
        })
        .collect();

    // start to listen for mDNS responses

    let handle = spawn(move || {
        let mut buffer = [0; 4096];
        loop {
            let mut blocked_receivers = 0;
            for receiver in &receivers {
                match receiver.recv_from(&mut buffer) {
                    Ok((n_bytes, origin)) => {
                        let src_ip = origin.ip();
                        let data = &buffer[0..n_bytes];
                        if let Some(name) = parse_mdns_response(data) {
                            let log_msg = format!("{} {}", src_ip, name.to_string());
                            if channel.send(log_msg).is_err() {
                                println!("upstream error, abort scan");
                                return;
                            }
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        blocked_receivers += 1;
                        continue;
                    }
                    Err(msg) => {
                        panic!("error while reading from UDP socket: {}", msg);
                    }
                };
            }
            if blocked_receivers == receivers.len() {
                sleep(Duration::from_millis(97));
            }
        }
    });

    //
    // send mDNS question
    //
    let packet = build_mdns_packet();

    for sender in senders {
        let mdns_socket_addr = match sender.local_addr().unwrap().ip() {
            IpAddr::V4(_) => SocketAddr::V4(mdns_v4_socket_addr),
            IpAddr::V6(_) => SocketAddr::V6(mdns_v6_socket_addr),
        };
        sender.send_to(&packet, &mdns_socket_addr)?;
    }

    // We're done!
    Ok(handle)
}

fn build_mdns_packet() -> Vec<u8> {
    let mut builder = dns_parser::Builder::new_query(0, false);
    builder.add_question(
        "_googlecast._tcp.local",
        true, // prefer unicast response
        dns_parser::QueryType::PTR,
        dns_parser::QueryClass::IN,
    );
    println!("{:?}", builder);
    return builder.build().unwrap();
}

fn parse_mdns_response(data: &[u8]) -> Option<String> {
    if let Ok(packet) = dns_parser::Packet::parse(data) {
        for answer in packet.answers.first() {
            if let dns_parser::rdata::RData::PTR(dns_parser::rdata::Ptr(name)) = answer.data {
                return Some(name.to_string());
            }
        }
    };
    return None;
}

///
/// start an SSDP scanner thread
///
/// Setup a socket and send a question to the mDNS multicast address
/// requesting a unicast reply. The replies are gathered in a separate
/// thread and sent to a logging channel.
fn scan_ssdp(
    local_ips: &[interfaces::InetAddr],
    channel: sync::mpsc::Sender<String>,
) -> std::io::Result<JoinHandle<()>> {
    //
    // Setup source/destination socket addresses
    //
    let ssdp_v4_socket_addr = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900);
    let ssdp_v6_socket_addr =
        SocketAddrV6::new(Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 0xc), 1900, 0, 0);

    let local_socket_addrs = local_ips.iter().map(|(ip, scope_id)| match ip.clone() {
        IpAddr::V4(addr) => SocketAddr::V4(SocketAddrV4::new(addr, 0)),
        IpAddr::V6(addr) => SocketAddr::V6(SocketAddrV6::new(addr, 0, 0, scope_id.unwrap())),
    });

    let senders: Vec<UdpSocket> = local_socket_addrs
        .filter_map(|addr| match UdpSocket::bind(addr) {
            Ok(socket) => Some(socket),
            Err(msg) => {
                eprintln!("skipped SSDP @ {} ({})", addr, msg);
                None
            }
        })
        .collect();

    let receivers: Vec<UdpSocket> = senders
        .iter()
        .map(|sender| {
            let receiver: UdpSocket = sender.try_clone().unwrap();
            receiver.set_nonblocking(true).unwrap();
            receiver
        })
        .collect();

    //
    // start to listen for mDNS responses
    //
    let handle = spawn(move || {
        let mut buffer = [0; 4096];
        loop {
            let mut blocked_receivers = 0;
            for receiver in &receivers {
                match receiver.recv_from(&mut buffer) {
                    Ok((n_bytes, origin)) => {
                        let ip = origin.ip();
                        let data = &buffer[0..n_bytes];
                        if let Some(name) = parse_ssdp_response(data) {
                            let log_msg = format!("{} {}", ip, name);
                            if channel.send(log_msg).is_err() {
                                println!("upstream error, abort scan");
                                return;
                            }
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        blocked_receivers += 1;
                        continue;
                    }
                    Err(msg) => {
                        panic!("error while reading from UDP socket: {}", msg);
                    }
                };
            }
            if blocked_receivers == receivers.len() {
                sleep(Duration::from_millis(103));
            }
        }
    });

    //
    // send SSDP M-SEARCH
    //

    for sender in senders {
        let ssdp_socket_addr = match sender.local_addr().unwrap().ip() {
            IpAddr::V4(_) => SocketAddr::V4(ssdp_v4_socket_addr),
            IpAddr::V6(_) => SocketAddr::V6(ssdp_v6_socket_addr),
        };
        let packet = build_ssdp_packet(&ssdp_socket_addr);
        sender.send_to(&packet, &ssdp_socket_addr)?;
    }

    // We're done!
    Ok(handle)
}

fn build_ssdp_packet(dst: &SocketAddr) -> Vec<u8> {
    let m_search = format!(
        "\
    M-SEARCH * HTTP/1.1\r\n\
    Host:{}\r\n\
    Man:\"ssdp:discover\"\r\n\
    ST: ssdp:all\r\n\
    MX: 1\r\n\r\n",
        dst.to_string()
    );

    return m_search.as_bytes().to_vec();
}

fn parse_ssdp_response(data: &[u8]) -> Option<String> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut headers);
    if let Ok(_) = response.parse(data) {
        for header in response.headers {
            if header.name.to_ascii_lowercase() == "server" {
                return Some(std::str::from_utf8(header.value).unwrap().to_string());
            }
        }
    }
    return None;
}

///
/// Loop over available interfaces and start a discovery scan
/// on each of their addresses.
///
fn main() {
    let if_inet_addresses: Vec<interfaces::InetAddr> = interfaces::ifaddrs().collect();
    let (sender, receiver) = sync::mpsc::channel::<String>();

    let mut scanner_thread_handles = Vec::<JoinHandle<()>>::new();

    match scan_mdns(&if_inet_addresses, sender.clone()) {
        Ok(handle) => {
            scanner_thread_handles.push(handle);
        }
        Err(msg) => eprintln!("mDNS scan failed to start: {}", msg),
    };
    match scan_ssdp(&if_inet_addresses, sender.clone()) {
        Ok(handle) => {
            scanner_thread_handles.push(handle);
        }
        Err(msg) => eprintln!("SSDP scan failed to start: {}", msg),
    };

    println!("scanning...");
    let mut log_set = collections::HashSet::<String>::new();
    for log_msg in receiver.into_iter() {
        if log_set.contains(&log_msg) {
            continue;
        }
        println!("{}", log_msg);
        log_set.insert(log_msg);
    }

    for handle in scanner_thread_handles {
        handle.join().unwrap();
    }

    return;
}
