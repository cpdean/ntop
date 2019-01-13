extern crate pnet;

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::PacketSize;
use pnet::packet::udp::UdpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;

use std::env;
use std::collections::HashMap;

struct PacketAccumulator {
    addrs: HashMap<(std::net::Ipv4Addr, std::net::Ipv4Addr), i32>,
}

impl PacketAccumulator {
    pub fn new() -> PacketAccumulator {
        PacketAccumulator {
            addrs: HashMap::new(),
        }
    }

    fn render(&self) {
        let mut a = Vec::new();
        for ((src, dest), bytes) in &self.addrs {
            a.push((format!("{} -> {}", src.clone(), dest.clone()), bytes.clone()));
        }
        a.sort_by(|a, b| b.1.cmp(&a.1));
        a.truncate(5);
        println!("=======");
        for entry in a {
            println!("{:?}", entry);
        }
    }

    pub fn push(&mut self, ethernet: EthernetPacket) {
        if let EtherTypes::Ipv4 = ethernet.get_ethertype() {
            let ipv4_packet = Ipv4Packet::new(ethernet.payload());
            if let Some(ipv4_packet) = ipv4_packet {
                // i guess discard non tcp
                if let IpNextHeaderProtocols::Tcp = ipv4_packet.get_next_level_protocol() {
                    let tcp = TcpPacket::new(ipv4_packet.payload());
                    if let Some(tcp) = tcp {
                        let (src, dest) = (
                            ipv4_packet.get_source(),
                            ipv4_packet.get_destination()
                        );
                        let running: i32 = match self.addrs.get(&(src, dest)) {
                            Some(running_total) => *running_total,
                            None => 0,
                        };
                        let payload_size = tcp.payload().len() as i32;
                        self.addrs.insert((src, dest), running + payload_size);
                        self.render();
                    }
                }
            }
        }
    }
}


fn parseable(ethernet: EthernetPacket) -> Option<EthernetPacket> {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 | EtherTypes::Ipv6 | EtherTypes::Arp => Some(ethernet) ,
        _ => None
    }
}

fn handle_packet(ethernet: &EthernetPacket) {
    if let EtherTypes::Ipv4 = ethernet.get_ethertype() {
        let header = Ipv4Packet::new(ethernet.payload());
        if let Some(header) = header {
            if let IpNextHeaderProtocols::Tcp = header.get_next_level_protocol() {
                let tcp = TcpPacket::new(header.payload());
                if let Some(tcp) = tcp {
                    println!(
                        "Ipv4:TCP: {} to {}: size {}, seq {}, win {}, offset {}, first {}, payload len {}",
                        header.get_source(),
                        header.get_destination(),
                        tcp.packet_size(),
                        tcp.get_sequence(),
                        tcp.get_window(),
                        tcp.get_data_offset(),
                        if tcp.payload().len() > 0 {
                            tcp.payload()[0]
                        } else {
                            0
                        },
                        tcp.payload().len(),
                        );
                }
            }
        }
    }
}

fn handle_packet_everything(ethernet: &EthernetPacket) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let header = Ipv4Packet::new(ethernet.payload());
            if let Some(header) = header {
                match header.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        let tcp = TcpPacket::new(header.payload());
                        if let Some(tcp) = tcp {
                            println!(
                                "Ipv4:TCP: {} to {}: size {}",
                                header.get_source(),
                                header.get_destination(),
                                tcp.packet_size(),
                                );
                        }
                    },
                    IpNextHeaderProtocols::Udp => {
                        let tcp = UdpPacket::new(header.payload());
                        if let Some(tcp) = tcp {
                            println!(
                                "Ipv4:UDP: {} to {}: size {}",
                                header.get_source(),
                                header.get_destination(),
                                tcp.packet_size(),
                                );
                        }
                    },
                    IpNextHeaderProtocols::Igmp => {
                        // write one, like https://docs.rs/pnet_packet/0.21.0/src/pnet_packet/home/cratesfyi/cratesfyi/debug/build/pnet_packet-5727444bbdb057d0/out/udp.rs.html#61-66
                        println!( "Ipv4:Igmp: no supported parser yet");
                    },
                    x => println!("Ipv4:ignoring non TCP packet, {:?}", x),
                }
            }
        },
        EtherTypes::Ipv6 => {
            let header = Ipv4Packet::new(ethernet.payload());
            if let Some(header) = header {
                match header.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        let tcp = TcpPacket::new(header.payload());
                        if let Some(tcp) = tcp {
                            println!(
                                "Ipv6:TCP: {}:{} to {}:{}",
                                header.get_source(),
                                tcp.get_source(),
                                header.get_destination(),
                                tcp.get_destination()
                                );
                        }
                    },
                    IpNextHeaderProtocols::Sscopmce => {
                        // maybe follow https://docs.rs/pnet_packet/0.21.0/src/pnet_packet/home/cratesfyi/cratesfyi/debug/build/pnet_packet-5727444bbdb057d0/out/udp.rs.html#61-66
                        println!( "Ipv6:Sscopmce: no supported parser yet");
                    },
                    x => println!("Ipv6:ignoring non TCP packet, {:?}", x),
                }
            }
        },
        EtherTypes::Arp => {
            let header = Ipv4Packet::new(ethernet.payload());
            if let Some(header) = header {
                match header.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        let tcp = TcpPacket::new(header.payload());
                        if let Some(tcp) = tcp {
                            println!(
                                "Arp:TCP: {}:{} to {}:{}",
                                header.get_source(),
                                tcp.get_source(),
                                header.get_destination(),
                                tcp.get_destination()
                                );
                        }
                    },
                    x => {
                        let name = format!("{}", x);
                        println!("Arp:ignoring non TCP packet, {}", name)
                    }
                }
            }
        },
        x => println!("ignoring non ipv4,ipv6,arp packet, {:?}", x),
    }
}

fn handle_packet_raw(ethernet: &EthernetPacket) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let header = Ipv4Packet::new(ethernet.payload());
            if let Some(header) = header {
                match header.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        let tcp = TcpPacket::new(header.payload());
                        if let Some(tcp) = tcp {
                            println!(
                                "Ipv4:TCP: {}:{} to {}:{}",
                                header.get_source(),
                                tcp.get_source(),
                                header.get_destination(),
                                tcp.get_destination()
                                );
                        }
                    },
                    IpNextHeaderProtocols::Udp => {
                        let tcp = UdpPacket::new(header.payload());
                        if let Some(tcp) = tcp {
                            println!(
                                "Ipv4:UDP: {}:{} to {}:{}",
                                header.get_source(),
                                tcp.get_source(),
                                header.get_destination(),
                                tcp.get_destination()
                                );
                        }
                    },
                    IpNextHeaderProtocols::Igmp => {
                        // write one, like https://docs.rs/pnet_packet/0.21.0/src/pnet_packet/home/cratesfyi/cratesfyi/debug/build/pnet_packet-5727444bbdb057d0/out/udp.rs.html#61-66
                        println!( "Ipv4:Igmp: no supported parser yet");
                    },
                    x => println!("Ipv4:ignoring non TCP packet, {:?}", x),
                }
            }
        },
        EtherTypes::Ipv6 => {
            let header = Ipv4Packet::new(ethernet.payload());
            if let Some(header) = header {
                match header.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        let tcp = TcpPacket::new(header.payload());
                        if let Some(tcp) = tcp {
                            println!(
                                "Ipv6:TCP: {}:{} to {}:{}",
                                header.get_source(),
                                tcp.get_source(),
                                header.get_destination(),
                                tcp.get_destination()
                                );
                        }
                    },
                    IpNextHeaderProtocols::Sscopmce => {
                        // maybe follow https://docs.rs/pnet_packet/0.21.0/src/pnet_packet/home/cratesfyi/cratesfyi/debug/build/pnet_packet-5727444bbdb057d0/out/udp.rs.html#61-66
                        println!( "Ipv6:Sscopmce: no supported parser yet");
                    },
                    x => println!("Ipv6:ignoring non TCP packet, {:?}", x),
                }
            }
        },
        EtherTypes::Arp => {
            let header = Ipv4Packet::new(ethernet.payload());
            if let Some(header) = header {
                match header.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        let tcp = TcpPacket::new(header.payload());
                        if let Some(tcp) = tcp {
                            println!(
                                "Arp:TCP: {}:{} to {}:{}",
                                header.get_source(),
                                tcp.get_source(),
                                header.get_destination(),
                                tcp.get_destination()
                                );
                        }
                    },
                    x => {
                        let name = format!("{}", x);
                        println!("Arp:ignoring non TCP packet, {}", name)
                    }
                }
            }
        },
        x => println!("ignoring non ipv4,ipv6,arp packet, {:?}", x),
    }
}

fn main() {
    let interface_name = env::args().nth(1).unwrap();

    // get all interfaces
    let interfaces = datalink::interfaces();

    //filter the list to find the given interface name
    let interface = interfaces.into_iter()
        .filter(|iface: &NetworkInterface| iface.name == interface_name)
        .next()
        .expect("error getting interface");

    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unhandled channel type!"),
        Err(e) => {
            panic!(
                "An Error occurred when creating th edatalink channel: {}",
                e
                )
        },
    };

    let mut accumulator = PacketAccumulator::new();

    // loop over packets arriving on the given interface
    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = EthernetPacket::new(packet).unwrap();
                accumulator.push(packet);
            }
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}


