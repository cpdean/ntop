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


fn parseable(ethernet: EthernetPacket) -> Option<EthernetPacket> {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 | EtherTypes::Ipv6 | EtherTypes::Arp => Some(ethernet) ,
        _ => None
    }
}

fn handle_packet(ethernet: &EthernetPacket) {
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

    // loop over packets arriving on the given interface
    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = EthernetPacket::new(packet).unwrap();
                handle_packet(&packet);
            }
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}


