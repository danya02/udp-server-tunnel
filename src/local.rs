use packet::Builder;
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio_tun::{Tun, TunBuilder};

#[derive(Debug, Clone)]
struct IPRange {
    addr: Ipv4Addr,
    mask: u8,
}

impl IPRange {
    fn new(addr: Ipv4Addr, mask: u8) -> Self {
        IPRange {
            addr: addr,
            mask: mask,
        }
    }

    fn get_addr(&self) -> Ipv4Addr {
        self.addr
    }

    fn get_bitmask(&self) -> u32 {
        // Get a number whose first `mask` bits are 1 and the rest are 0.
        let mut bitmask = 0;
        for i in 0..self.mask {
            bitmask |= 1 << (31 - i);
        }
        bitmask
    }

    fn get_addr_mask(&self) -> Ipv4Addr {
        // Get the address with the first `mask` bits set to 1.
        Ipv4Addr::from(self.get_bitmask())
    }

    fn get_size(&self) -> u32 {
        // Get the number of IP addresses in the range.
        // (if mask is 24, then there are 256 IP addresses in the range == 2**(32-24) == 2**8)
        1 << (32 - self.mask)
    }

    fn get_by_index(&self, index: u32) -> Option<Ipv4Addr> {
        // Get the IP address in this range by adding the index to the base address, and checking that the result is within the subnet.
        let addr_num: u32 = self.addr.into();
        let bitmask = self.get_bitmask();
        let anti_mask = !bitmask;
        let addr_start = addr_num & bitmask;
        let addr_end = addr_start | anti_mask;
        let addresses = addr_start..=addr_end;

        // If the address overflowed, then it is surely not in the subnet.
        let (potential_addr, did_overflow) = addr_start.overflowing_add(index);
        if did_overflow {
            return None;
        }
        if addresses.contains(&potential_addr) {
            Some(Ipv4Addr::from(potential_addr))
        } else {
            None
        }
    }
}

// To create a TUN interface on Linux and set an IP range associated with it, run:
// sudo ip tuntap add dev tun0 mode tun user $USER
// sudo ip link set tun0 up
// sudo ip addr add 172.16.0.0/12 dev tun0

fn get_iface(range: &IPRange) -> Tun {
    println!("{} {}", range.get_addr(), range.get_addr_mask());
    let builder = TunBuilder::new()
        .name("tun0")
        .tap(false)
        .packet_info(true) // Strictly not needed, but I already wrote code for ignoring non-IPv4 packets.
        .mtu(3000) // Jumbograms, in case the application tries sending a very large packet to the TUN. Probably not needed.
        .owner(1000)
        .group(1000) // Usually on Linux, the `1000` UID/GID correspond to the user account.
        .address(range.get_addr())
        .netmask(range.get_addr_mask())
        .up();

    builder.try_build().expect("Could not build TUN device")
}

#[tokio::main]
async fn main() {
    println!("Hello, world!");

    // Connect to the public side via TCP.
    let addr = "127.0.0.1:12345";  // TODO: Make this configurable.
    let stream = TcpStream::connect(addr)
        .await
        .expect("Could not connect to server");
    let (read_half, write_half) = stream.into_split();
    println!("Connected to server");

    let range = IPRange::new(Ipv4Addr::new(172, 16, 0, 0), 12); // 172.16.0.0/12 subnet (class B local network)
    let range_clone = range.clone();
    let iface = get_iface(&range);
    let (tun_reader, tun_writer) = tokio::io::split(iface);

    let i2t = tokio::spawn(async move { recv_tun_send_tcp(tun_reader, write_half, range).await });
    let t2i =
        tokio::spawn(async move { recv_tcp_send_tun(read_half, tun_writer, range_clone).await });

    i2t.await.unwrap();
    t2i.await.unwrap();
}

async fn recv_tun_send_tcp(
    mut tun_read_half: tokio::io::ReadHalf<Tun>,
    write_half: OwnedWriteHalf,
    range: IPRange,
) {
    let mut buf = [0u8; 65536];
    loop {
        let n;
        match tun_read_half.read(&mut buf).await {
            Ok(len) => {
                n = len;
            }
            Err(e) => {
                // An error of "Resource temporarily unavailable" occurs after every read, ignore it.
                println!("Error: {:?}", e);
                continue;
            }
        }

        let buf = &buf[..n];
        println!("Read {} bytes from TUN", n);


        // The first two bytes are the flags, and the next two are the EtherType of the protocol:
        // https://en.wikipedia.org/wiki/EtherType
        // The expected EtherType is 0x0800 (0x00 0x08) for IPv4; IPv6 is hard so we'll ignore it for now.
        if !(&buf[2..=3] == &[0x08, 0x00]) {
            println!("Protocol {:x?} is not IPv4, ignoring", &buf[2..=3]);
            continue;
        }

        // The remaining bytes are the IPv4 packet.
        let ip_buf = &buf[4..];
        let ip_packet = packet::ip::v4::Packet::new(ip_buf).expect("Could not parse IPv4 packet");
        // ip_packet.payload is not the actual application data; the application data is after the header.
        let udp_packet = &ip_buf[(ip_packet.header() as usize * 4)..];
        println!("IP packet payload (UDP packet): {} bytes", udp_packet.len());

        // The UDP packet has a 8-byte header: source port, destination port, length, checksum, each as a u16.

        let _source_port = u16::from_be_bytes([udp_packet[0], udp_packet[1]]);
        let dest_port = u16::from_be_bytes([udp_packet[2], udp_packet[3]]);
        let length = u16::from_be_bytes([udp_packet[4], udp_packet[5]]);
        let _checksum = u16::from_be_bytes([udp_packet[6], udp_packet[7]]);
        let payload = &udp_packet[8..];

        if dest_port != 10000 {
            // The virtual client has sent their request over port 10000, and if the reply isn't sent back to the same port, it will be lost.
            // The server shouldn't be doing this, so we ignore the packet.
            println!("Destination port {} is not 10000, ignoring", dest_port);
            continue;
        }
        println!("UDP packet payload: {} (header says {}) bytes {:x?}", payload.len(), length-8, payload);


        // The virtual client sent a request using a virtual IP, and the server replied with that virtual IP as the destination.
        let virtual_client_ip: u32 = ip_packet.destination().into();
        let range_start_ip: u32 = range.get_addr().into();
        let virtual_client_index = virtual_client_ip - range_start_ip;
        if virtual_client_index > (range.get_size() - 1) as u32 {
            println!(
                "Virtual client IP {} is outside of range {:?}",
                ip_packet.destination(),
                range
            );
            continue;
        }


        let mut tcp_buf = Vec::with_capacity(payload.len() + 4);
        tcp_buf.extend_from_slice(&virtual_client_index.to_be_bytes());
        tcp_buf.extend_from_slice(&payload);

        println!("Sending {} bytes over TCP", tcp_buf.len());
        match write_half.writable().await {
            Ok(_) => match write_half.try_write(&tcp_buf) {
                Ok(len) => {
                    println!("Sent {} bytes over TCP", len);
                }
                Err(e) => {
                    println!("Error writing to TCP: {:?}", e);
                    break;
                }
            },
            Err(e) => {
                println!("Error waiting to write to TCP: {:?}", e);
                break;
            }
        }
    }
}

async fn recv_tcp_send_tun(
    read_half: OwnedReadHalf,
    mut tun: tokio::io::WriteHalf<Tun>,
    range: IPRange,
) {
    let mut buf = [0u8; 65536];
    loop {
        let n;
        match read_half.readable().await {
            Ok(_) => match read_half.try_read(&mut buf) {
                Ok(len) => {
                    n = len;
                    if n == 0 {
                        println!("TCP connection closed");
                        break;
                    }
                }
                Err(e) => {
                    println!("Error reading from TCP: {:?}", e);
                    continue;
                }
            },
            Err(e) => {
                println!("Error waiting to read from TCP: {:?}", e);
                continue;
            }
        }

        let buf = &buf[..n];
        println!("Received {} bytes from TCP:", n);
        println!("Data: {:x?}", &buf);

        // The first 4 bytes are the virtual client ID, which we will convert to an IP address.
        let virtual_client_id = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        let virtual_ip;

        match range.get_by_index(virtual_client_id) {
            Some(addr) => {
                virtual_ip = addr;
            }
            None => {
                println!(
                    "Virtual client ID {} is outside of range {:?}",
                    virtual_client_id, range
                );
                continue;
            }
        }

        let payload = &buf[4..];
        println!("Received payload: {} bytes {:x?}", payload.len(), payload);

        // Now we have the virtual client IP, we can construct the IP packet.
        let packet_buf = packet::ip::v4::Builder::default()
            .source(virtual_ip).unwrap()
            .ttl(8).unwrap()  // Don't let this packet get too far into the network.
            .destination(Ipv4Addr::new(172,20,50,146)).unwrap() // TODO: this must be the IP address of the server
            //.payload(payload).unwrap()
            .protocol(packet::ip::Protocol::Udp).unwrap()
            .udp().unwrap()
                .source(10000).unwrap()
                .destination(34197).unwrap()  // TODO: this must be the port of the server
                .payload(payload).unwrap()
                .build().unwrap();


        // Now we have the IP packet, we can construct the TUN packet.
        // The first 4 bytes need to be set to 0x0000 for the flags, and 0x0080 for IPv4.
        let mut tun_buf = Vec::with_capacity(packet_buf.len() + 4);
        tun_buf.extend_from_slice(&[0x00, 0x00, 0x08, 0x00]);
        tun_buf.extend_from_slice(&packet_buf);



        println!("Sending {} bytes to TUN: {:x?}", tun_buf.len(), &tun_buf);

        match tun.write(&tun_buf).await {
            Ok(len) => {
                println!("Sent {} bytes to TUN", len);
            }
            Err(e) => {
                println!("Error writing to TUN: {:?}", e);
                break;
            }
        }
    }
}
