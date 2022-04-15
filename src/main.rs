use std::net::Ipv4Addr;
use tun_tap::Iface;
use tun_tap::Mode;

// To create a TUN interface on Linux and set an IP range associated with it, run:
// sudo ip tuntap add dev tun0 mode tun user $USER
// sudo ip link set tun0 up
// sudo ip addr add 172.16.0.0/12 dev tun0

fn get_iface() -> Iface {
    let iface = Iface::new("tun0", Mode::Tun).unwrap();
    iface
}

fn main() {
    println!("Hello, world!");
    let iface = get_iface();

    println!("Connected to interface {}", iface.name());

    loop {
        let mut buf = [0u8; 65536];
        let n;
        match iface.recv(&mut buf) {
            Ok(len) => {
                n = len;
            }
            Err(e) => {
                println!("Error: {:?}", e);
                break;
            }
        }
        println!("Received {} bytes:", n);
        // The first two bytes are the flags, and the next two are the EtherType of the protocol: 
        // https://en.wikipedia.org/wiki/EtherType
        // The expected EtherType is 0x0800 (0x00 0x08) for IPv4; IPv6 is hard so we'll ignore it for now.
        if !(&buf[2..=3] == &[0x08, 0x00]) {
            println!("Protocol {:x?} is not IPv4, ignoring", &buf[2..=3]);
            continue;
        }

        // The remaining bytes are the IPv4 packet.
        let ip_packet = &buf[4..=n];

        let version_and_ihl = ip_packet[0];
        let version = version_and_ihl >> 4;
        let ihl = version_and_ihl & 0x0F;
        let header_length: usize = ihl as usize * 4;

        let dscp_and_ecn = ip_packet[1];
        let dscp = dscp_and_ecn >> 2;
        let ecn = dscp_and_ecn & 0x03;

        let total_length = u16::from_be_bytes([ip_packet[2], ip_packet[3]]) as usize;

        let identification = u16::from_be_bytes([ip_packet[4], ip_packet[5]]);

        let flags_and_fragment_offset = u16::from_be_bytes([ip_packet[6], ip_packet[7]]);
        let flags = flags_and_fragment_offset >> 13;
        let fragment_offset = flags_and_fragment_offset & 0x1FFF;

        let ttl = ip_packet[8];
        let protocol = ip_packet[9];
        let header_checksum = u16::from_be_bytes([ip_packet[10], ip_packet[11]]);

        let source_address = u32::from_be_bytes([ip_packet[12], ip_packet[13], ip_packet[14], ip_packet[15]]);
        let destination_address = u32::from_be_bytes([ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]]);

        let source_address = Ipv4Addr::from(source_address);
        let destination_address = Ipv4Addr::from(destination_address);



        let data = &ip_packet[header_length..total_length];

        println!("IP packet: version={}, header_length={}, total_length={}, identification={}, flags={}, fragment_offset={}, ttl={}, protocol={}, header_checksum={}, source_address={}, destination_address={}",
            version, header_length, total_length, identification, flags, fragment_offset, ttl, protocol, header_checksum, source_address, destination_address);
        println!("Data: {:x?}", data);



    }

}
