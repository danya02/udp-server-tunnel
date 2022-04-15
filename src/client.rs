
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "0.0.0.0:34197";
    let socket = UdpSocket::bind(addr).await?;
    println!("Listening on {}", socket.local_addr()?);

    loop {
        let mut buf = [0u8; 65536];
        let (size, peer) = socket.recv_from(&mut buf).await?;
        println!("Received {} bytes from {}", size, peer);
        println!("{:x?}", &buf[..size]);
    }
}