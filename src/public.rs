use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::*;
use tokio::spawn;

struct Client {
    addr: Option<SocketAddr>,
    last_transfer: Instant,
}

struct ClientDatabase {
    clients: Vec<Client>,
    clients_by_transfer: BTreeMap<Instant, usize>,
    clients_by_ip: HashMap<SocketAddr, usize>,
}

// After this time, a client is considered inactive and its slot is available for use.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

impl Client {
    fn update_transfer(&mut self) {
        self.last_transfer = Instant::now();
    }

    fn is_inactive(&self) -> bool {
        self.last_transfer.elapsed() > CLIENT_TIMEOUT
    }
}

impl ClientDatabase {
    fn new(max_size: usize) -> Self {
        // In order to ensure that the first slot will be taken up by the first client,
        // the transfer time for each client is set a long time in the past,
        // and each of the client slots has that long-ago time incremented.
        let mut cur_time = Instant::now() - Duration::from_secs(max_size.try_into().unwrap());
        cur_time -= CLIENT_TIMEOUT;
        let mut clients = Vec::with_capacity(max_size);
        let mut clients_by_transfer = BTreeMap::new();
        for i in 0..max_size {
            let client = Client {
                addr: None,
                last_transfer: cur_time,
            };
            clients.push(client);
            clients_by_transfer.insert(cur_time, i);
            cur_time += Duration::from_secs(1);
        }
        ClientDatabase {
            clients: clients,
            clients_by_transfer: clients_by_transfer,
            clients_by_ip: HashMap::new(),
        }
    }

    fn get_free_slot_index(&self) -> Option<usize> {
        // Because the B-Tree will be sorted by the last time a client transferred,
        // the first slot in the B-Tree will be the oldest client.
        // If that client is inactive, we can use it;
        // if it is not, then we are out of clients, and we return None.
        //
        // Note that this only returns an index, and doesn't update the database.

        let first_slot = self.clients_by_transfer.iter().next()?;
        let first_client = &self.clients[*first_slot.1];
        if first_client.is_inactive() {
            Some(*first_slot.1)
        } else {
            None
        }
    }

    fn update_slot(&mut self, slot_index: usize, new_client: Client) {
        // Set the current values for the client in the given slot to match the specified client.
        // This will update the hash maps.
        let client = &mut self.clients[slot_index];
        self.clients_by_transfer.remove(&client.last_transfer);
        if let Some(addr) = &client.addr {
            self.clients_by_ip.remove(addr);
        }
        *client = new_client;
        self.clients_by_transfer
            .insert(client.last_transfer, slot_index);
        if let Some(addr) = &client.addr {
            self.clients_by_ip.insert(*addr, slot_index);
        }
    }

    fn get_client_by_addr(&mut self, addr: SocketAddr) -> Option<usize> {
        // If the client is already in the database, update its transfer time, then return its slot index.
        // If the client is not in the database, try to find a free slot.
        // If there is one, add the client to the database and return its slot index.
        // If there is not one, return None.
        if let Some(slot_index) = self.clients_by_ip.get(&addr) {
            Some(*slot_index)
        } else {
            let free_slot_index = self.get_free_slot_index()?;
            let client = Client {
                addr: Some(addr),
                last_transfer: Instant::now(),
            };
            self.update_slot(free_slot_index, client);
            Some(free_slot_index)
        }
    }

    fn get_addr_by_index(&mut self, slot_index: usize) -> Option<SocketAddr> {
        // Return the address of the client in the given slot, updating its transfer time (even if it is already timeouted).
        // If the slot does not have an address, or if the slot does not exist, return None.
        let client = self.clients.get_mut(slot_index)?;
        if let Some(addr) = client.addr {
            client.update_transfer();
            Some(addr)
        } else {
            None
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target: std::net::SocketAddr = "0.0.0.0:12345".parse().unwrap();
    let listener = TcpListener::bind(&target).await?;
    println!("Waiting for connection bound to {}...", target);
    let (tcp_stream, _remote_addr) = listener.accept().await?;
    println!("Connected to server at {}", tcp_stream.peer_addr()?);
    let (read_half, write_half) = tcp_stream.into_split();

    let recv_socket = UdpSocket::bind("0.0.0.0:34197").await?; // This socket is used both to receive and send packets.

    let client_database = ClientDatabase::new(256);
    let client_database_lock = Arc::new(Mutex::new(client_database));
    let client_database_lock_clone = client_database_lock.clone();

    let recv_socket_mutex = Arc::new(tokio::sync::Mutex::new(recv_socket)); // Because this socket is used by multiple threads, we need to wrap it in a Mutex,
                                                                            // and it's easier to use the expensive async Mutex here.
    let recv_socket_mutex_clone = recv_socket_mutex.clone();

    let t2u =
        spawn(async { recv_tcp_send_udp(read_half, recv_socket_mutex, client_database_lock).await });

    let _u2t = spawn(async{
        recv_udp_send_tcp(recv_socket_mutex_clone, write_half, client_database_lock_clone).await
    });

    // When the TCP connection is closed, only the recv_tcp task will detect it.
    // Because of this, we only wait for that task to finish before exiting.
    t2u.await.unwrap();
    Ok(())
}

// Wire format: the first 4 bytes of every packet sent over TCP are the client's ID, in big-endian format; the rest of the packet is the UDP data.
async fn recv_udp_send_tcp(
    reader: Arc<tokio::sync::Mutex<UdpSocket>>,
    write_half: tokio::net::tcp::OwnedWriteHalf,
    database: Arc<Mutex<ClientDatabase>>,
) {
    let mut buf = [0u8; 65536];
    println!(
        "Spawned recv_udp_send_tcp with reader={:?} and write_half={:?}",
        reader, write_half
    );
    loop {
        let size;
        let peer;
        {
            let held_reader = reader.lock().await;
            let (n, addr) = held_reader.recv_from(&mut buf).await.unwrap();
            size = n;
            peer = addr;
        }
        println!("Received {} bytes from {}", size, peer);

        let maybe_client_index;
        {
            // Block for mutex lock acquisition
            let mut database = database.lock().unwrap();
            maybe_client_index = database.get_client_by_addr(peer);
        }
        if let Some(client_index) = maybe_client_index {
            let client_index = client_index+1;  // The first IP address in a range is not routable.
            println!("That corresponds to client {}", client_index);
            let client_index: u32 = client_index.try_into().unwrap();
            let client_index_bytes = client_index.to_be_bytes();
            let mut to_send_over_tcp = [0u8; 65536 + 4];
            to_send_over_tcp[..4].copy_from_slice(&client_index_bytes);
            to_send_over_tcp[4..4+size].copy_from_slice(&buf[..size]);
            // Wait until the write half is ready to write.
            match write_half.writable().await {
                Ok(_) => match write_half.try_write(&to_send_over_tcp[..size + 4]) {
                    Ok(sent_size) => {
                        println!("Sent {} bytes to TCP", sent_size);
                    }
                    Err(e) => {
                        println!("Error writing to TCP: {:?}", e);
                        return;
                    }
                },
                Err(e) => {
                    println!("Error while waiting to write to TCP: {:?}", e);
                    return;
                }
            }
        } else {
            println!("That client is not in the database");
        }
    }
}

async fn recv_tcp_send_udp(
    read_half: tokio::net::tcp::OwnedReadHalf,
    writer: Arc<tokio::sync::Mutex<UdpSocket>>,
    database: Arc<Mutex<ClientDatabase>>,
) {
    let mut buf = [0u8; 65536];

    println!(
        "Spawned recv_tcp_send_udp with read_half={:?} and writer={:?}",
        read_half, writer
    );
    loop {
        read_half.readable().await.unwrap();
        let result = read_half.try_read(&mut buf);
        match result {
            Ok(0) => {
                // Receiving 0 bytes means the connection is closed.
                println!("TCP connection closed");
                return;
            }
            Ok(n) => {
                println!("Received {} bytes from TCP", n);
                if n < 4 {
                    println!("Received a packet with less than 4 bytes");
                    continue;
                }
                let client_index = u32::from_be_bytes(buf[..4].try_into().unwrap());
                let client_index = (client_index-1) as usize;  // The first IP address in a range is not routable, and we incremented the IP address up top.
                println!("That corresponds to client {}", client_index);
                let maybe_addr;
                {
                    // Block for mutex lock acquisition
                    let mut database = database.lock().unwrap();
                    maybe_addr = database.get_addr_by_index(client_index);
                }
                
                if let Some(addr) = maybe_addr {
                    println!("Sending to {}", addr);
                    //let writer = UdpSocket::connect(addr).await.unwrap();
                    let held_writer = writer.lock().await;
                    held_writer.send_to(&buf[4..n], addr).await.unwrap();  // FIXME: thread 'tokio-runtime-worker' panicked at 'called `Result::unwrap()` on an `Err` value: Os { code: 22, kind: InvalidInput, message: "Invalid argument" }', src/public.rs:240:60
                } else {
                    println!("That client is not in the database");
                }
            },

            Err(_e) => {
                // This shouldn't happen: try_read() should only return an error if there is no data available,
                // but we checked for that with readable().
                // Actually this does happen every time after a successful read, so this should be ignored.
                //println!("Error while reading from TCP: {:?}", e);
            }
        }
    }
}
