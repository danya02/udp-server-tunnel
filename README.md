# udp-server-tunnel
Proxy connections to a UDP server through TCP.

Designed to allow connecting to a UDP server behind a NAT, given a publicly accessible server.

## How it works
The Gateway is a computer that is reachable from the internet, and the Host is a computer that is behind a NAT.
The Host is running an application that is a UDP server.

There are two programs: `public` and `local`.

The `public` program is run on the Gateway.
It accepts a TCP connection from the Host, and uses that connection as the tunnel.
It also accepts UDP packets from the internet.
When a packet is received, the IP-port pair is recorded and assigned a unique ID.
Then, the packet is sent over the TCP connection to the Host.

The `local` program is run on the Host.
It establishes the connection to the Gateway.
It also creates (or uses an existing) local TUN device.
When the Gateway sends a packet, the unique ID of the client who sent it is converted into an IP address in the TUN device's address range.
The packet is then sent to the TUN device, where the application will pick it up and handle.

To the application, the packet looks like it came from the TUN device's address range, so the response will be pointed there.
When the application replies, the `local` program will receive the packet, and it will be sent back to the Gateway, along with the number of the virtual IP address that the packet came from.
The Gateway will then use the number of the virtual IP address as the unique ID, identifying the client, and send the contents of the packet to the client.