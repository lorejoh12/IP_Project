README: IP_Project

Names: Leeviana Gray (lpg6), John Lorenz (jcl47)

Notes:

To compile, gcc needs to include both node.c and ipsum.c
	gcc node.c ipsum.c -o node

Routing implementation
----------------------
On initialization, direct links (interfaces set up from file) and the node's own addresses are stored in routing table. IP addresses directly associated with the node are set with a distance 0 and interface ID -1. RIP update requests are sent out on the node's interfaces and RIP responses containing table information (cost and destination addresses) are sent back. If the source of the route information is the destination of the update, the cost is set to 16 (reverse poison).

Whenever the routing table is accessed (to print routes, send RIP response, or get a route entry), refresh_table is called first to set all table entries with expired timestamps to distance INFINITY (16).

When select times out or a fd that select is listening to has data, then the last_trigger timestamp is checked. If it has been 5 seconds or longer since the last timeout triggered update, the trigger_update() method is called that sends out RIP route information packets to all the node's interfaces that are up. trigger_update is also called after an interface's status has been changed (up or down). The timeout for select is set to be the amount of time left until the next 5 second update should be sent out.

Forwarding implementation
-------------------------


Extra credit Implementation: Fragmentation
------------------------------------------
assumptions: MTU is the total maximum size, including the header (so having an mtu of size < sizeof(iphdr) doesn't make sense

- Extra commands:
mtu interface_id mtu_value: sets the MTU for that link, including header size
dfset: sets the DF bit for all generated packets to 1 (not applied to forwarded packets)
dfoff: sets the DF bit for all generated packets to 0 (not applied to forwarded packets)

Fragmentation was implemented in the send_packet and receive_packet methods.
In send_packet, the mtu for the current link is checked. This is compared to size of the payload and the header. If the mtu value isn't 0 (0 means it wasn't set, so don't fragment at all). If the size of payload + header is > mtu, the payload is broken down and sent in multiple packets (all sent back to back). If the DF bit is set to 1, then the packet is dropped.

in receive, a packet is checked to see if the IP_MF bit is 1. If it is, then the data from the payload is read into a buffer. This continues until a packet is read with IP_MF of 0, when the buffer is collapsed together and considered to be a single payload. This packet then carries through the system as though it hadn't been fragmented at all.

The fragmentation occurs for all messages sent through that link, both test messages and routing messages.

