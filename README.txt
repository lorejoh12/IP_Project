README: IP_Project

Names: Leeviana Gray (lpg6), John Lorenz (jcl47)

Notes:

To compile, gcc needs to include both node.c and ipsum.c
	gcc node.c ipsum.c -o node

Extra credit Implementation: Fragmentation
assumptions: MTU is the total maximum size, including the header (so having an mtu of size < sizeof(iphdr) doesn't make sense)

Fragmentation was implemented in the send_packet and receive_packet methods.
In send_packet, the mtu for the current link is checked. This is compared to size of the payload and the header. If the mtu value isn't 0 (0 means it wasn't set, so don't fragment at all). If the size of payload + header is > mtu, the payload is broken down and sent in multiple packets (all sent back to back)

in receive, a packet is checked to see if the IP_MF bit is 1. If it is, then the data from the payload is read into a buffer. This continues until a packet is read with IP_MF of 0, when the buffer is collapsed together and considered to be a single payload.

