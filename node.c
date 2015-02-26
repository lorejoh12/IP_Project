#include <netinet/ip.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

#include "ipsum.h"

#define MAX_MSG_LENGTH (1400)
#define MAX_BACK_LOG (5)
#define MAX_READIN_BUFFER (64 * 1024)

#define MAX_DISTANCE 16

#define LOCALHOST_IP "127.0.0.1"

#define RIP_PROTOCOL 200
#define TEST_PROTOCOL 0

/* table of table entries */
/* table of link interfaces along with their status (up or down) */
/* uint16_t myPort */
/* socket mySocket */
typedef struct link_entry
{
    //sourceofentry // what is this?
    //int connection; // what is this?
    int distance;
    int interface_id;
    uint16_t port; // the actual port to send to
    char interface_ip[20]; // the actual IP address of the connection
    char interface_vip[20]; // the given "virtual" IP address of the connection
    char my_vip[20]; // the "virtual" IP address that they have for this node
    char * status; // up or down
    //lastupdated timestamp // not sure if necessary since we'll be doing simultaneous updates?
} entry_t;

typedef struct ifconfig_entry
{
    int interface_id;
    int mtu_size;
    uint16_t port; // the actual port to send to
    char interface_ip[20]; // the actual IP address of the connection
    char interface_vip[20]; // the given "virtual" IP address of the connection
    char my_vip[20]; // the "virtual" IP address that they have for this node
    char * status; // up or down
} ifentry_t;

entry_t link_entry_table[100]; // I'm tired of trying to do this correctly
ifentry_t ifconfig_table[100];

typedef struct rip_msg
{
    uint16_t command;
    uint16_t num_entries;
    
    struct {
        uint32_t cost;
        uint32_t address;
    } entries[64];
} rip_msg_t;

/* 
IP packet header in ip.h
*/

print_ifconfig(){
    int i;
    printf("printing ifconfig:\n");
    for(i = 0; ; i += 1){
        ifentry_t e = ifconfig_table[i];
        if(e.interface_id == 0) break;
        printf("%d %s %s\n", e.interface_id, e.interface_vip, e.status);
    }
}

// gets the table entry in the router from the VIP provided
entry_t extractNextHopFromVIP(char * interface_vip){
    entry_t NullStruct = { MAX_DISTANCE, -1, -1, "", "", "" };
    if(interface_vip == NULL) return NullStruct;
    int i;
    for(i = 0; ; i +=1){
        entry_t e = link_entry_table[i];
        if(strcmp(interface_vip, e.interface_vip)==0) return e;
        if(e.interface_id <= 0) break;
    }
    return NullStruct;
}

ifentry_t extractIfEntryFromPort(int port){
    ifentry_t NullStruct = { MAX_DISTANCE, -1, -1, "", "", "" };
    if(port == 0) return NullStruct;
    int i;
    for(i = 0; ; i +=1){
        ifentry_t e = ifconfig_table[i];
        if(e.port == port) return e;
        if(e.interface_id <= 0) break;
    }
    return NullStruct;
}

int isMe(char * vip){
    if(vip == NULL) return -1;
    int i;
    for(i = 0; ; i +=1){
        ifentry_t e = ifconfig_table[i];
        if(strcmp(vip, e.my_vip)==0) return 1;
        if(e.interface_id <= 0) break;
    }
    return -1;
}

/* refreshTable()
checks if entries are expired (older than 12 seconds)


/* referenceTable()
        call refreshtable
        return appropriate entry/value/port
*/

receivePacket(char * message)
{
    /*call upon receiving a packet
    
    if(dest != myPort) {
            calculate IP checksum
            decrement TTL
            do any other necessary header changes and such
            referenceTable() - get necessary information
            send(header, packet)
    }
    else {
            if IP protocol field = 200
                    if command = 1
                            sendUpdate(request source)
                    else if command =2
                            read and updateTable(entry)
            else
                    print packet contents
                    */
    }
    
/* updateTable ()
        replaces or adds entry if better distance
        updates timestamp to now
*/

int send_packet(char * dest_addr, char * payload, int send_socket, uint8_t TTL, uint8_t protocol, entry_t * entry_pointer){
    char packet[MAX_MSG_LENGTH];
    char * mes;
    struct iphdr * ip;
    struct sockaddr_in send_addr;
    ifentry_t ifentry;

    * entry_pointer = extractNextHopFromVIP(dest_addr);
    ifentry = extractIfEntryFromPort(entry_pointer->port);

    if(entry_pointer->interface_id <=0){
        printf("failed to send: intended recipient not in table\n");
        return -1;
    }

    ip = (struct iphdr*) packet;

    ip->check       = 0; // so that checksum will be calculated properly
    ip-> ihl        = (unsigned int) sizeof(struct iphdr) / 4; // 4 bytes to a word, ihl stores number of words in header
    ip->version     = 4;
    ip->tot_len     = ip->ihl * 4 + strlen(payload);
    ip->protocol    = protocol;
    ip->ttl         = TTL;
    ip->saddr       = inet_addr(entry_pointer->my_vip);
    ip->daddr       = inet_addr(entry_pointer->interface_vip);
    ip->check       = ip_sum((char * )ip, ip->ihl * 4);

    printf("ipsum: %d\n", ip->check);

    mes = (char *)(packet + ip->ihl * 4); // use the header length parameter to offset the packet
    strcpy(mes, payload); // copy the payload from into the packet

    send_addr.sin_addr.s_addr = inet_addr(entry_pointer->interface_ip);
    send_addr.sin_family = AF_INET;
    send_addr.sin_port = htons(entry_pointer->port);

    if (sendto(send_socket, packet, ip->tot_len, 0, (struct sockaddr*) &send_addr, sizeof(send_addr))==-1) {
        perror("failed to send message");
        return -1;
    }

    return 0;
}

int receive_packet(int rec_socket, int send_socket){
    char recv_packet[MAX_READIN_BUFFER];
    char * payload;
    char dest_addr[20];
    struct iphdr * recv_ip;
    struct sockaddr_in sa;
    entry_t * nextHop;
    int calculated_check, received_check;

    recv(rec_socket, recv_packet, MAX_READIN_BUFFER, 0);

    recv_ip = (struct iphdr*) recv_packet;
    payload = (char *)(recv_packet + recv_ip->ihl * 4);

    received_check = recv_ip->check;
    recv_ip->check = 0;
    calculated_check  = ip_sum((char *) recv_ip, recv_ip->ihl * 4);

    if(received_check != calculated_check){ // the checksums don't match, drop packet
        printf("Checksums don't match (%d, %d), dropping packet\n", calculated_check, received_check);
        return -1;
    }

    // check protocol to see if this is RIP or test send message
    if(recv_ip->protocol == TEST_PROTOCOL){
        inet_ntop(AF_INET, &(recv_ip->daddr), dest_addr, INET_ADDRSTRLEN); // store string representation of the address in dest_addr

        if(isMe(dest_addr)<0){ // not in the table, need to forward
            send_packet(dest_addr, payload, send_socket, (recv_ip->ttl) - 1, recv_ip->protocol, nextHop); // decrement ttl by 1, nextHop currently unused
        }
        else{
            printf("message: %s\n", payload);
        }
    }
    else if(recv_ip->protocol == RIP_PROTOCOL){
        // TODO: Leevi, fill this out
    }
    else{ // unknown protocol
        printf("received packet with unknown protocol, value: %d\n", (int)recv_ip->protocol);
    }
    return 0;
}

sendUpdate(char * interface_vip, int send_socket) {
    // char packet[];
    
    // look up entry in table
    //entry_t * entry_pointer;
    //* entry_pointer = extractNextHopFromVIP(interface_vip, table);
    
    // entry_pointer ->
    
    rip_msg_t * payload; // sizeof or instantiation sizeof(rip_msg)
    
    payload -> command = 2;
    
    //link_entry_table
    
    // iterate (set cost, address)
    // if table source = destination set route metric to infinity (16)
    // rip_msg -> entries[0]
    //    rip_msg -> num_entries ++
    
    // TODO: test void pointer
    entry_t * nextHop;
    send_packet(interface_vip, (char *) payload, send_socket, MAX_DISTANCE, RIP_PROTOCOL, nextHop);
}

int setUpPort(uint16_t port, struct sockaddr_in server_addr)
{
    int sock, in_sock;
                
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) { // SOCK_DGRAM for UDP, and IPROTO_UDP?
        perror("Create socket error");
        return -1;
    }

    printf("Socket created\n");

    if ((bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr))) < 0) {
         perror("Bind error:");
         return -1;
    }
    
    printf("bind done\n");
    
    listen(sock, MAX_BACK_LOG);
    printf("listen done, waiting for connection\n");
    
    return sock;
}

int listenOn(uint16_t port) {
    // start up new thread to listen for incoming messages
    int sock, in_sock;
    int len;
    struct sockaddr_in server_addr;
    char msg[MAX_MSG_LENGTH];
    char addr[len];

    bzero((char *)&server_addr, sizeof(server_addr));
    server_addr.sin_addr.s_addr = INADDR_ANY; // set to myIP?
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) { // SOCK_DGRAM for UDP
        perror("Create socket error:");
        return -1;
    }

    printf("Socket created\n");

    if ((bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr))) < 0) {
         perror("Bind error:");
         return -1;
    }
    
    printf("bind done\n");

    return sock;
}

int populate_entry_table(FILE * ifp){
    int id;
    char nextDescrip[80], myVIP[80], remoteVIP[80];
    char * nextIP;
    uint16_t nextPort;

    id = 0; // because oddly the assignment specifies the first element as id 1, not id 0
    while(!feof(ifp)){
        id++;

        fscanf(ifp, "%s %s %s", nextDescrip, myVIP, remoteVIP);
        fprintf(stdout, "next: %s\n", nextDescrip);
        
        nextIP = strtok (nextDescrip,":");
        if(strcmp(nextIP, "localhost")==0) strcpy(nextIP, LOCALHOST_IP);
        nextPort = atoi(strtok (NULL,": "));

        printf("nextIP: %s, nextPort: %d\n  myVIP: %s, remoteVIP: %s\n", nextIP, (int) nextPort, myVIP, remoteVIP);

        // initialize the routing table
        link_entry_table[id-1].distance = MAX_DISTANCE;
        link_entry_table[id-1].interface_id = id;
        link_entry_table[id-1].port = nextPort;
        strcpy(link_entry_table[id-1].interface_ip, nextIP);
        strcpy(link_entry_table[id-1].interface_vip, remoteVIP);
        strcpy(link_entry_table[id-1].my_vip, myVIP);
        link_entry_table[id-1].status = "up";

        // initialize the ifconfig table
        ifconfig_table[id-1].interface_id = id;
        ifconfig_table[id-1].port = nextPort;
        strcpy(ifconfig_table[id-1].interface_ip, nextIP);
        strcpy(ifconfig_table[id-1].interface_vip, remoteVIP);
        strcpy(ifconfig_table[id-1].my_vip, myVIP);
        ifconfig_table[id-1].status = "up";
        ifconfig_table[id-1].mtu_size = 0; // default, no mtu value
    }
}

int handle_commands(char * cmd, int send_socket){
    char sendAddress[40], message[MAX_MSG_LENGTH], c;
    entry_t extracted_entry;

    if(strcmp("ifconfig", cmd)==0){
        print_ifconfig();
    }
    else if(strcmp("send", cmd)==0){
        scanf("%s %[^\n]s", sendAddress, message);
        send_packet(sendAddress, message, send_socket, MAX_DISTANCE, TEST_PROTOCOL, &extracted_entry);
        printf("sent to: %s, port %d, message: %s\n", extracted_entry.interface_vip, extracted_entry.port, message);
    }
    else if(strcmp("mtu", cmd)==0){ // extra credit
        int link_int, mtu_size;
        scanf("%d %d", &link_int, &mtu_size);
        ifconfig_table[link_int-1].mtu_size = mtu_size;
        printf("mtu for link %d set to %d\n", link_int, mtu_size);
    }
    else if(strcmp("down", cmd)==0){
        int id;
        scanf("%d", &id);
        ifconfig_table[id-1].status = "down";
    }
    else if(strcmp("up", cmd)==0){
        int id;
        scanf("%d", &id);
        ifconfig_table[id-1].status = "up";
    }
    else{
        printf("not a valid command: %s\n", cmd);
    }
    while ((c = getchar()) != '\n' && c != EOF); // clears the stdin buffer if there's anything left
}

int initialize_from_file(char * file_name){
    FILE *ifp;

    printf("file name: %s\n", file_name);

    if ((ifp = fopen(file_name, "rt")) == NULL) {
        printf("Can't open input file\n");
        exit(1);
    }

    char myDescrip[80];
    char * myIP;
    uint16_t myPort;

    // reads in addr:port and splits
    fscanf(ifp, "%s", myDescrip);
    printf("%s\n", myDescrip);
    myIP = strtok (myDescrip,":");
    myPort = atoi(strtok (NULL,": "));

    printf("myIP: %s\nmyPort: %d\n", myIP, (int) myPort);
    
    populate_entry_table(ifp);

    return myPort;

}

int initialize_recieve_socket(int myPort, fd_set * active_fd_set){
    int rec_socket;

    rec_socket = listenOn(myPort);
    FD_SET (rec_socket, active_fd_set);

    if ( fcntl( rec_socket,  F_SETFL,  O_NONBLOCK, 1) == -1 ) { 
        printf( "failed to set non-blocking\n" ); 
        return -1; 
    }

    printf("receive socket: %d, set to non-blocking UDP\n\n", rec_socket);

    return rec_socket;
}

int main(int argc, char ** argv)
{
        /* argv[1] is file name
        /* open up using file descriptor
        /* read first line of file and set as myPort, call listenOn(myPort) */
        /* while other lines in file, read and set up link file/create interfaces implemented by UDP socket (call method setUpPort(port) */
        
        /* send request message (RIP command: 1) to all links in link table
        
        /* wait for user commands */
        /* wait for 5 second timeouts
                on 5 second timeout call sendUpdate to every active ('up') link in table
                */
     
        /* if (ifconfig)  etc.*/

    int rec_socket, send_socket, myPort;
    fd_set active_fd_set, read_fd_set;
    fd_set * active_set_ptr;

    active_set_ptr = & active_fd_set;

    FD_ZERO (&active_fd_set);
    FD_SET (0, &active_fd_set);

    myPort = initialize_from_file(argv[1]);

    // creates the rec_socket, sets it to be non-blocking UDP
    rec_socket = initialize_recieve_socket(myPort, active_set_ptr);

    print_ifconfig();
    printf("\n");

    // Set up send socket
    if ((send_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1){ // not sure what IPPROTO_UDP is
        perror("send socket error");
        exit(EXIT_FAILURE);
    }

    char cmd[40];

    while(1){
        printf("\nwaiting for input from the user or socket...\n");

        read_fd_set = active_fd_set;
        if (select (FD_SETSIZE, &read_fd_set, NULL, NULL, NULL) < 0){ // 3rd NULL, no timeout in this example
            perror ("select error");
            exit (EXIT_FAILURE);
        }

        // select says there's data, go through all open file descriptors and update
        if (FD_ISSET (0, &read_fd_set)){ // data ready on stdin (0)
            scanf("%s", cmd);
            handle_commands(cmd, send_socket);
        }
        if (FD_ISSET (rec_socket, &read_fd_set)){ // data ready on the read socket
            receive_packet(rec_socket, send_socket);
        }
    }
}