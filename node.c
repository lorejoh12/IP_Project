#include <netinet/ip.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/time.h>

#include "ipsum.h"

#define MAX_MSG_LENGTH (1400)
#define MAX_BACK_LOG (5)
#define MAX_READIN_BUFFER (64 * 1024)

#define INFINITY 16

#define LOCALHOST_IP "127.0.0.1"

#define RIP_PROTOCOL 200
#define TEST_PROTOCOL 0
#define DEFAULT_IP_HEADER_SIZE 5

/* table of table entries */
/* table of link interfaces along with their status (up or down) */
/* uint16_t myPort */
/* socket mySocket */
typedef struct route_entry
{
    char source_vip[20]; // where we learned the route from
    int distance; // distance to destination
    int interface_id; // where to go next
    char destination_vip[20]; // the "virtual" IP address of the ultimate destination
    time_t last_updated; // last time this entry was updated
} route_entry_t;

typedef struct ifconfig_entry
{
    int interface_id;
    int mtu_size;
    uint16_t port; // the actual port to send to
    char interface_ip[20]; // the actual IP address of the connection
    char interface_vip[20]; // the given "virtual" IP address of the connection
    char my_vip[20]; // the "virtual" IP address that they have for this node
    char * status; // up or down
} if_entry_t;

typedef struct routing_table
{
    int num_entries;
    route_entry_t route_entries[100];
} routing_table_t;

typedef struct ifconfig_table
{
    int num_entries;
    if_entry_t ifconfig_entries[100];
} ifconfig_table_t;

routing_table_t ROUTING_TABLE;
ifconfig_table_t IFCONFIG_TABLE;
int NODE_DF = 0;

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

/*
* Prints ifconfig method
*/
print_ifconfig(){
    if_entry_t * ifconfig_entries = IFCONFIG_TABLE.ifconfig_entries;
    
    int i;
    printf("printing ifconfig:\n");
    for(i = 0; i < IFCONFIG_TABLE.num_entries; i += 1){
        if_entry_t e = ifconfig_entries[i];
        printf("%d %s %s\n", e.interface_id, e.interface_vip, e.status);
    }
}

/*
* Return pointer to relevant route entry
*/
route_entry_t * get_route_entry(char * destination_vip){
    refresh_routes();
    route_entry_t * route_entries = ROUTING_TABLE.route_entries;
    
    int i;
    for(i = 0; i < ROUTING_TABLE.num_entries; i +=1){
        route_entry_t e = route_entries[0];
        if(strcmp(destination_vip, e.destination_vip)==0) return (route_entry_t *) route_entries;
        
        route_entries++;
    }
    return NULL;
}

/*
* Return pointer to relevant if entry
*/
if_entry_t * extractIfEntryFromVIP(char * interface_vip){
    if_entry_t * ifconfig_entries = IFCONFIG_TABLE.ifconfig_entries;

    int i;
    for(i = 0; i < IFCONFIG_TABLE.num_entries; i += 1){
        if_entry_t e = ifconfig_entries[0];
        if(strcmp(e.interface_vip, interface_vip)==0) return ifconfig_entries;
        
        ifconfig_entries++;
    }
    return NULL;
}

print_routes(){
    refresh_routes();
    route_entry_t * route_entries = ROUTING_TABLE.route_entries;
    printf("Route Entries:\n");
    printf("Destination\tif_ID\tDistance\n");
    int i;
    for(i = 0; i < ROUTING_TABLE.num_entries; i += 1){
        route_entry_t e = route_entries[i];

        printf("%s\t%d\t%d\n", e.destination_vip, e.interface_id, e.distance);
    }
}

int isMe(char * vip){
    if_entry_t * ifconfig_entries = IFCONFIG_TABLE.ifconfig_entries;
    
    int i;
    for(i = 0; i < IFCONFIG_TABLE.num_entries; i +=1){
        if_entry_t e = ifconfig_entries[i];
        if(strcmp(vip, e.my_vip)==0) return 1;
    }
    return -1;
}

refresh_routes() {
    route_entry_t * route_entries = ROUTING_TABLE.route_entries;
    
    int i;
    for(i = 0; i < ROUTING_TABLE.num_entries; i += 1){
        if ((int) time(NULL) - (int) route_entries -> last_updated > 12 & route_entries -> distance > 0) {
            route_entries -> distance = 16; // entry expired
        }    
        route_entries++;
    }
}

update_routes (char * source_vip, char * next_vip, uint32_t cost, uint32_t address){
    char dest_addr[20];
    inet_ntop(AF_INET, &(address), dest_addr, INET_ADDRSTRLEN);
    route_entry_t * route_entries = ROUTING_TABLE.route_entries;
    route_entry_t * e = get_route_entry(dest_addr); // can be null
    
    if_entry_t * ifentry = extractIfEntryFromVIP(next_vip);
    int entryID = ROUTING_TABLE.num_entries;
    
    if(e == NULL){
        if(ifentry == NULL)
            route_entries[entryID].interface_id = -1;
        else
            route_entries[entryID].interface_id = ifentry -> interface_id;
        
        strcpy(route_entries[entryID].source_vip, source_vip);
        route_entries[entryID].distance = cost + 1;
        strcpy(route_entries[entryID].destination_vip, dest_addr);
        route_entries[entryID].last_updated = time(NULL); 
        ROUTING_TABLE.num_entries++;
    }
    else if(e -> distance > (cost + 1)) {
        strcpy(e -> source_vip, source_vip);
        e -> interface_id = ifentry -> interface_id;
        e -> distance = cost + 1;
        e -> last_updated = time(NULL);
    }   
    else if(strcmp(e -> destination_vip, dest_addr) == 0 & (e -> distance == (cost + 1))){
        e -> last_updated = time(NULL);
    }
}

send_packet_raw(int send_socket, char * payload, struct iphdr * ip, char * packet, struct sockaddr_in send_addr, int size, if_entry_t * entry){
    char * mes;

    mes = (char *)(packet + ip->ihl * 4); // use the header length parameter to offset the packet
    memcpy(mes, payload, size); // copy the rest of the payload into the packet

    send_addr.sin_addr.s_addr = inet_addr(entry -> interface_ip);
    send_addr.sin_family = AF_INET;
    send_addr.sin_port = htons(entry -> port);

    if (sendto(send_socket, packet, ip->tot_len, 0, (struct sockaddr*) &send_addr, sizeof(send_addr))==-1) {
        perror("failed to send message");
        return -1;
    }
}

int send_packet(char * dest_addr, char * payload, int payload_size, int send_socket, int node_DF, 
                uint8_t TTL, uint8_t protocol, int header_size){

    char packet[MAX_MSG_LENGTH];
    char * mes;
    struct iphdr * ip;
    struct sockaddr_in send_addr;
    if_entry_t * ifentry;
    uint16_t frag;
    int total_size;
    route_entry_t * entry_pointer;
    
    entry_pointer = get_route_entry(dest_addr);
    
    if(entry_pointer == NULL | entry_pointer->distance == INFINITY){
        printf("failed to send: destination address unknown: addr %s\n", dest_addr);
        return -1;
    }

    ifentry = extractIfEntryFromVIP(entry_pointer->destination_vip);

    if(ifentry == NULL){
        printf("failed to send: intended recipient not in table\n");
        return -1;
    }

    memset(&packet[0], 0, sizeof(packet));

    ip = (struct iphdr*) packet;

    ip-> ihl        = header_size; // 4 bytes to a word, ihl stores number of words in header
    ip-> id         = rand(); // 
    ip->version     = 4;
    ip->protocol    = protocol;
    ip->ttl         = TTL;
    ip->saddr       = inet_addr(ifentry -> my_vip);
    ip->daddr       = inet_addr(entry_pointer->destination_vip);

    total_size = header_size * 4 + payload_size;
    int payload_size_fragmented = (ifentry -> mtu_size - header_size*4);

    uint16_t DF_fragment = node_DF ? IP_DF : 0;
    int fragment_i = 0;

    while(ifentry -> mtu_size > 0 && total_size > ifentry -> mtu_size){ // need to fragment
        ip->check       = 0;
        ip->tot_len     = ip->ihl * 4 + payload_size_fragmented;

        if(node_DF){
            printf("fragmentation failed, DF = 1\n");
            return -1;
        }
        uint16_t MF_fragment;
        MF_fragment = IP_MF;
        ip->frag_off = fragment_i * payload_size_fragmented + MF_fragment;
        ip->check = ip_sum((char * )ip, ip->ihl * 4);

        send_packet_raw(send_socket, payload, ip, packet, send_addr, payload_size_fragmented, ifentry);

        payload = payload + payload_size_fragmented;
        total_size -= payload_size_fragmented;
        fragment_i ++;
    }

    ip->tot_len         = ip->ihl * 4 + payload_size - fragment_i*payload_size_fragmented;
    ip->check           = 0;
    ip->frag_off        = DF_fragment + fragment_i * payload_size_fragmented;
    ip->check           = ip_sum((char * )ip, ip->ihl * 4);

    send_packet_raw(send_socket, payload, ip, packet, send_addr, ip->tot_len, ifentry);

    return 0;
}

char fragment_buffer[MAX_READIN_BUFFER];
int fragment_id;
int fragmenting = 0;

int receive_packet(int rec_socket, int send_socket){
    char recv_packet[MAX_READIN_BUFFER];
    char payload[MAX_READIN_BUFFER];
    char * recv_payload;
    char dest_addr[20];
    struct iphdr * recv_ip;
    struct sockaddr_in sa;
    int calculated_check, received_check;

    memset(&recv_packet[0], 0, sizeof(recv_packet)); // clear the recv buffer for new incoming messages

    recv(rec_socket, recv_packet, MAX_READIN_BUFFER, 0);

    recv_ip = (struct iphdr*) recv_packet;
    recv_payload = (char *)(recv_packet + recv_ip->ihl * 4);

    received_check = recv_ip->check;
    recv_ip->check = 0;
    calculated_check  = ip_sum((char *) recv_ip, recv_ip->ihl * 4);

    if(received_check != calculated_check){ // the checksums don't match, drop packet
        printf("Checksums don't match (%d, %d), dropping packet\n", calculated_check, received_check);
        return -1;
    }

    if((recv_ip->frag_off & IP_MF) == IP_MF){ // receiving more fragments, pass into the buffer and do nothing
        printf("got an IP_MF\n");
        memcpy(fragment_buffer + (recv_ip->frag_off & IP_OFFMASK), recv_payload, MAX_READIN_BUFFER);
        fragmenting = 1;
        return 0;
    }

    if(fragmenting){
        memcpy(fragment_buffer + (recv_ip->frag_off & IP_OFFMASK), recv_payload, MAX_READIN_BUFFER);
        memcpy(payload, fragment_buffer, MAX_READIN_BUFFER);
    }
    else
        memcpy(payload, recv_payload, MAX_READIN_BUFFER);
    
    fragmenting = 0;

    // check protocol to see if this is RIP or test send message
    if(recv_ip->protocol == TEST_PROTOCOL){
        inet_ntop(AF_INET, &(recv_ip->daddr), dest_addr, INET_ADDRSTRLEN); // store string representation of the address in dest_addr

        if(isMe(dest_addr)<0){ // not in the table, need to forward
            int df_bit = (recv_ip->frag_off & IP_DF) == IP_DF;
            send_packet(dest_addr, payload, strlen(payload), send_socket, df_bit, (recv_ip->ttl) - 1, recv_ip->protocol, recv_ip->ihl); // decrement ttl by 1
        }
        else{
            printf("message: %s\n", payload);
        }
    }
    else if(recv_ip->protocol == RIP_PROTOCOL){
        rip_msg_t * rip_msg = (rip_msg_t*) payload;
        inet_ntop(AF_INET, &(recv_ip->saddr), dest_addr, INET_ADDRSTRLEN);
        if(rip_msg -> command == 1) {
            send_update(dest_addr, send_socket);
        }
        else if(rip_msg -> command == 2){
            int i;
            for(i = 0; i < rip_msg -> num_entries; i += 1){
                update_routes(dest_addr, dest_addr, rip_msg -> entries[i].cost, rip_msg -> entries[i].address);
            }
        }
    }
    else{ // unknown protocol
        printf("received packet with unknown protocol, value: %d\n", (int)recv_ip->protocol);
    }
    return 0;
}

int send_update(char * destination_vip, int send_socket) {

    rip_msg_t * payload = malloc(sizeof(rip_msg_t)); // sizeof or instantiation sizeof(rip_msg)
    
    payload -> command = 2;
    
    payload -> num_entries = ROUTING_TABLE.num_entries;
    route_entry_t * route_entries = ROUTING_TABLE.route_entries;
    
    int i;
    for(i = 0; i < ROUTING_TABLE.num_entries; i +=1){
        route_entry_t e = route_entries[i];
        
        payload -> entries[i].address = inet_addr(e.destination_vip);
        if(strcmp(destination_vip, e.source_vip)==0){
            payload -> entries[i].cost = INFINITY - 1;
        }
        else {
            payload -> entries[i].cost = e.distance;
        }
    }
    
    return send_packet(destination_vip, (char *) payload, sizeof(rip_msg_t), send_socket, NODE_DF, INFINITY, RIP_PROTOCOL, DEFAULT_IP_HEADER_SIZE);
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

int request_routes(int send_socket){    
    if_entry_t * ifconfig_entries = IFCONFIG_TABLE.ifconfig_entries;
    int i;
    for(i = 0; i < IFCONFIG_TABLE.num_entries; i += 1){  
        if_entry_t e = ifconfig_entries[i];
    
        rip_msg_t * payload = malloc(sizeof(rip_msg_t)); // sizeof or instantiation sizeof(rip_msg)
        payload -> command = 1;
        payload -> num_entries = 0;
        
        return send_packet(e.interface_vip, (char *) payload, sizeof(rip_msg_t), send_socket, NODE_DF, INFINITY, RIP_PROTOCOL, DEFAULT_IP_HEADER_SIZE);
    }
}

int populate_entry_table(FILE * ifp){
    int id;
    char nextDescrip[80], myVIP[80], remoteVIP[80];
    char * nextIP;
    uint16_t nextPort;
     route_entry_t * route_entries = ROUTING_TABLE.route_entries;
    if_entry_t * ifconfig_entries = IFCONFIG_TABLE.ifconfig_entries;
    
    id = 0; // because oddly the assignment specifies the first element as id 1, not id 0
    while(!feof(ifp)){
        id++;

        fscanf(ifp, "%s %s %s", nextDescrip, myVIP, remoteVIP);
        fprintf(stdout, "next: %s\n", nextDescrip);
        
        nextIP = strtok (nextDescrip,":");
        if(strcmp(nextIP, "localhost")==0) strcpy(nextIP, LOCALHOST_IP);
        nextPort = atoi(strtok (NULL,": "));

        printf("nextIP: %s, nextPort: %d\n  myVIP: %s, remoteVIP: %s\n", nextIP, (int) nextPort, myVIP, remoteVIP);

        
        // initialize the ifconfig table
        ifconfig_entries[id-1].interface_id = id;
        ifconfig_entries[id-1].port = nextPort;
        strcpy(ifconfig_entries[id-1].interface_ip, nextIP);
        strcpy(ifconfig_entries[id-1].interface_vip, remoteVIP);
        strcpy(ifconfig_entries[id-1].my_vip, myVIP);
        ifconfig_entries[id-1].status = "up";
        ifconfig_entries[id-1].mtu_size = 0;
        IFCONFIG_TABLE.num_entries++;
        
        // initialize the routing table  
        update_routes (LOCALHOST_IP, remoteVIP, 0, inet_addr(remoteVIP));
        update_routes (LOCALHOST_IP, LOCALHOST_IP, -1, inet_addr(myVIP));
    }
}

int handle_commands(char * cmd, int send_socket){
    char sendAddress[40], message[MAX_MSG_LENGTH], c;
    if_entry_t * ifconfig_entries = IFCONFIG_TABLE.ifconfig_entries;

    if(strcmp("ifconfig", cmd)==0){
        print_ifconfig();
    }
    else if(strcmp("send", cmd)==0){
        scanf("%s %[^\n]s", sendAddress, message);
        send_packet(sendAddress, message, strlen(message), send_socket, NODE_DF, INFINITY, TEST_PROTOCOL, DEFAULT_IP_HEADER_SIZE);
    }
    else if(strcmp("mtu", cmd)==0){ // extra credit
        int link_int, mtu_size;
        scanf("%d %d", &link_int, &mtu_size);
        ifconfig_entries[link_int-1].mtu_size = mtu_size;
        printf("mtu for link %d set to %d\n", link_int, mtu_size);
    }
    else if(strcmp("down", cmd)==0){
        int id;
        scanf("%d", &id);
        ifconfig_entries[id-1].status = "down";
        route_entry_t * route_entry = get_route_entry(ifconfig_entries[id-1].my_vip);
        route_entry -> distance = 16;
        trigger_update();
    }
    else if(strcmp("up", cmd)==0){
        int id;
        scanf("%d", &id);
        ifconfig_entries[id-1].status = "up";
        route_entry_t * route_entry = get_route_entry(ifconfig_entries[id-1].my_vip);
        route_entry -> distance = 0;
        trigger_update();
    }
    else if(strcmp("routes", cmd)==0){
        print_routes();
    }
    else if(strcmp("dfset", cmd)==0){
        NODE_DF = 1;
        printf("DF bit on all messages set to 1\n");
    }
    else if(strcmp("dfoff", cmd)==0){
        NODE_DF = 0;
        printf("DF bit on all messages set to 0\n");
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

trigger_update(int send_socket){
    if_entry_t * ifconfig_entries = IFCONFIG_TABLE.ifconfig_entries;
    
    int i;
    for(i = 0; i < IFCONFIG_TABLE.num_entries; i += 1){  
        if_entry_t e = ifconfig_entries[i];
        
        if(strcmp(e.status, "up") == 0)
            send_update(e.interface_vip, send_socket);
    }
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
    
    request_routes(send_socket);
    char cmd[40];
    printf("Ready for user input:\n");

    while(1){

        read_fd_set = active_fd_set;
        
        struct timeval timeout = {5, 0};   // 5 second timeout
        
        if (select (FD_SETSIZE, &read_fd_set, NULL, NULL, &timeout) < 0){ 
            perror ("select error");
            exit (EXIT_FAILURE);
        }

        // select says there's data, go through all open file descriptors and update
        if (FD_ISSET (0, &read_fd_set)){ // data ready on stdin (0)
            scanf("%s", cmd);
            handle_commands(cmd, send_socket);
            printf("\nReady for user input:\n");
        }
        else if (FD_ISSET (rec_socket, &read_fd_set)){ // data ready on the read socket
            receive_packet(rec_socket, send_socket);
        }
        else {
            trigger_update(send_socket);
        }
    }
}