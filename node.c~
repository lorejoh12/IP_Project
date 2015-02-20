#include <netinet/ip.h>

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

#define MAX_MSG_LENGTH (1400)
#define MAX_BACK_LOG (5)
#define MAX_READIN_BUFFER (64 * 1024)

#define MAX_DISTANCE 16

#define LOCALHOST_IP "127.0.0.1"

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

entry_t link_entry_table[100]; // I'm tired of trying to do this correctly

/* RIP HEADER

uint16_t command;
uint16_t num_entries;
struct {
uint32_t cost;
uint32_t address;
} entries[num_entries];
*/

/* 
IP packet header in ip.h
*/


printTable(entry_t * table){
  int i;
  printf("printing table:\n");
  for(i = 0; ; i += 1){
    entry_t e = table[i];
    if(e.interface_id == 0) break;
    printf("%d %s %s\n", e.interface_id, e.interface_vip, e.status);
  }
}

// gets the table entry in the router from the VIP provided
entry_t extractNextHopFromVIP(char * interface_vip, entry_t * table){
  entry_t NullStruct = { MAX_DISTANCE, -1, -1, "", "", "" };
  if(interface_vip == NULL) return NullStruct;
  int i;
  for(i = 0; ; i +=1){
    entry_t e = table[i];
    if(strcmp(interface_vip, e.interface_vip)==0) return e;
    if(e.interface_id <= 0) break;
  }
  return NullStruct;
}
/* example code   
bool builtin_cmd(job_t *last_job, int argc, char **argv) {
   if (!strcmp(argv[0], "quit")) {
	  close(flog);
	  exit(EXIT_SUCCESS);
   }
   else if (!strcmp("jobs", argv[0])) {
      job_t *curJob;
      job_t *prevJob = joblist;
      for(curJob = joblist->next; curJob; curJob = curJob->next) {
         char* jobStatus = malloc(12*sizeof(char));
         
         if(job_is_completed(curJob)) jobStatus = "Completed";
         else if(job_is_stopped(curJob)) jobStatus = "Stopped";	
         else jobStatus = "Running";

         fprintf(stdout, "%d(%s): %s\n", curJob->pgid, jobStatus, curJob->commandinfo); 
         
         if(job_is_completed(curJob)) {
            delete_job(curJob, joblist);
            curJob = prevJob;
         }
         else {
            prevJob = curJob;
         }
      }
   }
   else if (!strcmp("cd", argv[0])) {
      chdir(argv[1]);
   }
   else if (!strcmp("bg", argv[0])) {
   }
   else if (!strcmp("fg", argv[0])) {
      if(argc > 1) {
         job_t *curJob;
         for(curJob = joblist->next; curJob; curJob = curJob->next) {
            char* str = malloc(15*sizeof(char));
            sprintf(str, "%d", (int) curJob -> pgid);
            if(strcmp(argv[1], str) == 0) {
               continue_job(curJob);
                     
               delete_job(last_job, joblist);
               return true;
            }
         }
      }
      
      job_t *curJob;
      job_t *lastStopped = malloc(sizeof(job_t));
      bool stoppedProcess;
      for(curJob = joblist->next; curJob; curJob = curJob->next) {
         if(job_is_stopped(curJob)) {
            lastStopped = curJob;
            stoppedProcess = true;
         }
      }
      
      if(stoppedProcess) {
         continue_job(lastStopped);
      }
      else {
         fputs("No stopped jobs to resume \n",stderr);
         printf("No stopped jobs to resume \n");
      }
   }
   else {
      return false;
   }
   
   delete_job(last_job, joblist);
   return true;
}
*/

/* sendUpdate(destination) 
    if table source = destination set route metric to infinity (16)
*/

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

/*
Edit this method to just send a message out of a socket with the input header and packet contents
int send(uint16_t outport, header, contents)
Also, change socket(PARAMS) to UDP instead of TCP

int client(const char * addr, uint16_t port)
{
	int sock;
	struct sockaddr_in server_addr;
	char msg[MAX_MSG_LENGTH], reply[MAX_REPLY_LENGTH];

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Create socket error:");
		return 1;
	}

	printf("Socket created\n");
	server_addr.sin_addr.s_addr = inet_addr(addr);
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);

	if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
		perror("Connect error:");
		return 1;
	}

	printf("Connected to server %s:%d\n", addr, port);

	int recv_len = 0;
	while (1) {
		fflush(stdin);
		printf("Enter message: \n");
		gets(msg);
		if (send(sock, msg, MAX_MSG_LENGTH, 0) < 0) {
			perror("Send error:");
			return 1;
		}
		recv_len = read(sock, reply, MAX_REPLY_LENGTH);
		if (recv_len < 0) {
			perror("Recv error:");
			return 1;
		}
		reply[recv_len] = 0;
		printf("Server reply:\n%s\n", reply);
		memset(reply, 0, sizeof(reply));
	}
	close(sock);
	return 0;
}
*/

int setUpPort(uint16_t port, struct sockaddr_in server_addr)
{
  int sock, in_sock;
        
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
  /*
  while(1) {
    
      inet_ntop(AF_INET, &(server_addr.sin_addr), addr, len);
      memset(msg, 0, MAX_MSG_LENGTH);
      
      msg[MAX_MSG_LENGTH] = '\0';
      
      while (len = recv(sock, msg, MAX_MSG_LENGTH, 0)) {
        receivePacket(msg);
        printf("recv from client: %s\n", msg);
        sprintf(reply, "%s%s%s", msg, msg, msg);
        send(in_sock, reply, strnlen(reply, MAX_REPLY_LENGTH), 0);
        
        memset(msg, 0, MAX_MSG_LENGTH);

        int nonBlocking = 1; 
        if ( fcntl( handle,  F_SETFL,  O_NONBLOCK,  nonBlocking ) == -1 ) { 
          printf( "failed to set non-blocking\n" ); 
          return false; 
        }

      }
      
      close(in_sock);
      printf("client disconnected\n");
      exit(0);
    }
    
    
    close(in_sock); */
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

  FILE *ifp;
  int rec_socket, send_socket, len;
  char msg[MAX_MSG_LENGTH];
  fd_set active_fd_set, read_fd_set;

  FD_ZERO (&active_fd_set);
  FD_SET (0, &active_fd_set);

  // test
  printf("file name: %s\n", argv[1]);

  if ((ifp = fopen(argv[1], "rt")) == NULL) {
    printf("Can't open input file\n");
    exit(1);
  }

  char myDescrip[80], nextDescrip[80], myVIP[80], remoteVIP[80];
  char * myIP, * nextIP;
  uint16_t myPort, nextPort;
  int id;

  // reads in addr:port and splits
  fscanf(ifp, "%s", myDescrip);
  printf("%s\n", myDescrip);
  myIP = strtok (myDescrip,":");
  myPort = atoi(strtok (NULL,": "));

  // creates the rec_socket, sets it to be non-blocking UDP
  rec_socket = listenOn(myPort);
  FD_SET (rec_socket, &active_fd_set);

  int nonBlocking = 1; 
  if ( fcntl( rec_socket,  F_SETFL,  O_NONBLOCK,  nonBlocking ) == -1 ) { 
    printf( "failed to set non-blocking\n" ); 
    return -1; 
  }

  printf("receive socket: %d, set to non-blocking UDP\n\n", rec_socket);

  printf("myIP: %s\nmyPort: %d\n", myIP, (int) myPort);
  id = 0; // because oddly the assignment specifies the first element as id 1, not id 0
  while(!feof(ifp)){
    id++;

    fscanf(ifp, "%s %s %s", nextDescrip, myVIP, remoteVIP);
    fprintf(stdout, "next: %s\n", nextDescrip);
    
    nextIP = strtok (nextDescrip,":");
    if(strcmp(nextIP, "localhost")==0) strcpy(nextIP, LOCALHOST_IP);
    nextPort = atoi(strtok (NULL,": "));

    printf("nextIP: %s, nextPort: %d\n  myVIP: %s, remoteVIP: %s\n", nextIP, (int) nextPort, myVIP, remoteVIP);

    link_entry_table[id-1].distance = MAX_DISTANCE;
    link_entry_table[id-1].interface_id = id;
    link_entry_table[id-1].port = nextPort;
    strcpy(link_entry_table[id-1].interface_ip, nextIP);
    strcpy(link_entry_table[id-1].interface_vip, remoteVIP);
    strcpy(link_entry_table[id-1].my_vip, myVIP);
    link_entry_table[id-1].status = "up";
  }

  printTable(link_entry_table);
  printf("\n");


  // Set up send socket
  if ((send_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1){ // not sure what IPPROTO_UDP is
    perror("send socket error");
    exit(EXIT_FAILURE);
  }

  char c;
  char cmd[40], sendAddress[40], message[MAX_MSG_LENGTH];
  struct sockaddr_in send_addr;
  int sendPort;

  while(1){
    printf("waiting for input from the user or socket...\n");

    read_fd_set = active_fd_set;
    if (select (FD_SETSIZE, &read_fd_set, NULL, NULL, NULL) < 0){ // 3rd NULL, no timeout in this example
      perror ("select error");
      exit (EXIT_FAILURE);
    }

    // select says there's data, go through all open file descriptors and update
    if (FD_ISSET (0, &read_fd_set)){
      scanf("%s", cmd);
      if(strcmp("ifconfig", cmd)==0){
        printTable(link_entry_table);
      }
      else if(strcmp("send", cmd)==0){
        scanf("%s %[^\n]s", sendAddress, message);

        entry_t e = extractNextHopFromVIP(sendAddress, link_entry_table);
        if(e.interface_id <=0){
          printf("Failed to send, recipient not in table");
        }
        else {
          sendPort = e.port;
          strcpy(sendAddress, e.interface_ip);

          send_addr.sin_addr.s_addr = inet_addr(sendAddress);
          send_addr.sin_family = AF_INET;
          send_addr.sin_port = htons(sendPort);

          if (sendto(send_socket,message,sizeof(message),0, (struct sockaddr*) &send_addr,sizeof(send_addr))==-1) {
            perror("failed to send message");
          }

          printf("send to: %s, port %d, message: %s\n", sendAddress, sendPort, message);
        }
      }
      else{
        printf("not a valid command: %s\n", cmd);
      }
      while ((c = getchar()) != '\n' && c != EOF); // clears the stdin buffer if there's anything left
    }
    if (FD_ISSET (rec_socket, &read_fd_set)){
      printf("got data\n");
      recv(rec_socket, message, MAX_READIN_BUFFER, 0);
      printf("%s\n", message);
    }
  }
}