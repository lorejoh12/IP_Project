#include <netinet/ip.h>

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>


#define MAX_MSG_LENGTH (1400)
#define MAX_BACK_LOG (5)
#define MAX_READIN_BUFFER (64 * 1024)

/* table of table entries */
/* table of link interfaces along with their status (up or down) */
/* uint16_t myPort */
/* socket mySocket */
/*struct table entry

sourceofentry
connection
distance
port
lastupdated timestamp
*/

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

/* receivePacket() 
    call upon receiving a packet
    
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
    }
*/

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

/*
int listenOn(uint16_t port) {
    setUpPort(port)
    listen for packets and call receivePacket(packet) on receive)
}
*/



/* Edit this method to just set up a socket port and return the int
int setUpPort(uint16_t port)
{
    int len;
    int sock, in_sock;
	struct sockaddr_in server_addr;
    char msg[MAX_MSG_LENGTH], reply[MAX_REPLY_LENGTH];
    char addr[len];
        
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Create socket error:");
		return 1;
	}

	printf("Socket created\n");
	
    bzero((char *)&server_addr, sizeof(server_addr));
    server_addr.sin_addr.s_addr = INADDR_ANY; 
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);

    if ((bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr))) < 0) {
       perror("Bind error:");
       return 1;
    }
    
    printf("bind done\n");
    
    listen(sock, MAX_BACK_LOG);
    printf("listen done, waiting for connection\n");
    
    while(1) {
        if((in_sock = accept(sock, (struct sockaddr *)&server_addr, &len)) < 0) {
            perror("Accept error:");
            return 1;
        }
        
        if ((fork()) == 0) {
            close(sock);
            inet_ntop(AF_INET, &(server_addr.sin_addr), addr, len);
    
            printf("accept connection from %s\n", addr);
            memset(msg, 0, MAX_MSG_LENGTH);
            memset(reply, 0, MAX_REPLY_LENGTH);
            
            msg[MAX_MSG_LENGTH] = '\0';
            reply[MAX_REPLY_LENGTH] = '\0';
            
            while (len = recv(in_sock, msg, MAX_MSG_LENGTH, 0)) {
                printf("recv from client: %s\n", msg);
                sprintf(reply, "%s%s%s", msg, msg, msg);
                
                send(in_sock, reply, strnlen(reply, MAX_REPLY_LENGTH), 0);
                memset(msg, 0, MAX_MSG_LENGTH);
                memset(reply, 0, MAX_REPLY_LENGTH);
            }
            
            close(in_sock);
            printf("client disconnected\n");
            exit(0);
        }
        
        
        close(in_sock);
    }   
 
	return 0;
} */
