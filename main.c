#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

int server(uint16_t port);
int client(const char * addr, uint16_t port);

#define MAX_MSG_LENGTH (512)
#define MAX_BACK_LOG (5)

int main(int argc, char ** argv)
{
	if (argc < 3) {
		printf("usage: myprog c <port> <address> or myprog s <port>\n");
		return 0;
	}

	uint16_t port = atoi(argv[2]);
	if (port < 1024) {
		fprintf(stderr, "port number should be equal to or larger than 1024\n");
		return 0;
	}
	if (argv[1][0] == 'c') {
		return client(argv[3], port);
	} else if (argv[1][0] == 's') {
		return server(port);
	} else {
		fprintf(stderr, "unkonwn command type %s\n", argv[1]);
		return 0;
	}
	return 0;
}

int client(const char * addr, uint16_t port)
{
	int sock;
	struct sockaddr_in server_addr;
	char msg[MAX_MSG_LENGTH], reply[MAX_MSG_LENGTH*3];

	if ((sock = socket(AF_INET, SOCK_STREAM/* use tcp */, 0)) < 0) {
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
		recv_len = read(sock, reply, MAX_MSG_LENGTH*3);
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

int server(uint16_t port)
{
	struct sockaddr_in sin;
	char buf[3*MAX_MSG_LENGTH], msg[MAX_MSG_LENGTH];

	int len, i;
	int s, new_s;
	char str[INET_ADDRSTRLEN];
	int clientID;

	/* build address data structure */
	bzero((char *)&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(port);

	/* setup passive open */
	if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Create socket error");
		return 1;
	}
	if ((bind(s, (struct sockaddr *)&sin, sizeof(sin))) < 0) {
		perror("binding error");
		return 1;
	}
	printf("bind done\n");

	listen(s, MAX_BACK_LOG);

	printf("listen done, waiting for connection\n");

	clientID = 0;

	/* wait for connection, then receive and print text */
	while(1) {
		if ((new_s = accept(s, (struct sockaddr *)&sin, &len)) < 0) {
			perror("accepting error");
			return 1;
		}

		/* fork a new child process to handle the connection */
		int pid = fork();

		if(pid < 0){
			perror("fork failed");
			close(new_s);
			continue;
		}
		/* parent process just closes its copy of the current connection and moves on to accept new clients */
		else if(pid > 0){
			close(new_s);
			clientID++;
			continue;
		}
		else{
			printf("accept connection from %s, clientID: %d\n", inet_ntop(AF_INET, &(sin.sin_addr), str, INET_ADDRSTRLEN), clientID);

			while (len = recv(new_s, msg, MAX_MSG_LENGTH, 0)){
				/* should return the received message three times, combine into the buffer */
				msg[MAX_MSG_LENGTH] = '\0';
				for(i = 0; i < (3*strlen(msg)); i++){
					buf[i] = msg[i%strlen(msg)];
				}

				buf[3*strlen(msg)] = '\0';

				printf("recv from clientID %d: %s, length: %d\n", clientID, msg, (int)strlen(msg));

				if (send(new_s, buf, MAX_MSG_LENGTH, 0) < 0) {
					perror("server recv error:");
					return 1;
				}

				printf("test");

				memset(&buf[0], 0, sizeof(buf));
			}

			close(new_s);

			printf("client %d disconnected\n", clientID);
			exit(0);
		}
	}
	return 0;
}