/*
 * socket-client.c
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "socket-common.h"

/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
	ssize_t ret;
	size_t orig_cnt = cnt;
	
	while (cnt > 0) {
	        ret = write(fd, buf, cnt);
	        if (ret < 0)
	                return ret;
	        buf += ret;
	        cnt -= ret;
	}

	return orig_cnt;
}

int main(int argc, char *argv[])
{
	int sd, port;
	ssize_t n;
	char buf[100];
	char *hostname;
	struct hostent *hp;
	struct sockaddr_in sa;
	int activity;
	fd_set readfds;				//set of socket descriptors


	if (argc != 3) {
		fprintf(stderr, "Usage: %s hostname port\n", argv[0]);
		exit(1);
	}
	hostname = argv[1];
	port = atoi(argv[2]); /* Needs better error checking */

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");
	
	/* Look up remote hostname on DNS */
	if ( !(hp = gethostbyname(hostname))) {
		printf("DNS lookup failed for host %s\n", hostname);
		exit(1);
	}

	/* Connect to remote TCP port */
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));
	fprintf(stderr, "Connecting to remote host... "); fflush(stderr);
	if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		perror("connect");
		exit(1);
	}
	fprintf(stderr, "Connected.\n");
	
	FD_ZERO(&readfds);
	
	/* Read answer and write it to standard output */
	for (;;) {
		
		FD_SET(sd, &readfds);
		FD_SET(0, &readfds);

		activity = select(sd+1, &readfds , NULL , NULL , NULL);

		if ((activity < 0) && (errno!=EINTR)) 
        	{
            		printf("select error");
        	}

		if(FD_ISSET(sd, &readfds)) {
			n = read(sd, buf, sizeof(buf));
			if (n < 0) {
				perror("read");
				exit(1);
			}
			if (n <= 0)
				break;
			printf("Remote says:\n");
			if (insist_write(1, buf, n) != n) {
				perror("write");
				exit(1);
			}
		}
		
		if(FD_ISSET(0, &readfds)) {			    
			n = read(0, buf, sizeof(buf));
			if (n < 0) {
				perror("read");
				exit(1);
			}
			if (n <= 0)
				break;
			
			if (insist_write(sd, buf, n) != n) {
				perror("write");
				exit(1);
			}
		}

	}

	fprintf(stderr, "\nDone.\n");
	return 0;
}
