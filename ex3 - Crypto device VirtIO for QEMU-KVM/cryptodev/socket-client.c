/*
 * client-cryptodev.c
 * Encrypted TCP/IP communication using sockets
 *
 * Anastasis Stathopoulos <anas.stathop@gmail.com>
 */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <crypto/cryptodev.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "socket-common.h"

#define DATA_SIZE       256
#define BLOCK_SIZE      16
#define KEY_SIZE        16  /* AES128 */


unsigned char buf[256];
unsigned char key[] = "okrokotinpairni";
unsigned char inv[] = "abcdefghijklmno";
struct session_op sess;

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


int encrypt(int cfd)
{
        int i;
        struct crypt_op cryp;
        
	struct {
                unsigned char   in[DATA_SIZE],
                                encrypted[DATA_SIZE],
                                iv[BLOCK_SIZE];
        } data;
        
        memset(&cryp, 0, sizeof(cryp));

        /*
         * Encrypt data.in to data.encrypted
         */
        cryp.ses = sess.ses;
        cryp.len = sizeof(data.in);
        cryp.src = buf;
        cryp.dst = data.encrypted;
        cryp.iv = inv;
        cryp.op = COP_ENCRYPT;

        if (ioctl(cfd, CIOCCRYPT, &cryp)) {
                perror("ioctl(CIOCCRYPT)");
                return 1;
        }

        printf("\nEncrypted data:\n");
 	
	for(i=0; i<DATA_SIZE; i++)
		printf("%x",data.encrypted[i]);     

	printf("\n\n");	
	i = 0;
        while(data.encrypted[i] != '\0'){
                buf[i] = data.encrypted[i];
               // printf("%x", data.encrypted[i]);
                i++;
        }

        return 0;
}

int decrypt(int cfd){

        int i;
        struct crypt_op cryp;
        struct {
                unsigned char   in[DATA_SIZE],
                                decrypted[DATA_SIZE],
                                iv[BLOCK_SIZE];
        } data;

        memset(&cryp, 0, sizeof(cryp));

        /*
         * Decrypt data.encrypted to data.decrypted
         */
        cryp.ses = sess.ses;
        cryp.len = sizeof(data.in);
        cryp.src = buf;
        cryp.dst = data.decrypted;
        cryp.iv = inv;
        cryp.op = COP_DECRYPT;
        if (ioctl(cfd, CIOCCRYPT, &cryp)) {
                perror("ioctl(CIOCCRYPT)");
                return 1;
        }
	
	memset(buf, '\0', 256);
        printf("\nDecrypted data:\n");
        i = 0;
        while(data.decrypted[i] != '\0'){
                buf[i] = data.decrypted[i];
                //printf("%x", buf[i]);
                i++;
        }

        return 0;
}


int main(int argc, char *argv[])
{
        int sd, port, cfd;
        ssize_t n;
        char *hostname;
        struct hostent *hp;
        struct sockaddr_in sa;
        int activity;
        fd_set readfds;                         //set of socket descriptors

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

        cfd = open("/dev/crypto", O_RDWR);
        if (cfd < 0) {
                perror("open(/dev/crypto)");
                return 1;
        }
	
	memset(&sess, 0, sizeof(sess));

        /*
         * Get crypto session for AES128
         */
        sess.cipher = CRYPTO_AES_CBC;
        sess.keylen = KEY_SIZE;
        sess.key = key;

        if (ioctl(cfd, CIOCGSESSION, &sess)) {
                perror("ioctl(CIOCGSESSION)");
                return 1;
        }
	
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

                        if(decrypt(cfd)){
                                perror("decrypt");
                        }

                        if (insist_write(1, buf, n) != n) {
                                perror("write");
                                exit(1);
                        }
			printf("\n");
                }

                if(FD_ISSET(0, &readfds)) {
                        memset(buf, '\0', sizeof(buf));
			n = read(0, buf, sizeof(buf));
                        if (n < 0) {
                                perror("read");
                                exit(1);
                        }
                        if (n <= 0)
                                break;

                        if(encrypt(cfd)){
                                perror("encrypt");
                        }

                        if (insist_write(sd, buf, sizeof(buf)) != sizeof(buf)) {
                                perror("write");
                                exit(1);
                        }
                }

        }
	
	/* Finish crypto session */
        if (ioctl(cfd, CIOCFSESSION, &sess.ses)) {
                perror("ioctl(CIOCFSESSION)");
                return 1;
        }
	
        if (close(cfd) < 0) {
                perror("close(cfd)");
                return 1;
        }

        fprintf(stderr, "\nDone.\n");
        return 0;
}


