
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <netdb.h>

#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "ssl_util.h"

#define QLEN          32    /* maximum connection queue length  */
#define BUFSIZE     4096
#define SERVER_CERT "server.cert"
#define SERVER_KEY  "server_priv.key"

extern int  errno;
int     errexit(const char *format, ...);
int     passivesock(const char *portnum, int qlen);
int     echo(SSL *ssl);

/*------------------------------------------------------------------------
 * main - Concurrent TCP server for ECHO service
 *------------------------------------------------------------------------
 */
int main(int argc, char *argv[])
{
    char    *portnum = "5004";  /* Standard server port number  */
    struct sockaddr_in fsin;    /* the from address of a client */
    int msock;                  /* master server socket         */
    fd_set  rfds;               /* read file descriptor set     */
    fd_set  afds;               /* active file descriptor set   */
    unsigned int    alen;       /* from-address length          */
    int fd, nfds;
    int err;

    SSL_CTX         *ctx;
    SSL_METHOD      *meth;
    SSL             *ssl;

    switch (argc) {
    case    1:
        break;
    case    2:
        portnum = argv[1];
        break;
    default:
        errexit("usage: TCPmechod [port]\n");
    }

    ssl_init();               // initialize ssl functions and error strings
    meth = SSLv3_method();    // create a SSL_METHOD structure, in this case use SSLv3
    ctx = SSL_CTX_new(meth);  // create a SSL_CTX structure

    // make sure no errors occured creating the ssl context
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    // Load the server certificate into the SSL_CTX structure
    // This will be used for authenticating the server
    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    printf("after\n");

    // Load the private-key corresponding to the server certificate
    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    // Check if the server certificate and private-key matches
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        exit(1);
    }

    // main server socket
    msock = passivesock(portnum, QLEN);
    if (LOGGING) printf("msock is %d\n", msock);

#ifdef __APPLE__
    // OSX workaround, can't have more than 1024 fds
    nfds = 1024;
#else
    nfds = getdtablesize();
#endif

    FD_ZERO(&afds);
    FD_SET(msock, &afds);

    while (1) {
        memcpy(&rfds, &afds, sizeof(rfds));

        if (select(nfds, &rfds, (fd_set *)0, (fd_set *)0, (struct timeval *)0) < 0)
            errexit("select: %s\n", strerror(errno));

        if (FD_ISSET(msock, &rfds)) {
            int ssock;

            alen = sizeof(fsin);
            ssock = accept(msock, (struct sockaddr *)&fsin, &alen);
            if (ssock < 0)
                errexit("accept: %s\n", strerror(errno));
            FD_SET(ssock, &afds);

            // create a SSL structure and make sure its not NULL
            ssl = SSL_new(ctx);
            if (ssl == NULL) {
                printf("Error creating new SSL structure\n");
                exit(1);
            }

            // Assign the socket into the SSL structure
            // From now on, we can deal with the ssl structure and not the socket directly
            SSL_set_fd(ssl, ssock);

            // Perform SSL Handshake on the SSL server
            err = SSL_accept(ssl);
            if (err < 0) {
                ERR_print_errors_fp(stderr);
                exit(1);
            }

            if (LOGGING) printf("SSL connection using %s\n", SSL_get_cipher (ssl));
        }

        for (fd=0; fd < nfds; ++fd)
            if (fd != msock && FD_ISSET(fd, &rfds))
                if (echo(ssl) == 0) {
                    (void) close(fd);
                    FD_CLR(fd, &afds);
                }
    }
}

/*------------------------------------------------------------------------
 * echo - echo one buffer of data, returning byte count
 *------------------------------------------------------------------------
 */
int echo(SSL *ssl)
{
    char buf[BUFSIZ];
    int cc, n;

    cc = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (cc < 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    buf[cc] = '\0';

    printf("Received %d chars: %s", cc, buf);

    if (cc < 0)
        errexit("echo read: %s\n", strerror(errno));
    if (cc)
    {
        // Echo data to the SSL client
        n = SSL_write(ssl, buf, cc);
        if (n < 0) {
            ERR_print_errors_fp(stderr);
            exit(1);
        }
    }
    return cc;
}

/*------------------------------------------------------------------------
 * errexit - print an error message and exit
 *------------------------------------------------------------------------
 */
int
errexit(const char *format, ...)
{
        va_list args;

        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);
        exit(1);
}

/*------------------------------------------------------------------------
 * passivesock - allocate & bind a server socket using TCP
 *------------------------------------------------------------------------
 */
int
passivesock(const char *portnum, int qlen)
/*
 * Arguments:
 *      portnum   - port number of the server
 *      qlen      - maximum server request queue length
 */
{
        struct sockaddr_in sin; /* an Internet endpoint address  */
        int     s;              /* socket descriptor             */

        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = INADDR_ANY;

    /* Map port number (char string) to port number (int) */
        if ((sin.sin_port=htons((unsigned short)atoi(portnum))) == 0)
                errexit("can't get \"%s\" port number\n", portnum);

    /* Allocate a socket */
        s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s < 0)
            errexit("can't create socket: %s\n", strerror(errno));

    /* Bind the socket */
        if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            fprintf(stderr, "can't bind to %s port: %s; Trying other port\n",
                portnum, strerror(errno));
            sin.sin_port=htons(0); /* request a port number to be allocated
                                   by bind */
            if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
                errexit("can't bind: %s\n", strerror(errno));
            else {
                int socklen = sizeof(sin);

                if (getsockname(s, (struct sockaddr *)&sin, &socklen) < 0)
                        errexit("getsockname: %s\n", strerror(errno));
                printf("New server port number is %d\n", ntohs(sin.sin_port));
            }
        }

        if (listen(s, qlen) < 0)
            errexit("can't listen on %s port: %s\n", portnum, strerror(errno));
        return s;
}
