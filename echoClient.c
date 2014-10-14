#include <sys/types.h>
#include <sys/socket.h>

#include <sys/errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "ssl_util.h"

#ifndef INADDR_NONE
#define INADDR_NONE     0xffffffff
#endif  /* INADDR_NONE */

extern int  errno;

int TCPecho(const char *host, const char *portnum);
int errexit(const char *format, ...);
int connectsock(const char *host, const char *portnum);

#define LINELEN        128
#define CLIENT_CA_CERT "demoCA/cacert.pem"
#define CLIENT_CA_KEY  "demoCA/private/cakey.pem"
#define PASSWORD       "netsys_2014"

/*------------------------------------------------------------------------
 * main - TCP client for ECHO service
 *------------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{
    char    *host = "localhost";    /* host to use if none supplied */
    char    *portnum = "5004";  /* default server port number   */

    switch (argc) {
    case 1:
        host = "localhost";
        break;
    case 3:
        host = argv[2];
        /* FALL THROUGH */
    case 2:
        portnum = argv[1];
        break;
    default:
        fprintf(stderr, "usage: TCPecho [host [port]]\n");
        exit(1);
    }
    TCPecho(host, portnum);
    exit(0);
}

/*------------------------------------------------------------------------
 * TCPecho - send input to ECHO service on specified host and print reply
 *------------------------------------------------------------------------
 */
int
TCPecho(const char *host, const char *portnum)
{
    char    buf[LINELEN+1];     /* buffer for one line of text  */
    int s, n;           /* socket descriptor, read count*/
    int outchars, inchars;  /* characters sent and received */
    char  *str;
    int err;

    SSL_CTX        *ctx;
    SSL_METHOD     *meth;
    SSL            *ssl;
    X509           *server_cert;
    EVP_PKEY       *pkey;

    ssl_init();               // initialize ssl functions and error strings
    meth = SSLv3_method();    // create a SSL_METHOD structure, in this case use SSLv3
    ctx = SSL_CTX_new(meth);  // create a SSL_CTX structure

    // make sure no errors occured creating the ssl context
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    // Set password callback
    SSL_CTX_set_default_passwd_cb_userdata(ctx, PASSWORD);

    // Load the local private key from the location specified by keyFile
    if ( SSL_CTX_use_PrivateKey_file(ctx, CLIENT_CA_KEY, SSL_FILETYPE_PEM) != 1 ){
        printf("Unable to load privatekey file\n");
        exit(0);
    }

    // Load the RSA CA certificate into the SSL_CTX structure
    // This will allow this client to verify the server's certificate.
    if (!SSL_CTX_load_verify_locations(ctx, CLIENT_CA_CERT, NULL)) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    // Set flag in the ssl context to require server certificate verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 1);

    s = connectsock(host, portnum);

    // An SSL structure is created
    ssl = SSL_new(ctx);
    if (ssl == NULL) exit(1);

    // Assign the socket into the SSL structure
    // From now on we can work with the ssl structure instead of the socket directly
    SSL_set_fd(ssl, s);

    // Perform SSL Handshake on the SSL client
    err = SSL_connect(ssl);
    if (err < 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (LOGGING) printf ("SSL connection using %s\n", SSL_get_cipher (ssl));

    // Get the server's certificate
    server_cert = SSL_get_peer_certificate(ssl);

    if (server_cert != NULL) {
        if (LOGGING) printf ("Server certificate:\n");

        str = X509_NAME_oneline(X509_get_subject_name(server_cert),0,0);
        if (str == NULL) {
            printf("Error: X509_NAME_oneline returned NULL\n");
            exit(1);
        }
        if (LOGGING) printf ("\t subject: %s\n", str);
        free (str);

        str = X509_NAME_oneline(X509_get_issuer_name(server_cert),0,0);
        if (str == NULL) {
            printf("Error: X509_NAME_oneline returned NULL\n");
            exit(1);
        }
        if (LOGGING) printf ("\t issuer: %s\n", str);
        free(str);

        X509_free (server_cert);
    }
    else
        printf("The SSL server does not have certificate.\n");



    while (fgets(buf, sizeof(buf), stdin)) {
        buf[LINELEN] = '\0'; //insure line null-terminated
        outchars = strlen(buf);

        err = SSL_write(ssl, buf, outchars);
        if (err < 0) {
            ERR_print_errors_fp(stderr);
            exit(1);
        }

        /* read it back */
        for (inchars = 0; inchars < outchars; inchars+=n ) {
            n = SSL_read(ssl, &buf[inchars], outchars - inchars);
            if (n < 0) {
                ERR_print_errors_fp(stderr);
                exit(1);
            }
        }
        fputs(buf, stdout);
    }
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
 * connectsock - allocate & connect a socket using TCP
 *------------------------------------------------------------------------
 */
int
connectsock(const char *host, const char *portnum)
/*
 * Arguments:
 *      host      - name of host to which connection is desired
 *      portnum   - server port number
 */
{
        struct hostent  *phe;   /* pointer to host information entry    */
        struct sockaddr_in sin; /* an Internet endpoint address         */
        int     s;              /* socket descriptor                    */


        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;

    /* Map port number (char string) to port number (int)*/
        if ((sin.sin_port=htons((unsigned short)atoi(portnum))) == 0)
                errexit("can't get \"%s\" port number\n", portnum);

    /* Map host name to IP address, allowing for dotted decimal */
        if ( phe = gethostbyname(host) )
                memcpy(&sin.sin_addr, phe->h_addr, phe->h_length);
        else if ( (sin.sin_addr.s_addr = inet_addr(host)) == INADDR_NONE )
                errexit("can't get \"%s\" host entry\n", host);

    /* Allocate a socket */
        s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s < 0)
                errexit("can't create socket: %s\n", strerror(errno));

    /* Connect the socket */
        if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
                errexit("can't connect to %s.%s: %s\n", host, portnum,
                        strerror(errno));
        return s;
}

