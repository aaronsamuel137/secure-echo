#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define LOGGING 1 // toggle logging

void ssl_init()
{
    SSL_library_init();       // load ssl library encryption and hashing functions
    SSL_load_error_strings(); // load error reporting stings for openssl functions
}
