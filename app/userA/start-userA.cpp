#include <iostream> 
#include <string>
#include <stdio.h> // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl

int main() {

    // Authenticate the server using the certificate
    // First we create a store
    X509_STORE* store = X509_STORE_new();

    return 0;
}