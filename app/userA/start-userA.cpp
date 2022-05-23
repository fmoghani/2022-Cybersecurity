#include <iostream> 
#include <string>
#include <stdio.h> // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>

using namespace std;


int main() {

    int ret;

    // Authenticate the server using the certificate

    // Read CA certificate
    string CA_cert_name = "CAcert.pem";
    FILE* CA_cert_file = fopen(CA_cert_name.c_str(), "r");
    if (!CA_cert_file) {
        cerr << "Error : cannot open " << CA_cert_name << "certificate\n";
    }
    X509* CAcert = PEM_read_X509(CA_cert_file, NULL, NULL, NULL);
    fclose(CA_cert_file);
    if (!CAcert) {
        cerr << "Error : cannot read " << CA_cert_name << "certificate\n";
    }

    // Create a store with CA certificate
    X509_STORE* store = X509_STORE_new();
    if (!store) {
        cerr << "Error : cannot create store\n";
    }
    ret = X509_STORE_add_cert(store, CAcert);
    if (!ret) {
        cerr << "Error : cannot add CA certificate to the store";
    }

    return 0;
}