#include <iostream> 
#include <string>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;

#define PORT 1804


int main() {

    int ret;

    // Create a socket connexion

    // Variables
    int socketfd;
    struct sockaddr_in serverAddr, clientAddr;

    // Socket creation
    socketfd = socket(AF_INET, SOCK_STREAM, 0);
    if (!socketfd) {
        cerr << "Error creating socket";
        exit(1);
    }

    // Socket parameters
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    // Bind the socket to the adress
    ret = bind(socketfd, (sockaddr*)&serverAddr, sizeof(serverAddr));
    if (!ret) {
        cerr << "Error binding socket";
        close(socketfd);
    }

    // Start listening for requests
    ret = listen(socketfd, 10);
    if (!ret) {
        cerr << "Error listening";
        exit(1);
    }

    // Authenticate the server using the certificate

    // Read CA certificate
    string CACertName = "CAcert.pem";
    FILE* CACertFile = fopen(CACertName.c_str(), "r");
    if (!CACertFile) {
        cerr << "Error : cannot open " << CACertName << "certificate\n";
    }
    X509* CAcert = PEM_read_X509(CACertFile, NULL, NULL, NULL);
    fclose(CACertFile);
    if (!CAcert) {
        cerr << "Error : cannot read " << CACertName << "certificate\n";
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