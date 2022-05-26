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

class Client {

    // Sockets
    int socketfd, clientfd;
    struct sockaddr_in serverAddr;

    // Client variables
    unsigned char * encryptedNonce;
    unsigned char * clientResponse;

    // Keys
    EVP_PKEY * clientPrvKey;

    public :

    // Create a socket connexion
    void connectClient() {

        // Socket creation
        socketfd = socket(AF_INET, SOCK_STREAM, 0);
        if (!socketfd) {
            cerr << "Error creating socket\n";
            exit(1);
        }

        // Socket parameters
        memset(&serverAddr, 0, sizeof(serverAddr));
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(PORT);
        serverAddr.sin_addr.s_addr = INADDR_ANY;

        // Connect client to the socket
        clientfd = connect(socketfd, (sockaddr *)&serverAddr, sizeof(serverAddr));
        if (!clientfd) {
            cerr << "Error connecting client to the server\n";
        }
    }

    // Receive server's challenge and sends client's response
    void generateResponse() {

        int ret;

        //  Receive server's challenge
        bzero(encryptedNonce, 120);
        ret = read(socketfd, encryptedNonce, 120);
        if (ret < 0) {
            cerr << "Error cannot read server's challenge\n";
        }

        // Retreive user's prvkey
        string path = "user_infos/pubkey.pem";
        FILE * keyFile = fopen(path.c_str(), "r");
        if (!keyFile) {
            cerr << "Error could not open client private key file\n";
        }
        clientPrvKey = PEM_read_PUBKEY(keyFile, NULL, NULL, NULL);
        if (!clientPrvKey) {
            cerr << "Error cannot read client private key from pem file\n";
        }

        // Decrypt the challenge
        int prvKeyLength = i2d_PublicKey(clientPrvKey, NULL);
        unsigned char * response = (unsigned char *) malloc(sizeof(prvKeyLength));
        if (!response) {
            cerr << "Error response buffer allocation failed";
        }
        
    }

    // Generate client Diffie Hellman key pair
    void generateKeyPair() {

        
    }

};

int main() {

    int ret;

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
        cerr << "Error : cannot add CA certificate to the store\n";
    }

    return 0;
}