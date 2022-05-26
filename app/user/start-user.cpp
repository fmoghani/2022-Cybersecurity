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
#include "../DH.h"
#include "../utils.h"

using namespace std;

#define PORT 1804

class Client {

    // Sockets
    int socketfd, clientfd;
    struct sockaddr_in serverAddr;

    // Client variables
    char * encryptedNonce;
    char * clientResponse;

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
            exit(1);
        }
    }

    // Authenticate server
    void authenticateServer() {

        int ret;

        // Read CA certificate
        string CACertPath = "../certificates/CAcert.pem";
        X509 * CACert = readCertificate(CACertPath); // Function from utils.h

        // Read CA crl
        string CACrlPath = "../certificates/CAcrl.pem";
        X509_CRL * CACrl = readCrl(CACrlPath); // Function from utils.h

        // Create a store with CA certificate and crl
        X509_STORE* store = X509_STORE_new();
        if (!store) {
            cerr << "Error : cannot create store\n";
            exit(1);
        }
        ret = X509_STORE_add_cert(store, CACert);
        if (!ret) {
            cerr << "Error : cannot add CA certificate to the store\n";
            exit(1);
        }
        ret = X509_STORE_add_crl(store, CACrl);
        if (!ret) {
            cerr << "Error cannot add CA CRL to the store\n";
            exit(1);
        }

        // Make sure crl will be checked when authenticating server
        ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
        if (!ret) {
            cerr << "Error setting certificate store flag\n";
            exit(1);
        }

        // Read server certificate
        string serverCertPath = "../certificates/servcert.pem\n";
        X509 * serverCert = readCertificate(serverCertPath); // Function fro utils.h

        // Verify server's certificate
        X509_STORE_CTX * ctx = X509_STORE_CTX_new();
        if (!ret) {
            cerr << "Error during certificate verification context creation\n";
            exit(1);
        }
        ret = X509_STORE_CTX_init(ctx, store, serverCert, NULL);
        if (!ret) {
            cerr << "Error initializing certificate verification\n";
            exit(1);
        }
        ret = X509_verify_cert(ctx);
        if (!ret) {
            cerr << "Error server not authenticated\n";
            exit(1);
        }
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
    }


    // Receive server's challenge and sends client's response
    void generateResponse() {

        int ret;

        //  Receive server's challenge
        bzero(encryptedNonce, 120);
        ret = read(socketfd, encryptedNonce, 120);
        if (ret < 0) {
            cerr << "Error cannot read server's challenge\n";
            exit(1);
        }

        // Retreive user's prvkey
        string path = "user_infos/pubkey.pem";
        FILE * keyFile = fopen(path.c_str(), "r");
        if (!keyFile) {
            cerr << "Error could not open client private key file\n";
            exit(1);
        }
        clientPrvKey = PEM_read_PUBKEY(keyFile, NULL, NULL, NULL);
        if (!clientPrvKey) {
            cerr << "Error cannot read client private key from pem file\n";
            exit(1);
        }

        // Decrypt the challenge
        int prvKeyLength = i2d_PublicKey(clientPrvKey, NULL);
        unsigned char * prvKey = (unsigned char *) malloc(sizeof(prvKeyLength));
        int decryptedLength;
        if (!prvKey) {
            cerr << "Error private key buffer allocation failed\n";
            exit(1);
        }
        ret = i2d_PrivateKey(clientPrvKey, &prvKey);
        if (ret < 0) {
            cerr << "Error converting private key into char\n";
            exit(1);
        }
        EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            cerr << "Error creating context challenge decryption\n";
            exit(1);
        }
        ret = EVP_DecryptInit(ctx, EVP_aes_128_ecb(), prvKey, NULL);
        free(prvKey);
        if (!ret) {
            cerr << "Error during decryption initialization\n";
            exit(1);
        }
        ret = EVP_DecryptUpdate(ctx, (unsigned char *) clientResponse, &decryptedLength, (unsigned char *) encryptedNonce, sizeof(encryptedNonce));
        if (!ret) {
            cerr << "Error during decryption update\n";
            exit(1);
        }
        ret = EVP_DecryptFinal(ctx, (unsigned char *) clientResponse + decryptedLength, &decryptedLength);
        if (!ret) {
            cerr << "Error during encryption finalization\n";
            exit(1);
        }

        // Send the response to the server
        ret = send(socketfd, clientResponse, sizeof(clientResponse), 0);
        if (ret < 0) {
            cerr << "Error sending response to the client\n";
            exit(1);
        }
    }

    // Generate client Diffie Hellman key pair
    void generateKeyPair() {

        
    }

};

int main() {

    

    return 0;
}