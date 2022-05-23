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
#include <DH.h>

#define PORT 1804

using namespace std;

class Server {

    // Sockets
    int socketfd, clientfd;
    struct sockaddr_in serverAddr, clientAddr;

    // Key
    EVP_PKEY* prvKey;

public:

    // Build function
    Server() {
        
        // Initialize server certificate
        // Initialize authorized users list
        startSocket();
    }

    // Creates a socket and makes it listen
    void startSocket() {

        int ret;

        // Socket creation
        socketfd = socket(AF_INET, SOCK_STREAM, 0);
        if (!socketfd) {
            cerr << "Error creating socket" << "\n";
            exit(1);
        }

        // Socket parameters setup
        memset(&serverAddr, 0, sizeof(serverAddr));
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(PORT);
        serverAddr.sin_addr.s_addr = INADDR_ANY;

        // Bind the socket to the adress
        ret = bind(socketfd, (sockaddr*)&serverAddr, sizeof(serverAddr));
        if (!ret) {
            cerr << "Error binding socket" << "\n";
            close(socketfd);
        }

        // Start listening for requests
        ret = listen(socketfd, 10);
        if (!ret) {
            cerr << "Error listening" << "\n";
            exit(1);
        }
        cout << "Listening to port : " << PORT << "\n";
    }

    // Handles client connexion request
    void acceptClient() {

        // Extract the first connexion in the queue
        int len = sizeof(clientAddr);
        clientfd = accept(socketfd, (sockaddr *)&clientAddr, (socklen_t *)&len);
        if (!clientfd) {
            cerr << "Error cannot accept client";
        }

        
    }

    // Establish session private key using DH key exchange
    void createSessionKey() {

        // Creation of a new private key using standart DH parameters from OpenSSL
        prvKey = EVP_PKEY_new();
        EVP_PKEY_set1_DH(prvKey, DH_get_2048_224());

        // Generation of a private/public key pair

    }

};

int main() {

    int ret;

    // Create a socket connexion

    return 0;
}