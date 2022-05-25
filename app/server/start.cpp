#include <iostream> 
#include <string>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509_vfy.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctime>
#include <unistd.h>
#include "../DH.h"

#define PORT 1804

using namespace std;

class Server {

    // Sockets
    int socketfd, clientfd;
    struct sockaddr_in serverAddr, clientAddr;

    // Client infos
    string clientUsername;
    string nonce;

    // Keys
    EVP_PKEY* clientPubKey;
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

    // Create and send a challenge to authenticate client
    void createChallenge() {

        int ret;

        // Generate a 16 bytes random number to ensure unpredictability
        unsigned char random[16];
        ret = RAND_bytes(random, sizeof(random));

        // Generate a char timestamp to ensure uniqueness
        char now[80];
        time_t currTime;
        tm* currentTime;
        time(&currTime);
        currentTime = localtime(&currTime);
        strftime(now, sizeof(now), "%Y%j%H%M%S", currentTime);

        // Concatenate random number and timestamp
        char nonceBuff[sizeof(now) + sizeof(random)];
        memcpy(nonceBuff, random, sizeof(random));
        strcat(nonceBuff, now);
        nonce = ""; // Reset the nonce in case it wasn't empty
        nonce += nonceBuff;

        // Retreive user's pubkey
        string path = "users_infos/" + clientUsername + "/pubkey.pem";
        FILE * keyFile = fopen(path.c_str(), "r");
        if (!keyFile) {
            cerr << "Error could not open client " << clientUsername << " public key file\n";
        }
        clientPubKey = PEM_read_PUBKEY(keyFile, NULL, NULL, NULL);
        if (!clientPubKey) {
            cerr << "Error could not read client " << clientUsername << " public key from pem file\n";
        }

        // Encrypt nonce using client public key
        int pubKeyLength = i2d_PublicKey(clientPubKey, NULL);
        unsigned char* buff = (unsigned char *)malloc(pubKeyLength);
        if (!buff) {
            cerr << "Error allocation for public key buffer failed";
        }
        i2d_PublicKey(clientPubKey, &buff);
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            cerr << "Error context creation failed";
        }
        ret = EVP_EncryptInit(ctx, EVP_aes_128_ecb(), buff, NULL);
        free(buff);


        // Send the challenge to the client
        ret = send(clientfd, nonce, sizeof(nonce), 0);
        if (ret < 0) {
            cerr << "Error sending challenge to the client";
        }

    }

    // Receive and check client response to the challenge
    void authenticateClient() {
        
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