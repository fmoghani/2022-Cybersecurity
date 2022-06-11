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
#include <map>
#include <filesystem>
#include <cerrno>
#include "users_infos/khabib/DH.h"
#include "../utils.h"

using namespace std;

#define PORT 1805

class Server {

    // Sockets
    int socketfd, clientfd;
    struct sockaddr_in serverAddr, clientAddr;

    // Client infos
    string clientUsername;
    unsigned char * nonce;

     // Map containing all the get_DH2048() functions specific to each user
    std::map<std::string, DH *> dhMap;

    // Keys
    EVP_PKEY* clientPubKey;
    EVP_PKEY* prvKey;

    // Diffie-Hellman session keys
    EVP_PKEY * dhparams;
    EVP_PKEY * tempKey;
    unsigned char * sessionDH;
    

public:

    // Get username
    string getClientUsername() {
        return clientUsername;
    }

    // Update server's map
    void updateDHMap() {

        // Add users and their corresponding dhparam function when needed
        dhMap["khabib"] = get_DH2048_khabib();
        
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
        if (ret < 0) {
            cerr << "Error binding socket\n";
            close(socketfd);
            exit(1);
        }

        // Start listening for requests
        ret = listen(socketfd, 10);
        if (ret < 0) {
            cerr << "Error listening\n";
            exit(1);
        }
        cout << "Listening to port : " << PORT << "\n";
    }

    // Handles client connexion request
    void acceptClient() {

        // Extract the first connexion in the queue
        int len = sizeof(clientAddr);
        clientfd = accept(socketfd, (sockaddr *)&clientAddr, (socklen_t *)&len);
        if (clientfd < 0) {
            cerr << "Error cannot accept client";
        }

        // Receive username et convert it back to string
        unsigned char * buffer;
        buffer = readChar(clientfd);
        clientUsername = std::string(reinterpret_cast<char*>(buffer));
        free(buffer);
    }

    // Create and send a challenge to authenticate client
    void createChallenge() {

        int ret;

        // Generate a 16 bytes random number to ensure unpredictability
        unsigned char random[16];
        ret = RAND_bytes(random, sizeof(random));
        if (!ret) {
            cerr << "Error generating random bytes\n";
            close(clientfd);
        }

        // Generate a char timestamp to ensure uniqueness
        char now[80];
        time_t currTime;
        tm * currentTime;
        time(&currTime);
        currentTime = localtime(&currTime);
        if (!currentTime) {
            cerr << "Error creating pointer containing current time\n";
            close(clientfd);
        }
        ret = strftime(now, sizeof(now), "%Y%j%H%M%S", currentTime);
        if (!ret) {
            cerr << "Error putting time in a char array\n";
            close(clientfd);
        }

        // Concatenate random number and timestamp
        char * tempNonce = (char * ) malloc(sizeof(now) + sizeof(random));
        if (!tempNonce) {
            cerr << "Error allocating temporary buffer for nonce\n";
        }
        memcpy(tempNonce, random, sizeof(random));
        strcat(tempNonce, now);
        nonce = (unsigned char *) tempNonce;

        // Retreive user's pubkey
        string path = "users_infos/" + clientUsername + "/pubkey.pem";
        FILE * keyFile = fopen(path.c_str(), "r");
        if (!keyFile) {
            cerr << "Error could not open client " << clientUsername << " public key file\n";
            close(clientfd);
        }
        clientPubKey = PEM_read_PUBKEY(keyFile, NULL, NULL, NULL);
        fclose(keyFile);
        if (!clientPubKey) {
            cerr << "Error could not read client " << clientUsername << " public key from pem file\n";
            close(clientfd);
        }

        // Encrypt nonce using client public key
        unsigned char * buff = pubKeyToChar(clientPubKey); // Buffer for key
        unsigned char * encryptedNonce = (unsigned char *) malloc(sizeof(nonce) + 16);
        int encryptedLength; 
        if (!buff) {
            cerr << "Error allocation for public key buffer failed\n";
            close(clientfd);
        }
        if (!encryptedNonce) {
            cerr << "Error allocation for encrypted nonce buffer failed\n";
            close(clientfd);
        }
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            cerr << "Error context creation failed\n";
            close(clientfd);
        }
        ret = EVP_EncryptInit(ctx, EVP_aes_128_ecb(), buff, NULL);
        if (!ret) {
            cerr << "Error during encryption initialization\n";
            close(clientfd);
        }
        ret = EVP_EncryptUpdate(ctx, encryptedNonce, &encryptedLength, (unsigned char *) nonce, sizeof(nonce));
        if (!ret) {
            cerr << "Error during encryption update\n";
            close(clientfd);
        }
        ret = EVP_EncryptFinal(ctx, encryptedNonce + encryptedLength, &encryptedLength);
        if (!ret) {
            cerr << "Error during encryption finalization\n";
            close(clientfd);
        }
        free(ctx);
        // PROBLEM HERE FREEING THE FUCKING BUFFER
        free(buff);
        cout << "buffer free\n";

        // Send the challenge to the client
        sendChar(socketfd, encryptedNonce); // Function from utils.h
        cout << "nonce sent\n";
        free(encryptedNonce);
    }

    // Receive and check client response to the challenge
    int authenticateClient() {
        
        int ret;

        // Receive client's response
        unsigned char * clientResponse = readChar(clientfd); // Function from utils.h
        if (!clientResponse) {
            cerr << "Error cannot read client response\n";
            close(clientfd);
        }

        // Compare response with the nonce sent previously and if it does not match, disconnect client
        ret = memcmp(nonce, clientResponse, 96);
        free(clientResponse);
        if (ret) {
            // Client not authenticated
            close(clientfd);
            return 0;
        } else {
            // Client succesfully authenticated
            return 1;
        }
    }

    // Generate private session key and sends pub key to the client so he can derive the session key
    void generateSessionKey() {

        int ret;

        // Receive public key from client
        unsigned char * buffer  = readChar(clientfd);
        EVP_PKEY * clientDHKey = charToPubkey(buffer);
        free(buffer);

        // Retreive dh params
        DH * DH = dhMap[clientUsername];
        ret = EVP_PKEY_set1_DH(dhparams, DH);
        DH_free(DH);
        if (!ret) {
            cerr << "Error loading DH parameters\n";
            close(clientfd);
        }

        // Generate public key to send back to the client
        EVP_PKEY_CTX * ctxParam = EVP_PKEY_CTX_new(dhparams, NULL);
        ret = EVP_PKEY_keygen_init(ctxParam);
        if (!ret) {
            cerr << "Error during DH keypair generation (initialization failed)\n";
            exit(1);
        }
        ret = EVP_PKEY_keygen(ctxParam, &tempKey);
        if (!ret) {
            cerr << "Error during DH keypair generation (generation failed)\n";
        }
        EVP_PKEY_CTX_free(ctxParam);

        // Send the public key to the client
        unsigned char * keychar = pubKeyToChar(tempKey);
        sendChar(clientfd, keychar); // Function from utils.h

        // Derivation
        size_t sessionDHLength;
        EVP_PKEY_CTX * ctx = EVP_PKEY_CTX_new(dhparams, NULL);
        if (!ctx) {
            cerr << "Error creating context for DH derivation\n";
            close(clientfd);
        }
        ret = EVP_PKEY_derive_init(ctx);
        if (!ret) {
            cerr << "Error during derivation initialization\n";
            close(clientfd);
        }
        ret = EVP_PKEY_derive_set_peer(ctx, clientDHKey);
        if (!ret) {
            cerr << "Error setting peer's key during derivation\n";
            close(clientfd);
        }
        ret = EVP_PKEY_derive(ctx, NULL, &sessionDHLength);
        if (!ret) {
            cerr << "Error determining sessionDH key length during derivation\n";
            close(clientfd);
        }
        sessionDH = (unsigned char *) malloc(sessionDHLength);
        ret = EVP_PKEY_derive(ctx, sessionDH, &sessionDHLength);
        if (!ret) {
            cerr << "Error derivating secret during Diffie-Hellman\n";
            close(clientfd);
        }
        
        // Free everything
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(clientDHKey);
        EVP_PKEY_free(dhparams);
    }

};

int main() {

    int ret;

    Server serv;
    serv.updateDHMap();
    cout << "Starting server...\n";
    serv.startSocket();
    cout << "Socket connection established, waiting for client connection\n";

    while (1) {

        // For each client in queue we do the following
        serv.acceptClient();
        cout << "Client " << serv.getClientUsername() << " connected, waiting for authentication...\n";
        serv.createChallenge();
        cout << "Challenge sent, waiting for " << serv.getClientUsername() << " to answer\n";
        ret = serv.authenticateClient();

        // Different cases depending on client identication
        if (ret) {
            // If client is authenticated we go on
            cout << "Client " << serv.getClientUsername() << " successfuly authenticated\n";
        } else {
            // Else we stop the operations here and wait for next client
            cout << "Client " << serv.getClientUsername() << " had not been authenticated\n";
            cout << "Client disconnected\n";
        }
    }

    return 0;
}