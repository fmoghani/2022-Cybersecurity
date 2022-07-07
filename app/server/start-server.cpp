

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
// #include <filesystem>
#include <experimental/filesystem>
#include <cerrno>
#include "users_infos/khabib/DH.h"
#include "../utils.h"
#include "../const.h"

using namespace std;

class Server
{

    // Sockets
    int socketfd, clientfd;
    struct sockaddr_in serverAddr, clientAddr;

    // Client infos
    string clientUsername;
    unsigned char * nonce;

    // Map containing all the get_DH2048() functions specific to each user
    std::map<std::string, DH *> dhMap;

    // Keys
    EVP_PKEY * clientPubKey;
    EVP_PKEY * prvKey;

    // Diffie-Hellman session keys
    EVP_PKEY * dhparams;
    EVP_PKEY * serverDHPubKey;
    unsigned char * sessionDH;
    unsigned char * sharedSecret;
    unsigned char * sessionKey;

public:

    // Get username
    string getClientUsername() {
        return clientUsername;
    }

    // Generate a random and fresh nonce
    int createNonce() {

        int ret;

        // Generate a 16 bytes random number to ensure unpredictability
        unsigned char * randomBuf = (unsigned char *) malloc(randBytesSize);
        if (!randomBuf) {
            cerr << "Error allocating unsigned buffer for random bytes\n";
            close(clientfd);
            return 0;
        }
        RAND_poll();
        ret = RAND_bytes(randomBuf, randBytesSize);
        if (!ret) {
            cerr << "Error generating random bytes\n";
            close(clientfd);
            return 0;
        }
        char * random = (char *) malloc(randBytesSize);
        if (!random) {
            cerr << "Error allocating buffer for random bytes *\n";
            close(clientfd);
            return 0;
        }
        memcpy(random, randomBuf, randBytesSize);
        free(randomBuf);

        // Generate a char timestamp to ensure uniqueness
        char * now = (char *) malloc(timeBufferSize);
        if (!now) {
            cerr << "Error allocating buffer for date and time\n";
            close(clientfd);
            return 0;
        }
        time_t currTime;
        tm * currentTime;
        time(&currTime);
        currentTime = localtime(&currTime);
        if (!currentTime) {
            cerr << "Error creating pointer containing current time\n";
            close(clientfd);
            return 0;
        }
        ret = strftime(now, timeBufferSize, "%Y%j%H%M%S", currentTime);
        if (!ret) {
            cerr << "Error putting time in a char array\n";
            close(clientfd);
            return 0;
        }

        // Concatenate random number and timestamp
        char * tempNonce = (char *) malloc(nonceSize);
        if (!tempNonce) {
            cerr << "Error allocating char buffer for nonce\n";
            close(clientfd);
            return 0;
        }
        memcpy(tempNonce, random, randBytesSize);
        free(random);
        strcat(tempNonce, now);
        free(now);
        nonce = (unsigned char *) malloc(nonceSize);
        if (!nonce) {
            cerr << "Error allocating buffer for nonce\n";
            close(clientfd);
            return 0;
        }
        memcpy(nonce, tempNonce, nonceSize);
        free(tempNonce);

        return 1;
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
        if (!socketfd)
        {
            cerr << "Error creating socket"
                 << "\n";
            exit(1);
        }

        // Socket parameters setup
        memset(&serverAddr, 0, sizeof(serverAddr));
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(PORT);
        serverAddr.sin_addr.s_addr = INADDR_ANY;

        // Bind the socket to the adress
        ret = bind(socketfd, (sockaddr *)&serverAddr, sizeof(serverAddr));
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

        int ret;

        // Extract the first connexion in the queue
        int len = sizeof(clientAddr);
        clientfd = accept(socketfd, (sockaddr *)&clientAddr, (socklen_t *)&len);
        if (clientfd < 0) {
            cerr << "Error cannot accept client";
        }

        // Receive username et convert it back to string
        unsigned char * buffer = (unsigned char *) malloc(sizeof(int)); // Dummy allocation to avoid double free error
        ret = readChar(clientfd, buffer);
        if (!ret) {
            cerr << "Error reading client username\n";
            close(clientfd);
        }
        clientUsername = std::string(reinterpret_cast<char *>(buffer));
        free(buffer);
    }

    void generateSessionKey() {

        int ret;

        // Create a random key of 256 bytes
        sharedSecret = (unsigned char *) malloc(sessionKeySize);
        if (!sharedSecret) {
            cerr << "Symmetric session key could not be allocated\n";
            close(clientfd);
        }
        RAND_poll();
        ret = RAND_bytes(sharedSecret, sessionKeySize);
        if (!ret) {
            cerr << "Bytes for symmetric key could not be generated\n";
            close(clientfd);
        }

        // Hash the secret to get session key
        ret = createHash(sharedSecret, sessionKeySize, sessionKey);
        if (!ret) {
            cerr << "Error creating hash of the shared secret\n";
            close(clientfd);
        }
    }

    // Create and send a challenge to authenticate client
    void shareKey() {

        int ret;

        // Retreive user's pubkey to encrypt session key
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

        // Encrypt session key using client public key

        // Variables for encryption
        const EVP_CIPHER * cipher = EVP_aes_256_cbc();
        int encryptedKeySize = EVP_PKEY_size(clientPubKey);
        int ivLength = EVP_CIPHER_iv_length(cipher);
        int blockSize = EVP_CIPHER_block_size(cipher);
        int cipherSize = sessionKeySize + blockSize;
        int encryptedSize = 0;

        // Create buffers for encrypted session key, iv, encrypted key
        unsigned char * iv = (unsigned char *) malloc(ivLength);
        unsigned char * encryptedKey = (unsigned char *) malloc(encryptedKeySize);
        unsigned char * encryptedSharedSecred = (unsigned char *) malloc(cipherSize);
        if (!iv || !encryptedKey || !encryptedSharedSecred) {
            cout << "Error allocating buffers during nonce encryption\n";
            close(clientfd);
        }

        // Digital envelope
        int bytesWritten = 0;
        EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            cerr << "Error creating context for nonce encryption\n";
            close(clientfd);
        }
        ret = EVP_SealInit(ctx, cipher, &encryptedKey, &encryptedKeySize, iv, &clientPubKey, 1);
        if (ret <= 0) {
            cerr << "Error during initialization of encrypted nonce envelope\n";
            close(clientfd);
        }
        ret = EVP_SealUpdate(ctx, encryptedSharedSecred, &bytesWritten, sharedSecret, sessionKeySize);
        if (ret <= 0) {
            cerr << "Error during update of encrypted nonce envelope\n";
            close(clientfd);
        }
        encryptedSize += bytesWritten;
        ret = EVP_SealFinal(ctx, encryptedSharedSecred + encryptedSize, &bytesWritten);
        if (ret <= 0) {
            cerr << "Error during finalization of encrypted nonce envelope\n";
            close(clientfd);
        }
        EVP_CIPHER_CTX_free(ctx);

        // Send the envelope to the client
        ret = sendInt(clientfd, encryptedSize);
        if (!ret) {
            cerr << "Error sending encrypted size to " << clientUsername << "\n";
            close(clientfd);
        }
        ret = sendChar(clientfd, encryptedKey);
        if (!ret) {
            cerr << "Error sending encrypted key to " << clientUsername << "\n";
            close(clientfd);
        }
        free(encryptedKey);
        ret = sendChar(clientfd, iv);
        if (!ret) {
            cerr << "Error sending iv to " << clientUsername << "\n";
            close(clientfd);
        }
        free(iv);
        ret = sendChar(clientfd, encryptedSharedSecred); // Function from utils.h
        if (!ret) {
            cerr << "Error sending encrypted session key to " << clientUsername << "\n";
            close(clientfd);
        }
        free(encryptedSharedSecred);
    }

    int sendEncryptedNonce() {

        int ret;

        // First create nonce
        ret = createNonce();
        if (!ret) {
            cerr << "Error creating nonce\n";
            close(clientfd);
            return 0;
        }

        // Encrypt nonce using symmetric key
        int encryptedSize;
        const EVP_CIPHER * cipher = EVP_aes_256_cbc();
        unsigned char * encryptedNonce = (unsigned char *) malloc(nonceSize + EVP_CIPHER_block_size(cipher));
        unsigned char * iv = (unsigned char *) malloc(EVP_CIPHER_iv_length(cipher));
        if (!encryptedNonce || !iv) {
            cerr << "Error allocating buffers for encryptedNonce and iv\n";
            close(clientfd);
            return 0;
        }
        ret = encryptSym(nonce, nonceSize, encryptedNonce, iv, sessionKey);
        if (!ret) {
            cerr << "Error encrypting the nonce\n";
            close(clientfd);
            return 0;
        }
        encryptedSize = ret;

        // Send encrypted nonce, encryptedSize and iv
        ret = sendInt(clientfd, encryptedSize);
        if (!ret) {
            cerr << "Error sending encrypted size for nonce to client\n";
            close(clientfd);
            return 0;
        }
        ret = sendChar(clientfd, encryptedNonce);
        if (!ret) {
            cerr << "Error sending encrypted nonce to client\n";
            close(clientfd);
            return 0;
        }
        ret = sendChar(clientfd, iv);
        if (!ret) {
            cerr << "Error sending iv for nonce decryption to client\n";
            close(clientfd);
            return 0;
        }

        return 1;
    }

    // Receive and check client response to the challenge
    int authenticateClient() {

        int ret;

        // Receive client's proof of identity
        unsigned char * clientProof = (unsigned char *) malloc(sizeof(int));
        ret = readChar(clientfd, clientProof); // Function from utils.h
        if (!ret) {
            cerr << "Error cannot read client response\n";
            close(clientfd);
        }

        // Compare response with the nonce sent previously and if it does not match, disconnect client
        ret = memcmp(nonce, clientProof, nonceSize);
        cout << nonce << "\n";
        cout << clientProof << "\n";
        free(clientProof);
        free(nonce);
        if (ret) {
            // Client not authenticated
            close(clientfd);
            return 0;
        }
        else {
            // Client succesfully authenticated
            return 1;
        }
    }
};

int main() {

    int ret;

    Server serv;
    serv.updateDHMap();
    cout << "Starting server...\n";
    serv.startSocket();
    cout << "Socket connection established\n";

    while (1) {

        cout << "Waiting for connection...\n";
        serv.acceptClient();
        cout << "Client " << serv.getClientUsername() << " connected\n";
        serv.generateSessionKey();
        cout << "Session symmetric key generated\n";
        serv.shareKey();
        cout << "Session symmetric key sent to client\n";
        serv.sendEncryptedNonce();
        cout << "Encrypted nonce sent, waiting for client's proof of identity\n";

        // Authenticate client
        ret = serv.authenticateClient();
        if (!ret)
        {
            cout << "Client not authenticated\n";
            continue;
        }
        cout << "Client " << serv.getClientUsername() << " authenticated\n";
    }

    return 0;
}