

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
        char * tempNonce = (char *) malloc(randBytesSize + timeBufferSize);
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
    int acceptClient() {

        int ret;

        // Extract the first connexion in the queue
        int len = sizeof(clientAddr);
        clientfd = accept(socketfd, (sockaddr *)&clientAddr, (socklen_t *)&len);
        if (clientfd < 0) {
            cerr << "Error cannot accept client";
            return 0;
        }

        // Receive username et convert it back to string
        int * usernameLen = (int *) malloc(sizeof(int));
        if (!usernameLen) {
            cerr << "Error allocating buffer for username length\n";
            close(clientfd);
            return 0;
        }
        ret = readInt(clientfd, usernameLen);
        if (!ret) {
            cerr << "Error reading username length\n";
            close(clientfd);
            return 0;
        }
        unsigned char * buffer = (unsigned char *) malloc(*usernameLen);
        if (!buffer) {
            cerr << "Error allocating buffer for username\n";
            close(clientfd);
            return 0;
        }
        ret = read(clientfd, buffer, *usernameLen);
        if (!ret) {
            cerr << "Error reading client username\n";
            close(clientfd);
            return 0;
        }
        clientUsername = std::string(reinterpret_cast<char *>(buffer));
        free(usernameLen);
        free(buffer);

        return 1;
    }

    int generateSessionKey() {

        int ret;

        // Create a random key for aes 256
        const EVP_CIPHER * cipher = EVP_aes_256_cbc();
        unsigned char * secret = (unsigned char *) malloc(EVP_CIPHER_key_length(cipher));
        if (!secret) {
            cerr << "Symmetric session key could not be allocated\n";
            close(clientfd);
            return 0;
        }
        RAND_poll();
        ret = RAND_bytes(secret, sessionKeySize);
        if (!ret) {
            cerr << "Bytes for symmetric key could not be generated\n";
            close(clientfd);
            return 0;
        }

        // Hash the secret to get session key
        sessionKey = (unsigned char *) malloc(EVP_MD_size(EVP_sha256()));
        ret = createHash(secret, sessionKeySize, sessionKey);
        if (!ret) {
            cerr << "Error creating hash of the shared secret\n";
            close(clientfd);
            return 0;
        }
        bzero(secret, EVP_CIPHER_key_length(cipher));
        free(secret);

        return 1;
    }

    // Create and send a challenge to authenticate client
    int shareKey() {

        int ret;

        // Retreive user's pubkey to encrypt session key
        string path = "users_infos/" + clientUsername + "/pubkey.pem";
        FILE * keyFile = fopen(path.c_str(), "r");
        if (!keyFile) {
            cerr << "Error could not open client " << clientUsername << " public key file\n";
            close(clientfd);
            return 0;
        }
        clientPubKey = PEM_read_PUBKEY(keyFile, NULL, NULL, NULL);
        fclose(keyFile);
        if (!clientPubKey) {
            cerr << "Error could not read client " << clientUsername << " public key from pem file\n";
            close(clientfd);
            return 0;
        }

        // Encrypt session key using client public key

        // Variables for encryption
        const EVP_CIPHER * cipher = EVP_aes_256_cbc();
        int encryptedKeySize = EVP_PKEY_size(clientPubKey);
        int ivLength = EVP_CIPHER_iv_length(cipher);
        int blockSizeEnvelope = EVP_CIPHER_block_size(cipher);
        int cipherSize = sessionKeySize + blockSizeEnvelope;
        int encryptedSize = 0;

        // Create buffers for encrypted session key, iv, encrypted key
        unsigned char * iv = (unsigned char *) malloc(ivLength);
        unsigned char * encryptedKey = (unsigned char *) malloc(encryptedKeySize);
        unsigned char * encryptedSecret = (unsigned char *) malloc(cipherSize);
        if (!iv || !encryptedKey || !encryptedSecret) {
            cout << "Error allocating buffers during nonce encryption\n";
            close(clientfd);
            return 0;
        }

        // Digital envelope
        int bytesWritten = 0;
        EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            cerr << "Error creating context for nonce encryption\n";
            close(clientfd);
            return 0;
        }
        ret = EVP_SealInit(ctx, cipher, &encryptedKey, &encryptedKeySize, iv, &clientPubKey, 1);
        if (ret <= 0) {
            cerr << "Error during initialization of encrypted nonce envelope\n";
            close(clientfd);
            return 0;
        }
        ret = EVP_SealUpdate(ctx, encryptedSecret, &bytesWritten, sessionKey, sessionKeySize);
        if (ret <= 0) {
            cerr << "Error during update of encrypted nonce envelope\n";
            close(clientfd);
            return 0;
        }
        encryptedSize += bytesWritten;
        ret = EVP_SealFinal(ctx, encryptedSecret + encryptedSize, &bytesWritten);
        if (ret <= 0) {
            cerr << "Error during finalization of encrypted nonce envelope\n";
            close(clientfd);
            return 0;
        }
        EVP_CIPHER_CTX_free(ctx);

        // TEST
        cout << "sessionKey :\n";
        BIO_dump_fp(stdout, (const char *) sessionKey, sessionKeySize);

        // Send the encrypted key
        ret = sendInt(clientfd, encryptedKeySize);
        if (!ret) {
            cerr << "Error sending encrypted key size\n";
            close(clientfd);
            return 0;
        }
        ret = send(clientfd, encryptedKey, encryptedKeySize, 0);
        if (ret <= 0) {
            cerr << "Error sending encrypted key to " << clientUsername << "\n";
            close(clientfd);
            return 0;
        }
        free(encryptedKey);

        // Send the encrypted session key
        ret = sendInt(clientfd, encryptedSize);
        if (!ret) {
            cerr << "Error sending encrcypted size\n";
            close(clientfd);
            return 0;
        }
        ret = send(clientfd, encryptedSecret, encryptedSize, 0);
        if (ret <= 0) {
            cerr << "Error sending encrypted session key to " << clientUsername << "\n";
            close(clientfd);
        }
        free(encryptedSecret);

        // Send the iv
        ret = sendInt(clientfd, ivLength);
        if (!ret) {
            cerr << "Error sending iv size\n";
            close(clientfd);
            return 0;
        }
        ret = send(clientfd, iv, ivLength, 0);
        if (!ret) {
            cerr << "Error sending iv\n";
            close(clientfd);
            return 0;
        }
        free(iv);

        return 1;    
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
        unsigned char * encryptedNonce = (unsigned char *) malloc(nonceSize + blockSize);
        unsigned char * iv = (unsigned char *) malloc(ivSize);
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

        // TEST
        cout << "nonce :\n";
        BIO_dump_fp(stdout, (const char *) nonce, nonceSize);
        cout << "encrypted size = " << encryptedSize << "\n";

        // Send encrypted nonce
        ret = sendInt(clientfd, encryptedSize);
        if (!ret) {
            cerr << "Error sending encrypted size for nonce to client\n";
            close(clientfd);
            return 0;
        }
        ret = send(clientfd, encryptedNonce, encryptedSize, 0);
        if (ret <= 0) {
            cerr << "Error sending encrypted nonce to client\n";
            close(clientfd);
            return 0;
        }

        // Send iv
        ret = send(clientfd, iv, ivSize, 0);
        if (ret <= 0) {
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

    void test() {

        // Test the send and receive functions

        int ret;

        // For small messages
        int * sizeSmall = (int *) malloc(sizeof(int));
        readInt(clientfd, sizeSmall);
        cout << "size received : " << *sizeSmall << "\n";
        unsigned char * shortmsg = (unsigned char *) malloc(*sizeSmall);
        ret = read(clientfd, shortmsg, *sizeSmall);
        cout << "bytes read : " << ret << "\n";
        BIO_dump_fp(stdout, (const char *) shortmsg, *sizeSmall);
        free(sizeSmall);
        free(shortmsg);

        // For int
        // int * n;
        // ret = readInt(clientfd, n);
        // if (!ret) {
        //     cerr << "readInt failed\n";
        //     exit(1);
        // }
        // if (*n != 1805) {
        //     cerr << "Test failed\n";
        // } else {
        //     cerr << "Test passed, n = " << *n << "\n";
        // }

        // For big messages
        int * sizeLong = (int *) malloc(sizeof(int));
        readInt(clientfd, sizeLong);
        cout << "size of long message = " << *sizeLong << "\n";
        unsigned char * longmsg = (unsigned char *) malloc(*sizeLong);
        ret = read(clientfd, longmsg, *sizeLong);
        cout << "bytes read : " << ret << "\n";
        cout << "long msg :\n";
        BIO_dump_fp(stdout, (const char *) longmsg, *sizeLong);
        free(sizeLong);
        free(longmsg);
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
        ret = serv.acceptClient();
        if (!ret) {
            cerr << "Error accepting client connection, communication stopped\n\n";
            continue;
        }
        cout << "Client " << serv.getClientUsername() << " connected\n";

        ret = serv.generateSessionKey();
        if (!ret) {
            cerr << "Error generating session key, communication stopped\n\n";
            continue;
        }
        cout << "Session symmetric key generated\n";

        ret = serv.shareKey();
        if (!ret) {
            cerr << "Error sharing key to the client, communication stopped\n\n";
            continue;
        }
        cout << "Session symmetric key sent to client\n";

        ret = serv.sendEncryptedNonce();
        if (!ret) {
            cerr << "Error sending encrypted nonce to the client, communication stopped\n\n";
            continue;
        }
        cout << "Encrypted nonce sent, waiting for client's proof of identity\n";

        // // Authenticate client
        // ret = serv.authenticateClient();
        // if (!ret)
        // {
        //     cout << "Client not authenticated\n";
        //     continue;
        // }
        // cout << "Client " << serv.getClientUsername() << " authenticated\n";
    }

    return 0;
}