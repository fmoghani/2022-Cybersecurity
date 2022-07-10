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
#include <fstream>
#include <cerrno>
#include <map>
#include "user_infos/DH.h"
#include "../utils.h"
#include "../const.h"

using namespace std;

#define PORT 1805

class Client {

    // Sockets
    int socketfd, clientfd;
    struct sockaddr_in serverAddr;

    // Client variables
    unsigned char * nonce;
    unsigned char * clientResponse;
    string username;
    
    // Diffie-Hellman session keys
    EVP_PKEY * dhparams;
    EVP_PKEY * clientDHPubKey; // Client public key
    unsigned char * sessionDH;
    unsigned char * sessionKey;

    public :

    // Create a socket connexion
    void connectClient() {

        int ret;

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
        if (clientfd < 0) {
            cerr << "Error connecting client to the server\n";
            exit(1);
        }

        // Send client username to the server
        string path = "./user_infos/username.txt";
        std::ifstream file;
        file.open(path);
        getline(file, username);
        int usernameLen = username.size();
        ret = sendInt(socketfd, usernameLen);
        if (!ret) {
            cerr << "Error sending username length\n";
            exit(1);
        }
        ret = send(socketfd, username.c_str(), username.size(), 0);
        if (ret <= 0) {
            cerr << "Error sending username to the server\n";
            exit(1);
        }
        file.close();
    }

    // Authenticate server
    void authenticateServer() {

        int ret;

        // Read CA certificate
        string CACertPath = "../certificates/CAcert.pem";
        X509 * CACert = readCertificate(CACertPath); // Function from utils.h
        if (!CACert) {
            cerr << "Error reading server CA certificate\n";
            exit(1);
        }

        // Read CA crl
        string CACrlPath = "../certificates/CAcrl.pem";
        X509_CRL * CACrl = readCrl(CACrlPath); // Function from utils.h
        if (!CACrl) {
            cerr << "Error reading CA Crl\n";
            exit(1);
        }

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
        string serverCertPath = "../certificates/servcert.pem";
        X509 * serverCert = readCertificate(serverCertPath); // Function from utils.h
        if (!ret) {
            cerr << "Error reading server certificate\n";
            exit(1);
        }

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
        if (ret <= 0) {
            cerr << "Error server not authenticated\n";
            exit(1);
        }
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
    }


    // Receive server's envelope and decrypt it to retreive session key
    void retreiveSessionKey() {

        int ret;

        // Receive encrypted key
        int * sizeKey = (int * ) malloc(sizeof(int));
        if (!sizeKey) {
            cerr << "Error allocating buffer for encrypted key size\n";
            exit(1);
        }
        ret = readInt(socketfd, sizeKey);
        if (!ret) {
            cerr << "Error reading enrypted key size\n";
            exit(1);
        }
        int encryptedKeySize = (*sizeKey); // Divided by 8 because encrypted key size is sent in bits
        free(sizeKey);
        unsigned char * encryptedKey = (unsigned char *) malloc(encryptedKeySize);
        if (!encryptedKey) {
            cerr << "Error allocating buffer for encrypted key\n";
        }
        ret = read(socketfd, encryptedKey, encryptedKeySize);
        if(ret <= 0) {
            cerr << "Error reading encrypted key\n";
            exit(1);
        }

        // Receive encrypted session key
        int * size = (int *) malloc(sizeof(int));
        if (!size) {
            cerr << "Error allocating buffer for encrypted session key size\n";
            exit(1);
        }
        ret = readInt(socketfd, size);
        if (!ret) {
            cerr << "Error reading encrypted session key size\n";
            exit(1);
        }
        int encryptedSize = *size;
        free(size);
        unsigned char * encryptedSecret = (unsigned char *) malloc(encryptedSize);
        if (!encryptedSecret) {
            cerr << "Error allocating buffer for encrypted session key\n";
            exit(1);
        }
        ret = read(socketfd, encryptedSecret, encryptedSize);
        if (ret <= 0) {
            cerr << "Error reading encrypted session key\n";
            exit(1);
        }

        // Receive iv
        int * sizeIv = (int *) malloc(sizeof(int));
        if (!sizeIv) {
            cerr << "Error allocating buffer for iv size\n";
            exit(1);
        }
        ret = readInt(socketfd, sizeIv);
        if (!ret) {
            cerr << "Error reading iv\n";
            exit(1);
        }
        int ivLength = *sizeIv;
        free(sizeIv);
        unsigned char * iv = (unsigned char *) malloc(ivLength);
        if (!iv) {
            cerr << "Error allocating buffer for iv\n";
            exit(1);
        }
        ret = read(socketfd, iv, ivLength);
        if(ret <= 0) {
            cerr << "Error reading iv\n";
            exit(1);
        }

        // Retreive user's prvkey
        string path = "user_infos/key.pem";
        FILE * keyFile = fopen(path.c_str(), "r");
        if (!keyFile) {
            cerr << "Error could not open client private key file\n";
            exit(1);
        }
        const char * password = "password";
        EVP_PKEY * clientPrvKey = PEM_read_PrivateKey(keyFile, NULL, NULL, (void *) password);
        fclose(keyFile);
        if (!clientPrvKey) {
            cerr << "Error cannot read client private key from pem file\n";
            exit(1);
        }

        // Decrypt the challenge envelope
        
        // Useful variables
        const EVP_CIPHER * cipher = EVP_aes_256_cbc();
        int decryptedSize;

        // Create buffer for session key
        unsigned char * sessionKey = (unsigned char *) malloc(sessionKeySize);
        if (!sessionKey) {
            cerr << "Error allocating buffer for session key\n";
            exit(1);
        }

        // Digital envelope
        int  bytesWritten;
        EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            cerr << "Error creating context for envelope decryption\n";
            exit(1);
        }
        ret = EVP_OpenInit(ctx, cipher, encryptedKey, encryptedKeySize, iv, clientPrvKey);
        if (ret <= 0) {
            cerr << "Error during initialization for envelope decryption\n";
            exit(1);
        }
        ret = EVP_OpenUpdate(ctx, sessionKey, &bytesWritten, encryptedSecret, encryptedSize);
        if (ret <= 0) {
            cerr << "Error during update for envelope decryption\n";
            exit(1);
        }
        decryptedSize = bytesWritten;
        ret = EVP_OpenFinal(ctx, sessionKey + decryptedSize, &bytesWritten);
        decryptedSize += bytesWritten;
        EVP_CIPHER_CTX_free(ctx);
        free(encryptedKey);
        free(iv);
        free(encryptedSecret);

        // TEST
        cout << "session key :\n";
        BIO_dump_fp(stdout, (const char *) sessionKey, sessionKeySize);
    }

    // Send to the server a proof of identity using the nonce
    void proveIdentity() {

        int ret;

        // Receive encrypted nonce
        int * size = (int *) malloc(sizeof(int));
        if (!size) {
            cerr << "Error allocating buffer for size of encrypted nonce\n";
        }
        ret = readInt(socketfd, size);
        if (!ret) {
            cerr << "Error reading encrypted nonce size\n";
            exit(1);
        }
        int encryptedSize = *size;
        free(size);
        unsigned char * encryptedNonce = (unsigned char *) malloc(encryptedSize);
        if (!encryptedNonce) {
            cerr << "Error allocating buffer for encrypted nonce\n";
            exit(1);
        }
        ret = read(socketfd, encryptedNonce, encryptedSize);
        if (ret <= 0) {
            cerr << "Error reading encrypted nonce\n";
            exit(1);
        }

        // Receive iv
        unsigned char * iv = (unsigned char *) malloc(ivSize);
        if (!iv) {
            cerr << "Error allocating buffer for iv\n";
            exit(1);
        }
        ret = read(socketfd, iv, ivSize);
        if (ret <= 0) {
            cerr << "Error reading iv for nonce decryption\n";
            exit(1);
        }

        // Decrypt nonce using the shared session key
        unsigned char * nonce = (unsigned char *) malloc(encryptedSize);
        if (!nonce) {
            cerr << "Error allocating buffer for decrypted nonce\n";
            exit(1);
        }
        ret = decryptSym(encryptedNonce, encryptedSize, nonce, iv, sessionKey);
        if (!ret) {
            cerr << "Error encrypting the nonce\n";
            exit(1);
        }

        // TEST
        cout << "nonce :\n";
        BIO_dump_fp(stdout,(const char *) nonce, nonceSize);

        // Send nonce to the server
        ret = send(socketfd, nonce, nonceSize, 0);
        if (ret <= 0) {
            cerr << "Error sending nonce to the server\n";
            exit(1);
        }
    }

    void test() {

        // Test the send and receive functions

        int ret;

        // For small messages
        int size = 16;
        unsigned char * shortmsg = (unsigned char *) malloc(size);
        RAND_bytes(shortmsg, 16);
        BIO_dump_fp(stdout, (const char *) shortmsg, size);
        sendInt(socketfd, size);
        ret = send(socketfd, shortmsg, size, 0);
        cout << "bytes sent : " << ret << "\n";
        free(shortmsg);

        // For int
        // int n = 1805;
        // ret = sendInt(socketfd, n);
        // if (!ret) {
        //     cerr << "sendInt failed\n";
        //     exit(1);
        // }

        // For big messages
        int sizeLong = 64;
        unsigned char * longmsg = (unsigned char *) malloc(sizeLong);
        RAND_bytes(longmsg, sizeLong);
        cout << "long msg :\n";
        BIO_dump_fp(stdout, (const char *) longmsg, sizeLong);
        sendInt(socketfd, sizeLong);
        ret = send(socketfd, longmsg, sizeLong, 0);
        cout << "bytes sent for long : " << ret << "\n";
        free(longmsg);
    }

};

int main() {

    Client user1;

    cout << "Starting client...\n";
    user1.connectClient();
    cout << "Client successfuly connected to the server\n";

    user1.authenticateServer();
    cout << "Server authenticated, waiting for server's envelope...\n";
    
    user1.retreiveSessionKey();
    cout << "Session key received\n";

    // user1.proveIdentity();
    // cout << "Proof of identity sent\n";

    return 0;
}