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
        send(socketfd, username.c_str(), username.size(), 0);
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

        unsigned char * encryptedKey = (unsigned char *) malloc(sessionKeySize);
        ret = read(socketfd, encryptedKey, sessionKeySize);
        if(ret <= 0) {
            cerr << "Error reading encrypted key from server\n";
            exit(1);
        }
        cout << "ret = " << ret << "\n";
        cout << "encrypted key : " << encryptedKey << "\n";
        int ivLen = EVP_CIPHER_iv_length(EVP_aes_256_cbc());
        unsigned char * iv = (unsigned char *) malloc(ivLen);
        ret = readChar(socketfd, iv);
        // ret = read(socketfd, iv, ivLen);
        if(ret <= 0) {
            cerr << "Error reading iv from server\n";
            exit(1);
        }
        cout << "ret = " << ret << "\n";
        cout << "iv : " << iv << "\n";
        unsigned char * encryptedSharedSecret = (unsigned char *) malloc(sessionKeySize);
        ret = read(clientfd, encryptedSharedSecret, sessionKeySize);
        if (ret <= 0) {
            cerr << "Error reading encrypted shared secret from server\n";
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
        int decryptedSize = 0;

        // Create buffer for shared secret
        unsigned char * sharedSecret = (unsigned char *) malloc(sessionKeySize);
        if (!sharedSecret) {
            cerr << "Error allocating buffer for session key\n";
            exit(1);
        }

        // TEST
        cout << "iv length : " << strlen((char *) iv) << "\n";
        cout << "iv length theo : " << EVP_CIPHER_iv_length(cipher) << "\n";
        cout << "encrypted key size : " << strlen((char *) encryptedKey) << "\n";
        if (encryptedKey[sessionKeySize] == NULL) {
            cerr << "Error\n";
        } else {
            cout << "ok\n";
        }

        // Digital envelope
        int  bytesWritten;
        EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            cerr << "Error creating context for envelope decryption\n";
            exit(1);
        }
        ret = EVP_OpenInit(ctx, cipher, encryptedKey, sessionKeySize, iv, clientPrvKey);
        if (ret <= 0) {
            cerr << "Error during initialization for envelope decryption\n";
            exit(1);
        }
        ret = EVP_OpenUpdate(ctx, sharedSecret, &bytesWritten, encryptedSharedSecret, sessionKeySize);
        if (ret <= 0) {
            cerr << "Error during update for envelope decryption\n";
            exit(1);
        }
        decryptedSize += bytesWritten;
        ret = EVP_OpenFinal(ctx, sharedSecret + decryptedSize, &bytesWritten);
        if (ret <= 0) {
            cerr << "Error during finalization for envelope decryption\n";
            exit(1);
        }
        decryptedSize += bytesWritten;
        EVP_CIPHER_CTX_free(ctx);
        free(encryptedKey);
        free(iv);
        free(encryptedSharedSecret);

        // Hash the shared secret to get the session key
        ret = createHash(sharedSecret, sessionKeySize, sessionKey);
        if (!ret) {
            cerr << "Error creating hash of the shared secret\n";
            exit(1);
        }
    }

    // Send to the server a proof of identity using the nonce
    void proveIdentity() {

        int ret;

        // Receive encrypted nonce
        int encryptedSize;
        ret = readInt(socketfd, &encryptedSize);
        if (!ret) {
            cerr << "Error reading encrypted size for nonce decryption\n";
            exit(1);
        }
        unsigned char * encryptedNonce = (unsigned char *) malloc(sizeof(int));
        ret = readChar(socketfd, encryptedNonce);
        if (!ret) {
            cerr << "Error reading encrypted nonce\n";
            exit(1);
        }
        unsigned char * iv = (unsigned char *) malloc(sizeof(int));
        ret = readChar(socketfd, iv);
        if (!ret) {
            cerr << "Error reading iv for nonce decryption\n";
            exit(1);
        }

        // Decrypt nonce using the shared session key
        unsigned char * nonce = (unsigned char *) malloc(nonceSize);
        ret = decryptSym(encryptedNonce, encryptedSize, nonce, iv, sessionKey);
        if (!ret) {
            cerr << "Error encrypting the nonce\n";
            exit(1);
        }

        // Send nonce to the server
        ret = sendChar(socketfd, nonce);
        if (!ret) {
            cerr << "Error sending nonce to the server\n";
            exit(1);
        }
    }

    void test() {

        // Test the send and receive functions

        int ret;

        // For small messages
        unsigned char * shortmsg = (unsigned char *) malloc(16);
        bzero(shortmsg, 16);
        ret = sendChar(socketfd, shortmsg);
        if (!ret) {
            cerr << "sendChar failed\n";
            exit(1);
        }
        
    }

};

int main() {

    Client user1;

    cout << "Starting client...\n";
    user1.connectClient();
    cout << "Client successfuly connected to the server\n";

    // TEST
    user1.test();

    user1.authenticateServer();
    cout << "Server authenticated, waiting for server's envelope...\n";
    user1.retreiveSessionKey();
    cout << "Session key received\n";
    user1.proveIdentity();
    cout << "Proof of identity sent\n";

    return 0;
}