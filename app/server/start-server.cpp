#include <iostream>
#include <string>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <algorithm>
#include <string>
#include <cctype>
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
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>
// #include <filesystem>
#include <experimental/filesystem>
#include <cerrno>
#include "../utils.h"
#include "../const.h"

using namespace std;
using namespace std::experimental;
namespace fs = std::experimental::filesystem;

class Server
{

    // Sockets
    int socketfd, clientfd;
    struct sockaddr_in serverAddr, clientAddr;

    // Connexion status
    int CONNEXION_STATUS = 0;

    // Client infos
    string clientUsername;
    unsigned char *serverNonce;
    unsigned char * NewClientNonce;

    // Keys
    EVP_PKEY * servTempPubKey;
    unsigned char * charTempPubKey;
    EVP_PKEY * servTempPrvKey;
    unsigned char *sessionKey;
    unsigned char * authKey;
    unsigned char * sessionHash;
    unsigned char * envelope;
    int envelopeSize;
    int pemSize;
    BIO * keyBio;
    int keyBioLen;

    // Signatures
    unsigned char * serverSig;
    unsigned int serverSigSize;
    unsigned char * clientSig;
    unsigned int clientSigSize;

    // Session
    unsigned int counter;

public:
    // Get username
    string getClientUsername()
    {
        return clientUsername;
    }

    int getConnexionStatus()
    {
        return CONNEXION_STATUS;
    }

    // Creates a socket and makes it listen
    void startSocket()
    {

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
        if (ret < 0)
        {
            cerr << "Error binding socket\n";
            close(socketfd);
            exit(1);
        }

        // Start listening for requests
        ret = listen(socketfd, 10);
        if (ret < 0)
        {
            cerr << "Error listening\n";
            exit(1);
        }
        cout << "Listening to port : " << PORT << "\n";

    }

    // Handles client connexion request
    int acceptClient()
    {

        int ret;

        // Extract the first connexion in the queue
        int len = sizeof(clientAddr);
        clientfd = accept(socketfd, (sockaddr *)&clientAddr, (socklen_t *)&len);
        if (clientfd < 0)
        {
            cerr << "Error cannot accept client";
            return 0;
        }

        // Receive username et convert it back to string
        int *usernameLen = (int *)malloc(sizeof(int));
        if (!usernameLen)
        {
            cerr << "Error allocating buffer for username length\n";
            close(clientfd);
            return 0;
        }
        ret = readInt(clientfd, usernameLen);
        if (!ret)
        {
            cerr << "Error reading username length\n";
            close(clientfd);
            return 0;
        }
        unsigned char *buffer = (unsigned char *)malloc(*usernameLen + 1);
        if (!buffer)
        {
            cerr << "Error allocating buffer for username\n";
            close(clientfd);
            return 0;
        }
        ret = read(clientfd, buffer, *usernameLen);
        if (!ret)
        {
            cerr << "Error reading client username\n";
            close(clientfd);
            return 0;
        }

        // Convert to string
        string strBuffer(buffer, buffer + *usernameLen / sizeof buffer[0]);
        clientUsername = strBuffer;
        free(usernameLen);
        free(buffer);

        // Initialize counter
        counter = 0;

        return 1;
    }

    int generateSessionKeyPair()
    {

        int ret;

        // Create the exponent
        BIGNUM * bn =  BN_new();
        ret = BN_set_word(bn, RSA_F4);
        if (!ret) {
            cerr << "Error creating exponent\n";
            close(clientfd);
            return 0;
        }

        // Create the RSA structure
        RSA * rsa = RSA_new();
        int rsaSize = 2048; // Size in bits
        ret =  RSA_generate_key_ex(rsa, rsaSize, bn, NULL);
        if (!ret) {
            cerr << "Error generating rsa\n";
            close(clientfd);
            return 0;
        }

        // Create bios to store public and private keys
        BIO * publicBio = BIO_new(BIO_s_mem());
        PEM_write_bio_RSAPublicKey(publicBio, rsa);
        BIO * privateBio = BIO_new(BIO_s_mem());
        PEM_write_bio_RSAPrivateKey(privateBio, rsa, NULL, NULL, 0, NULL, NULL);

        // Get the size from the bios and allocate buffers
        int pubSize = BIO_pending(publicBio);
        int privSize = BIO_pending(privateBio);
        unsigned char * charServTempPubKey = (unsigned char *) malloc(pubSize + 1);
        unsigned char * charServTempPrvKey = (unsigned char *) malloc(privSize + 1);

        // Read bios into the buffers
        BIO_read(publicBio, charServTempPubKey, pubSize);
        BIO_read(privateBio, charServTempPrvKey, privSize);
        // charServTempPubKey[pubSize] = '\0';
        // charServTempPrvKey[privSize] = '\0';

        // Create bios to convert unsigned char * keys to EVP_PKEYs
        BIO * pubKeyBio = BIO_new_mem_buf(charServTempPubKey, pubSize);
        BIO * prvKeyBio = BIO_new_mem_buf(charServTempPrvKey, privSize);

        // Create rsa structure for pub and prv keys
        RSA * pubRsa = NULL;
        RSA * prvRsa = NULL;
        pubRsa = PEM_read_bio_RSAPublicKey(pubKeyBio, &pubRsa, NULL, NULL);
        prvRsa = PEM_read_bio_RSAPrivateKey(prvKeyBio, &prvRsa, NULL, NULL);

        // Associate EVP_PKEYs
        servTempPubKey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(servTempPubKey, pubRsa);
        servTempPrvKey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(servTempPrvKey, prvRsa);

        // Put the public key inside a bio
        keyBio = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(keyBio, servTempPubKey);

        // Free everything
        bzero(charServTempPubKey, pubSize);
        free(charServTempPubKey);
        bzero(charServTempPrvKey, privSize);
        free(charServTempPrvKey);
        BIO_free_all(publicBio);
        BIO_free_all(privateBio);
        BIO_free(pubKeyBio);
        BIO_free(prvKeyBio);
        BN_free(bn);
        RSA_free(rsa);

        return 1;
    }

    // This function concatenate client's serverNonce with temporary pub key signs it and send it
    int createIdProof() {

        int ret;

        // Read the client nonce
        unsigned char * clientNonce = (unsigned char *) malloc(nonceSize);
        if (!clientNonce) {
            cerr << "Error allocating buffer for client serverNonce\n";
            close(clientfd);
            return 0;
        }
        ret = read(clientfd, clientNonce, nonceSize);
        if (ret <= 0) {
            cerr << "Error reading client's serverNonce\n";
            close(clientfd);
            return 0;
        }

        // Read bio to get public key as a char
        keyBioLen = BIO_pending(keyBio);
        charTempPubKey = (unsigned char *) malloc(keyBioLen);
        if (!charTempPubKey) {
            cerr << "Error allocating buffer for char pub key\n";
            close(clientfd);
            return 0;
        }
        ret = BIO_read(keyBio, charTempPubKey, keyBioLen);
        if (ret <= 0) {
            cerr << "Error reading content from bio\n";
            close(clientfd);
            return 0;
        }

        // Concatenate clientNonce and public key
        unsigned char * concat = (unsigned char *) malloc(nonceSize + keyBioLen);
        if (!concat) {
            cerr << "Error allocating buffer for concat\n";
            close(clientfd);
            return 0;
        }
        memcpy(concat, clientNonce, nonceSize);
        memcpy(concat + nonceSize, charTempPubKey, keyBioLen);
        free(clientNonce);

        // Retreive server's private key
        string path = "server_infos/prvkey.pem";
        FILE *keyFile = fopen(path.c_str(), "r");
        if (!keyFile)
        {
            cerr << "Error could not open server private key file\n";
            close(clientfd);
            return 0;
        }
        const char *password = "password";
        EVP_PKEY * serverPrvKey = PEM_read_PrivateKey(keyFile, NULL, NULL, (void *) password);
        fclose(keyFile);
        if (!serverPrvKey)
        {
            cerr << "Error cannot read server private key from pem file\n";
            close(clientfd);
            return 0;
        }

        // Allocate buffer for signature
        serverSig = (unsigned char *) malloc(EVP_PKEY_size(serverPrvKey));
        if (!serverSig) {
            cerr << "Error allocating buffer for signature\n";
            close(clientfd);
            return 0;
        }

        // Sign the concatenated message
        const EVP_MD * md = EVP_sha256();
        EVP_MD_CTX * ctx = EVP_MD_CTX_new();
        if (!ctx) {
            cerr << "Error creating context for signature\n";
            close(clientfd);
            return 0;
        }
        ret = EVP_SignInit(ctx, md);
        if (!ret) {
            cerr << "Error during initialization for signature\n";
            close(clientfd);
            return 0;
        }
        ret = EVP_SignUpdate(ctx, concat, nonceSize + keyBioLen);
        if (!ret) {
            cerr << "Error during update for signature\n";
            close(clientfd);
            return 0;
        }
        ret = EVP_SignFinal(ctx, serverSig, &serverSigSize, serverPrvKey);
        if (!ret) {
            cerr << "Error during finalization for signature\n";
            close(clientfd);
            return 0;
        }

        // Create server's nonce
        serverNonce = (unsigned char *) malloc(nonceSize);
        if (!serverNonce) {
            cerr << "Error allocating buffer for server nonce\n";
            close(clientfd);
            return 0;
        }
        ret = createNonce(serverNonce);
        if (!ret) {
            cerr << "Error creating server's nonce\n";
            close(clientfd);
            return 0;
        }

        // Free everything
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(serverPrvKey);
        free(concat);
        BIO_free(keyBio);

        return 1;
    }

    int sendMessage2() {

        int ret;
        int totalSize = serverSigSize + nonceSize;

        // Concatenate server's signature and server nonce
        unsigned char * concat = (unsigned char *) malloc(totalSize);
        if (!concat) {
            cerr << "Error allocating buffer for message 2\n";
            close(clientfd);
            return 0;
        }
        memcpy(concat, serverSig, serverSigSize);
        memcpy(concat + serverSigSize, serverNonce, nonceSize);
        free(serverSig);

        // Send content of the bio for emphemeral pub key
        ret = sendInt(clientfd, keyBioLen);
        if (!ret) {
            cerr << "Error sending bio len\n";
            close(clientfd);
            return 0;
        }
        ret = send(clientfd, charTempPubKey, keyBioLen, 0);
        if (ret <= 0) {
            cerr << "Error sending bio content\n";
            close(clientfd);
            return 0;
        }

        // Open certificate
        string serverCertPath = "../certificates/servcert.pem";
        X509 *serverCert = readCertificate(serverCertPath); // Function from utils.h
        if (!ret)
        {
            cerr << "Error reading server certificate\n";
            close(clientfd);
            return 0;
        }

        // Put certificate into a bio
        BIO * certBio = BIO_new(BIO_s_mem());
        PEM_write_bio_X509(certBio, serverCert);
        X509_free(serverCert);

        // Read certificate as a character
        int certBioLen = BIO_pending(certBio);
        unsigned char * charCert = (unsigned char *) malloc(certBioLen);
        if (!charCert) {
            cerr << "Error allocating buffer for character certificate\n";
            close(clientfd);
            return 0;
        }
        ret = BIO_read(certBio, charCert, certBioLen);
        if (ret <= 0) {
            cerr << "Error reeading certificate bio\n";
        }
        BIO_free(certBio);

        // Send certificate
        ret = sendInt(clientfd, certBioLen);
        if (!ret) {
            cerr << "Error sending cert length\n";
            close(clientfd);
            return 0;
        }
        ret = send(clientfd, charCert, certBioLen, 0);
        if (!ret) {
            cerr << "Error sending cert\n";
            close(clientfd);
            return 0;
        }
        free(charCert);

        // Send the message
        ret = sendInt(clientfd, totalSize);
        if (!ret) {
            cerr << "Error sending message 2 size\n";
            close(clientfd);
            return 0;
        }
        ret = send(clientfd, concat, totalSize, 0);
        if (ret <= 0) {
            cerr << "Error sending message 2\n";
            close(clientfd);
            return 0;
        }

        // Free things
        free(concat);

        return 1;
    }

    int receiveMessage3() {

        int ret;

        // Read message size
        int * totalSizePtr = (int *) malloc(sizeof(int));
        ret = readInt(clientfd, totalSizePtr);
        if (!ret) {
            cerr << "Error reading message 3 total size\n";
            close(clientfd);
            return 0;
        }
        int totalSize = *totalSizePtr;
        free(totalSizePtr);

        // Read client sig size
        int * sizePtr = (int *) malloc(sizeof(int));
        ret = readInt(clientfd, sizePtr);
        if (!ret) {
            cerr << "Error reading client sig size\n";
            close(clientfd);
            return 0;
        }
        clientSigSize = *sizePtr;
        free(sizePtr);

        // Read concatenate message 3
        unsigned char * concat = (unsigned char *) malloc(totalSize);
        if (!concat) {
            cerr << "Error allocating buffer for concatenate message 3\n";
            close(clientfd);
            return 0;
        }
        ret = read(clientfd, concat, totalSize);

        // Separate the parts
        envelopeSize = totalSize - clientSigSize - nonceSize;
        NewClientNonce = (unsigned char *) malloc(nonceSize);
        envelope = (unsigned char *) malloc(envelopeSize);
        clientSig = (unsigned char *) malloc(clientSigSize);
        if (!envelope || !clientSig || !NewClientNonce) {
            cerr << "Error allocating buffer for message 3\n";
            close(clientfd);
            return 0;
        }
        memcpy(NewClientNonce, concat, nonceSize);
        memcpy(envelope, concat + nonceSize, envelopeSize);
        memcpy(clientSig, concat + envelopeSize + nonceSize, clientSigSize);
        free(concat);

        return 1;
    }

    // Receive user's envelope and decrypt it to retreive session key
    int retreiveSessionKey()
    {

        int ret;

        // Allocate buffers
        int encryptedSize = 80;
        int encryptedKeySize = envelopeSize - encryptedSize - ivSize;
        unsigned char * encryptedSecret = (unsigned char *) malloc(encryptedSize);
        unsigned char * encryptedKey = (unsigned char *) malloc(encryptedKeySize);
        unsigned char * iv = (unsigned char *) malloc(ivSize);
        if (!encryptedSecret || !encryptedKey || !iv) {
            cerr << "Error allocating buffer for envelope\n";
            close(clientfd);
            return 0;
        }

        // Decompose envelope
        memcpy(encryptedKey, envelope, encryptedKeySize);
        memcpy(encryptedSecret, envelope + encryptedKeySize, encryptedSize);
        memcpy(iv, envelope + encryptedKeySize + encryptedSize, ivSize);
        free(envelope);

        // Decrypt the envelope

        // Useful variables
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();
        int decryptedSize;

        // Create buffer for session hash
        sessionHash = (unsigned char *) malloc(encryptedSize);
        if (!sessionHash) {
            cerr << "Error allocating buffer for session key\n";
            close(clientfd);
            return 0;
        }

        // Digital envelope
        int bytesWritten;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            cerr << "Error creating context for envelope decryption\n";
            close(clientfd);
            return 0;
        }
        ret = EVP_OpenInit(ctx, cipher, encryptedKey, encryptedKeySize, iv, servTempPrvKey);
        if (ret <= 0)
        {
            cerr << "Error during initialization for envelope decryption\n";
            close(clientfd);
            return 0;
        }
        ret = EVP_OpenUpdate(ctx, sessionHash, &bytesWritten, encryptedSecret, encryptedSize);
        if (ret <= 0)
        {
            cerr << "Error during update for envelope decryption\n";
            close(clientfd);
            return 0;
        }
        decryptedSize = bytesWritten;
        ret = EVP_OpenFinal(ctx, sessionHash + decryptedSize, &bytesWritten);
        if (ret <= 0)
        {
            cerr << "Error during finalization for envelope decryption\n";
            close(clientfd);
            return 0;
        }
        decryptedSize += bytesWritten;

        // Separate session key and authetication key
        sessionKey = (unsigned char *) malloc(sessionKeySize);
        authKey = (unsigned char *) malloc(sessionKeySize);
        if(!sessionKey || !authKey) {
            cerr << "Error allocating buffers for session key and auth key\n";
            close(clientfd);
            return 0;
        }
        memcpy(sessionKey, sessionHash, sessionKeySize);
        memcpy(authKey, sessionHash + sessionKeySize, sessionKeySize);

        // Free some stuff
        EVP_CIPHER_CTX_free(ctx);
        free(encryptedKey);
        free(iv);
        free(encryptedSecret);
        free(servTempPrvKey);

        return 1;
    }

    int authenticateClient() {

        int ret;

        // Concatenates server's nonce and session key
        unsigned char * concat = (unsigned char *) malloc(nonceSize + 2*sessionKeySize);
        if (!concat) {
            cerr << "Error allocating buffer for concat\n";
            close(clientfd);
            return 0;
        }
        memcpy(concat, serverNonce, nonceSize);
        memcpy(concat + nonceSize, sessionHash, 2*sessionKeySize);
        free(serverNonce);

        // Retreive user's pubkey to verify signature
        string path = "users_infos/" + clientUsername + "/pubkey.pem";
        FILE *keyFile = fopen(path.c_str(), "r");
        if (!keyFile)
        {
            cerr << "Error could not open client " << clientUsername << " public key file\n";
            close(clientfd);
            return 0;
        }
        EVP_PKEY * clientPubKey = PEM_read_PUBKEY(keyFile, NULL, NULL, NULL);
        fclose(keyFile);
        if (!clientPubKey)
        {
            cerr << "Error could not read client " << clientUsername << " public key from pem file\n";
            close(clientfd);
            return 0;
        }

        // Verify signature
        const EVP_MD * md = EVP_sha256();
        EVP_MD_CTX * mdCtx = EVP_MD_CTX_new();
        if (!mdCtx) {
            cerr << "Error creating context for verifying sig\n";
            close(clientfd);
            return 0;
        }
        ret = EVP_VerifyInit(mdCtx, md);
        if (!ret) {
            cerr << "Error during init for verifying sig\n";
            close(clientfd);
            return 0;
        }
        ret = EVP_VerifyUpdate(mdCtx, concat, nonceSize + 2*sessionKeySize);
        if (ret <= 0) {
            cerr << "Error during update for verifying sig\n";
            close(clientfd);
            return 0;
        }
        ret = EVP_VerifyFinal(mdCtx, clientSig, clientSigSize, clientPubKey);
        if (!ret) {
            // Free things
            EVP_MD_CTX_free(mdCtx);
            EVP_PKEY_free(clientPubKey);
            free(concat);
            free(clientSig);
            free(sessionHash);

            // Close connexion and exit function
            cerr << "User could not be authenticated\n";
            close(clientfd);
            return 0;
        }
        if (ret < 0) {
            cerr << "Error during finalization for verifying sig\n";
            close(clientfd);
            return 0;
        }

        // Free stuff
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(clientPubKey);
        free(concat);
        free(clientSig);
        
        CONNEXION_STATUS = 1;

        return 1;
    }

    // Last message containing the nonce conatenated with the session key encrypted with session key
    int sendMessage4() {

        int ret;

        // Concatenate nonce with session key
        unsigned char * concat = (unsigned char *) malloc(nonceSize + 2*sessionKeySize);
        if (!concat) {
            cerr << "Error allocating buffer for message 4 concat\n";
            close(clientfd);
            return 0;
        }
        memcpy(concat, NewClientNonce, nonceSize);
        memcpy(concat + nonceSize, sessionHash, 2*sessionKeySize);
        free(sessionHash);
        free(NewClientNonce);

        // Encrypt the concat
        unsigned char * encryptedConcat = (unsigned char *) malloc(nonceSize + 2*sessionKeySize + blockSize);
        unsigned char * iv = (unsigned char *) malloc(ivSize);
        if (!iv || !encryptedConcat) {
            cerr << "Error allocating buffers for encrypting message 4 concat\n";
            close(clientfd);
            return 0;
        }
        ret = encryptSym(concat, nonceSize + 2*sessionKeySize, encryptedConcat, iv, sessionKey);
        if (!ret) {
            cerr << "Error encrypting concat for message 4\n";
            close(clientfd);
            return 0;
        }
        int encryptedSize = ret;

        // Send the concat
        ret = sendInt(clientfd, encryptedSize);
        if (!ret) {
            cerr << "Error sending encrypted size for message 4\n";
            close(clientfd);
            return 0;
        }
        ret = send(clientfd, iv, ivSize, 0);
        if (!ret) {
            cerr << "Error sending the iv for message 4\n";
            close(clientfd);
            return 0;
        }
        ret = send(clientfd, encryptedConcat, encryptedSize, 0);
        if (!ret) {
            cerr << "Error sending encrypted concat for message 4\n";
            close(clientfd);
            return 0;
        }

        // Free things
        free(encryptedConcat);
        free(iv);
        free(concat);

        return 1;
    }

    // Function used to renegociate keys in case the counter wraps around
    int renegociateServer() {

        int ret;

        // Free some things
        bzero(sessionKey, sessionKeySize);
        free(sessionKey);
        bzero(authKey, sessionKeySize);
        free(authKey);

        // Now redo the process of generating the keys
        ret = generateSessionKeyPair();
        if (!ret)
        {
            cerr << "Error generating temporary RSA key pair, communication stopped\n\n";
            CONNEXION_STATUS = 0;
            close(clientfd);
            return 0;
        }
        cout << "Temporary RSA key pair generated\n";

        cout << "Creating ID proof\n";
        ret = createIdProof();
        if (!ret) {
            cerr << "Error creating ID proof, communication stopped\n\n";
            CONNEXION_STATUS = 0;
            close(clientfd);
            return 0;
        }
        cout << "Proof of ID created\n";

        ret = sendMessage2();
        if (!ret) {
            cerr << "Error sending ID proof\n\n";
            CONNEXION_STATUS = 0;
            close(clientfd);
            return 0;
        }
        cout << "ID proof sent\n";
        
        ret = receiveMessage3();
        if (!ret) {
            cerr << "Error receiving message 3\n\n";
            CONNEXION_STATUS = 0;
            close(clientfd);
            return 0;
        }
        cout << "Message 3 received\n";

        ret = retreiveSessionKey();
        if (!ret) {
            cerr << "Error retreiving session key from client's envelope\n\n";
            CONNEXION_STATUS = 0;
            close(clientfd);
            return 0;
        }
        cout << "Session key retreived\n";

        ret = authenticateClient();
        if (!ret) {
            cerr << "Client could not be authenticated, communication stopped\n\n";
            CONNEXION_STATUS = 0;
            close(clientfd);
            return 0;
        }
        cout << "Client authenticated, session started\n";

        ret = sendMessage4();
        if (!ret) {
            cerr << "Error sending message 4\n";
            CONNEXION_STATUS = 0;
            close(clientfd);
            return 0;
        }
        cout << "Message 4 sent successfully\n";

        counter = 0;

        return 1;

    }

    int uploadFile() {
        
        int ret;

        cout << "Client "<< clientUsername << " requested an upload\n";

        // Receive client's integer concerning file to upload
        int * noProblemPtr = (int *) malloc(sizeof(int));
        ret = readInt(clientfd, noProblemPtr);
        if (!ret) {
            cout << "Error reading integer for file upload\n";
            return 0;
        }
        int noProblem = *noProblemPtr;
        free(noProblemPtr);
        if (!noProblem) {
            cout << "Something was not valid in the file on client side\n";
            return 0; 
        }

        // Before receiving anything check if counter wraps around
        ret = checkCounter(counter);
        if (ret) {
            cout << "Counter wrapped around\n";
            ret = renegociateServer();
            if (!ret) {
                return 0;
            }
        }

        // Receive encrypted filepath size
        int * filepathEncLen = (int *) malloc(sizeof(int));
        if (!filepathEncLen) {
            cout << "Error allocating buffers to receive encrypted filename\n";
            return 0;
        }
        ret = readInt(clientfd, filepathEncLen);
        if (!ret) {
            cerr << "Error upload filepath length\n";
            return 0;
        }

        // Read File Path
        int totalSize = sessionKeySize + *filepathEncLen;
        unsigned char * concat = (unsigned char *) malloc(totalSize);
        unsigned char * iv = (unsigned char *) malloc(ivSize);
        unsigned char * filepathEnc = (unsigned char *) malloc(*filepathEncLen);
        unsigned char * digest = (unsigned char *) malloc(sessionKeySize);
        if (!concat || !iv || !filepathEnc || !digest) {
            cerr << "Error allocating buffers for receiving encrypted filepath\n";
            return 0;
        }
        ret = receiveEncrypted(*filepathEncLen, iv, concat, filepathEnc, digest, clientfd);
        if (!ret) {
            cout << "Error receiving encrypted filepath\n";
            return 0;
        }

        // Check authenticity of the message
        counter ++;
        ret = checkAuthenticity(*filepathEncLen, filepathEnc, digest, authKey, counter);
        if (!ret) {
            // Free things
            free(concat);
            free(iv);
            free(filepathEnc);
            free(digest);

            // Exit function
            cout << "Error encrypted filepath message not authenticated\n";
            return 0;
        }

        // Decrypt filename
        unsigned char * decryptedFilepath = (unsigned char *) malloc(*filepathEncLen);
        ret = decryptSym(filepathEnc, *filepathEncLen, decryptedFilepath, iv, sessionKey);
        if (!ret) {
            cerr << "Error decrypting the upload filepath\n";
            return 0;
        }
        string filepath(decryptedFilepath, decryptedFilepath + ret);
        string spath = "users_infos/" + clientUsername + "/files/" + filepath;
        filesystem::path path(spath);

        // Free things
        free(iv);
        free(concat);
        free(digest);
        free(filepathEncLen);
        free(filepathEnc);
        free(decryptedFilepath);

        // Read size of file
        int * upload_size = (int *) malloc(sizeof(int));
        ret = readInt(clientfd, upload_size);
        if (!ret) {
            cerr << "Error upload filepath length\n";
            return 0;
        }
        int remainedBlock = *upload_size;
        free(upload_size);

        // Read file content
        unsigned char * fileContent = (unsigned char *) malloc(remainedBlock);
        if (!fileContent) {
            cout << "Error allocating buffer for file content for upload\n";
            return 0;
        }
        int prevWrite = 0;
        while(remainedBlock>0){

            // Before receiving anything check if counter wraps around
            ret = checkCounter(counter);
            if (ret) {
                cout << "Counter wrapped around\n";
                ret = renegociateServer();
                if (!ret) {
                    return 0;
                }
            }

            // Receive upload block size
            int * uploadBlockLen = (int *) malloc(sizeof(int));
            if (!uploadBlockLen) {
                cout << "Error allocating buffer for upload block len pointer\n";
                return 0;
            }
            ret = readInt(clientfd, uploadBlockLen); // encrypted size
            if (!ret) {
                cerr << "Error upload block length\n";
                return 0;
            }

            // Receive encrypted upload block
            int totalSizeBlock = *uploadBlockLen + sessionKeySize;
            unsigned char * concatBlock = (unsigned char *) malloc(totalSizeBlock);
            unsigned char * ivBlock = (unsigned char *) malloc(ivSize);
            unsigned char * digestBlock = (unsigned char *) malloc(sessionKeySize);
            unsigned char * cyberBuffer = (unsigned char *) malloc(*uploadBlockLen);
            if (!concatBlock || !ivBlock || !digestBlock || !cyberBuffer) {
                cerr << "Error allocating buffer for receiving encrypted upload block\n";
                return 0;
            }
            ret = receiveEncrypted(*uploadBlockLen, ivBlock, concatBlock, cyberBuffer, digestBlock, clientfd);
            if (!ret) {
                cout << "Error receiving encrypted upload block\n";
                return 0;
            }

            // Check authenticity
            counter ++;
            ret = checkAuthenticity(*uploadBlockLen, cyberBuffer, digestBlock, authKey, counter);
            if (!ret) {
                // Free things
                free(concatBlock);
                free(ivBlock);
                free(digestBlock);
                free(cyberBuffer);
                free(uploadBlockLen);

                // Exit function
                cout << "Error encrypted upload block message could not be authenticated\n";
                return 0;
            }

            // Decrypt data
            unsigned char * plainBuffer = (unsigned char *) malloc(*uploadBlockLen);
            ret = decryptSym(cyberBuffer, *uploadBlockLen, plainBuffer, ivBlock, sessionKey);
            if (!ret) {
                cerr << "Error decrypting the upload block\n";
                return 0;
            }
            int plaintextLen = ret;

            // Add data to the file content
            memcpy(fileContent + prevWrite, plainBuffer, plaintextLen);
            remainedBlock -= plaintextLen;
            prevWrite += plaintextLen;

            // Free things
            free(uploadBlockLen);
            free(ivBlock);
            free(cyberBuffer);
            free(digestBlock);
            free(concatBlock);
            free(plainBuffer);
        }

        // Write file content into a new file
        ofstream wf(path, ios::out | ios::binary);
        if(!wf) {
            cout << "Cannot open file to write upload file!" << endl;
            return 0;
        }
        for (int i = 0; i < prevWrite; i++) {
            wf.write((char *) &fileContent[i], sizeof(char));
        }
        wf.close();

        if(!wf.good()) {
            cout << "Error occurred at writing time while saving uploaded file!" << endl;
            return 0;
        }

        // Free things
        free(fileContent);

        cout << "--- FILE UPLOADED ---\n";
        
        return 1;
    }

    int downloadFile() {

        cout << "Client "<< clientUsername << " requested a download\n";

        int ret;

        // Receive client's integer
        int * noProblemPtr = (int *) malloc(sizeof(int));
        ret = readInt(clientfd, noProblemPtr);
        if (!ret) {
            cout << "Error reading integer for download file\n";
            return 0;
        }
        int noProblem = *noProblemPtr;
        free(noProblemPtr);
        if (!noProblem) {
            cout << "Error on filename from client's side\n";
            return 0;
        }

        // Before receiving anything check if counter wraps around
        ret = checkCounter(counter);
        if (ret) {
            cout << "Counter wrapped around\n";
            ret = renegociateServer();
            if (!ret) {
                return 0;
            }
        }
        
        // Read Filepath length
        int * filepathEncLen = (int *) malloc(sizeof(int));
        if (!filepathEncLen) {
            cerr << "Error allocating buffer for upload filepath length\n";
            return 0;
        }
        ret = readInt(clientfd, filepathEncLen);
        if (!ret) {
            cerr << "Error upload filepath length\n";
            return 0;
        }

        // Receive encrypted filepath
        unsigned char * filepathEnc = (unsigned char *) malloc(*filepathEncLen);
        unsigned char * iv = (unsigned char *) malloc(ivSize);
        unsigned char * concat = (unsigned char *) malloc(*filepathEncLen + sessionKeySize);
        unsigned char * digest = (unsigned char *) malloc(sessionKeySize);
        if (!filepathEnc || !iv || !concat || !digest) {
            cerr << "Error allocating buffer for download filepath\n";
            return 0;
        }
        ret = receiveEncrypted(*filepathEncLen, iv, concat, filepathEnc, digest, clientfd);
        if (!ret) {
            cout << "Error receiving encrypted filepath\n";
            return 0;
        }

        // Check authenticity
        counter ++;
        ret = checkAuthenticity(*filepathEncLen, filepathEnc, digest, authKey, counter);
        if (!ret) {
            // Free things
            free(filepathEnc);
            free(iv);
            free(concat);
            free(digest);
            free(filepathEncLen);

            // Exit function
            cout << "Error encrypted filepath message not authenticated\n";
            return 0;
        }

        // Decrypt filename
        unsigned char * decryptedFilepath = (unsigned char *) malloc(*filepathEncLen);
        ret = decryptSym(filepathEnc, *filepathEncLen, decryptedFilepath, iv, sessionKey);
        if (!ret) {
            cerr << "Error decrypting the download filepath\n";
            return 0;
        }
        string filepath(decryptedFilepath, decryptedFilepath + ret);

        // Check existence of the file and send the response to the client
        ret = existsFile(filepath, clientUsername);
        int exists = ret;
        ret = sendInt(clientfd, exists);
        if (!ret) {
            cout << "Error sending response to the client\n";
            return 0;
        }
        if (!exists) {
            // Free things
            free(filepathEncLen);
            free(iv);
            free(concat);
            free(digest);
            free(filepathEnc);
            free(decryptedFilepath);

            // Exit function
            cout << "File does not exists\n";
            return 0;
        }

        // Get complete path to the file
        string sfullPath = "./users_infos/" + clientUsername + "/files/" + filepath;
        fs::path fullPath(sfullPath);

        // Free things
        free(filepathEncLen);
        free(iv);
        free(concat);
        free(digest);
        free(filepathEnc);
        free(decryptedFilepath);

        // open file
        std::ifstream infile(sfullPath);
 
        // Send file size to client 
        infile.seekg(0, std::ios::end);
        int upload_size = infile.tellg();
        ret = sendInt(clientfd, upload_size);
        if (!ret) {
            cerr << "Error sending download filesize to client\n";
            return 0;
        }

        //send file block by block
        infile.seekg(0, std::ios::beg);
        char plainBuffer[UPLOAD_BUFFER_SIZE];
        int remainbytes = upload_size;
        while((!infile.eof() && (remainbytes > 0))){

            int readlength = sizeof (plainBuffer);
            readlength = std::min(readlength,remainbytes);
            remainbytes -= readlength;
            infile.read(plainBuffer, readlength);

            // Before encrypting anything check if counter wraps around
            ret = checkCounter(counter);
            if (ret) {
                cout << "Counter wrapped around\n";
                ret = renegociateServer();
                if (!ret) {
                    return 0;
                }
            }
            
            // Encrypt the block
            unsigned char * cyperBuffer = (unsigned char *) malloc(readlength + blockSize);
            unsigned char * ivBlock = (unsigned char *) malloc(ivSize);
            if (!cyperBuffer || !ivBlock) {
                cerr << "Error allocating buffer for encrypting file block\n";
                return 0;
            }
            int ret = encryptSym((unsigned char *)plainBuffer, readlength, cyperBuffer, ivBlock, sessionKey);
            if (!ret) {
                cerr << "Error encrypting the upload block\n";
                return 0;
            }
            int encryptedSize = ret;

            // Hash and concatenate
            int totalSize = encryptedSize + sessionKeySize;
            unsigned char * concatBlock = (unsigned char *) malloc(totalSize);
            if (!concatBlock) {
                cerr << "Error allocating buffer for concat block\n";
                return 0;
            }
            counter ++;
            ret = hashAndConcat(concatBlock, cyperBuffer, encryptedSize, authKey, counter);
            if (!ret) {
                cout << "Error hashing and concatenating\n";
                return 0;
            }

            // Send encrypted block
            ret = sendEncrypted(encryptedSize, ivBlock, concatBlock, clientfd);
            if (!ret) {
                cout << "Error sending encrypted block\n";
                return 0;
            }

            // Free things
            free(ivBlock);
            free(concatBlock);
            free(cyperBuffer);
        }
        infile.close();
        
        cout << "--- FILE DOWNLOADED ---\n";
        
        return 1;
    }

    int deleteFile()
    {

        cout << "Client "<< clientUsername << " requested a delete\n";

        int ret;

        // Receive client's integer
        int * noProblemPtr = (int *) malloc(sizeof(int));
        ret = readInt(clientfd, noProblemPtr);
        if (!ret) {
            cout << "Error reading integer for delete file\n";
            return 0;
        }
        int noProblem = *noProblemPtr;
        free(noProblemPtr);
        if (!noProblem) {
            cout << "Error on filename from client's side\n";
            return 0;
        }

        // Before receiving anything check if counter wraps around
        ret = checkCounter(counter);
        if (ret) {
            cout << "Counter wrapped around\n";
            ret = renegociateServer();
            if (!ret) {
                return 0;
            }
        }

        // Receive encrypted filename size
        int *encryptedSizePtr = (int *)malloc(sizeof(int));
        if (!encryptedSizePtr)
        {
            cout << "Error allocating buffer for encrypted filename size\n";
            return 0;
        }
        ret = readInt(clientfd, encryptedSizePtr);
        if (!ret)
        {
            cout << "Error reading encrypted filename size\n";
            return 0;
        }
        int encryptedSize = *encryptedSizePtr;
        free(encryptedSizePtr);

        // Receive encrypted filename
        unsigned char *iv = (unsigned char *)malloc(ivSize);
        unsigned char * concat = (unsigned char *) malloc(encryptedSize + sessionKeySize);
        unsigned char *encryptedFilename = (unsigned char *)malloc(encryptedSize);
        unsigned char * digest = (unsigned char *) malloc(sessionKeySize);
        if (!iv || !concat || !encryptedFilename || !digest) {
            cout << "Error reading encrypted filename\n";
            return 0;
        }
        ret = receiveEncrypted(encryptedSize, iv, concat, encryptedFilename, digest, clientfd);
        if (!ret) {
            cout << "Error receiving encrypted filename\n";
            return 0;
        }

        // Check authenticity of the message
        counter ++;
        ret = checkAuthenticity(encryptedSize, encryptedFilename, digest, authKey, counter);
        if (!ret) {
            // Free things
            free(iv);
            free(concat);
            free(encryptedFilename);
            free(digest);

            // Exit function
            cerr << "Filename message not authenticated\n";
            return 0;
        }

        // Decrypt filename
        unsigned char *buggedFilename = (unsigned char *)malloc(encryptedSize);
        int decryptedSize;
        decryptedSize = decryptSym(encryptedFilename, encryptedSize, buggedFilename, iv, sessionKey);
        if (!decryptedSize)
        {
            cout << "Error decrypting new filename\n";
            return 0;
        }
        unsigned char *filename = (unsigned char *)malloc(decryptedSize);
        memcpy(filename, buggedFilename, decryptedSize);
        free(buggedFilename);

        // Check if file exists and send the result to the client
        int exists;
        string sfilename(filename, filename + decryptedSize);
        exists = existsFile(sfilename, clientUsername);
        ret = sendInt(clientfd, exists);
        if (!ret)
        {
            cout << "Error sending result of test to client\n";
            return 0;
        }
        if (!exists)
        {
            // Free things
            free(iv);
            free(concat);
            free(encryptedFilename);
            free(digest);
            free(filename);

            // Exit function
            cout << "Error file doesn't exists\n";
            return 0; // If the file does not exists we get out of the function without doing anything
        }

        // Delete file
        error_code ec;
        string spath = "./users_infos/" + clientUsername + "/files/" + sfilename;
        filesystem::path path(spath);
        remove(path, ec);

        // Free Buffers
        free(iv);
        free(concat);
        free(digest);
        free(filename);
        free(encryptedFilename);

        cout << "--- FILE DELETED ---\n";

        return 1;
    }

    int listFiles() {

        int ret;

        string filesPath = "users_infos/" + clientUsername + "/files/";
        int filesNumber = 0;

        // First retrieve the number of files
        for (const auto &file : directory_iterator(filesPath)) {
            filesNumber += 1;
        }

        // Send the number of files to the client
        ret = sendInt(clientfd, filesNumber);
        if (!ret) {
            cout << "Error sending number of files to the client\n";
            return 0;
        }

        // Iterate through files and send them
        for (const auto &file : directory_iterator(filesPath)) {

            // Before encrypting anything check if counter wraps around
            ret = checkCounter(counter);
            if (ret) {
                cout << "Counter wrapped around\n";
                ret = renegociateServer();
                if (!ret) {
                    return 0;
                }
            }

            // Encrypt the filename
            int encryptedSize;
            string filename = file.path().filename().string();
            unsigned char *encryptedFilename = (unsigned char *)malloc(filename.size() + blockSize);
            unsigned char *iv = (unsigned char *)malloc(ivSize);
            if (!encryptedFilename || !iv) {
                cout << ">> Error allocating buffers for encryption\n";
                return 0;
            }
            unsigned char * charFilename = (unsigned char *) malloc(filename.size());
            copy(filename.begin(), filename.end(), charFilename);
            ret = encryptSym(charFilename, filename.size(), encryptedFilename, iv, sessionKey);
            if (!ret) {
                cout << "Error during encryption\n";
                return 0;
            }
            free(charFilename);
            encryptedSize = ret;

            // Hash and concatenate
            unsigned char * concat = (unsigned char *) malloc(encryptedSize + sessionKeySize);
            if (!concat) {
                cout << "Error allocating buffer for concat\n";
                return 0;
            }
            counter ++;
            ret = hashAndConcat(concat, encryptedFilename, encryptedSize, authKey, counter);
            if (!ret) {
                cout << "Error hashing and concatenating\n";
                return 0;
            }

            // Send the encrypted filename
            ret = sendEncrypted(encryptedSize, iv, concat, clientfd);
            if (!ret) {
                cout << "Error sending encrypted filename\n";
                return 0;
            }

            // Free things
            free(iv);
            free(concat);
            free(encryptedFilename);
        }

        cout << "--- FILES LISTED ---\n";

        return 1;
    }

    int renameFile()
    {

        cout << "Client "<< clientUsername << " requested a rename\n";

        int ret;

        // Receive client's integer
        int * noProblemPtr = (int *) malloc(sizeof(int));
        ret = readInt(clientfd, noProblemPtr);
        if (!ret) {
            cout << "Error reading integer for rename file\n";
            return 0;
        }
        int noProblem = *noProblemPtr;
        free(noProblemPtr);
        if (!noProblem) {
            cout << "Error on filename from client's side\n";
            return 0;
        }

        // Before receiving anything check if counter wraps around
        ret = checkCounter(counter);
        if (ret) {
            cout << "Counter wrapped around\n";
            ret = renegociateServer();
            if (!ret) {
                return 0;
            }
        }

        // Receive encrypted filename size
        int *encryptedSizePtr = (int *)malloc(sizeof(int));
        if (!encryptedSizePtr)
        {
            cout << "Error allocating buffer for encrypted filename size\n";
            return 0;
        }
        ret = readInt(clientfd, encryptedSizePtr);
        if (!ret)
        {
            cout << "Error reading encrypted filename size\n";
            return 0;
        }
        int encryptedSize = *encryptedSizePtr;
        free(encryptedSizePtr);

        // Receive encrypted filename
        unsigned char *iv = (unsigned char *)malloc(ivSize);
        unsigned char * concat = (unsigned char *) malloc(encryptedSize + sessionKeySize);
        unsigned char *encryptedFilename = (unsigned char *)malloc(encryptedSize);
        unsigned char * digest = (unsigned char *) malloc(sessionKeySize);
        if (!iv || !concat || !encryptedFilename || !digest) {
            cerr << "Error allocating buffers for receiving encrypted filename\n";
        }
        ret = receiveEncrypted(encryptedSize, iv, concat, encryptedFilename, digest, clientfd);
        if (!ret) {
            cerr << "Error receiving encrypted filename\n";
            return 0;
        }

        // Check authenticity of the message
        counter ++;
        ret = checkAuthenticity(encryptedSize, encryptedFilename, digest, authKey, counter);
        if (!ret) {
            // Free things
            free(iv);
            free(concat);
            free(encryptedFilename);
            free(digest);

            // Exit function
            cerr << "Filename message not authenticated\n";
            return 0;
        }

        // Decrypt filename
        unsigned char *buggedFilename = (unsigned char *)malloc(encryptedSize);
        int decryptedSize;
        decryptedSize = decryptSym(encryptedFilename, encryptedSize, buggedFilename, iv, sessionKey);
        if (!decryptedSize)
        {
            cout << "Error decrypting new filename\n";
            return 0;
        }
        unsigned char *filename = (unsigned char *)malloc(decryptedSize);
        memcpy(filename, buggedFilename, decryptedSize);
        free(buggedFilename);

        // Check if file exists and send the result to the client
        int exists;
        string sfilename(filename, filename + decryptedSize);
        exists = existsFile(sfilename, clientUsername);
        ret = sendInt(clientfd, exists);
        if (!ret)
        {
            cout << "Error sending result of test to client\n";
            return 0;
        }
        if (!exists)
        {
            // Free things for next use of rename
            free(iv);
            free(concat);
            free(encryptedFilename);
            free(digest);
            free(filename);

            // Exit function
            cout << "File does not exists\n";
            return 0; // If the file does not exists we get out of the function without doing anything
        }

        // Receive client's integer
        int * noProblemPtrNew = (int *) malloc(sizeof(int));
        ret = readInt(clientfd, noProblemPtrNew);
        if (!ret) {
            cout << "Error reading integer for rename file\n";
            return 0;
        }
        int noProblemNew = *noProblemPtrNew;
        free(noProblemPtrNew);
        if (!noProblemNew) {
            cout << "Error on new filename from client's side\n";
            return 0;
        }

        // Before receiving anything check if counter wraps around
        ret = checkCounter(counter);
        if (ret) {
            cout << "Counter wrapped around\n";
            ret = renegociateServer();
            if (!ret) {
                return 0;
            }
        }

        // Receive new encrypted filename size
        int *encryptedNewSizePtr = (int *)malloc(sizeof(int));
        if (!encryptedNewSizePtr)
        {
            cout << "Error allocating buffer for encrypted filename size\n";
            return 0;
        }
        ret = readInt(clientfd, encryptedNewSizePtr);
        if (!ret)
        {
            cout << "Error reading encrypted filename size\n";
            return 0;
        }
        int encryptedNewSize = *encryptedNewSizePtr;
        free(encryptedNewSizePtr);

        // Receive new filename
        unsigned char *ivNew = (unsigned char *)malloc(ivSize);
        unsigned char * concatNew = (unsigned char *) malloc(encryptedNewSize + sessionKeySize);
        unsigned char *encryptedNewFilename = (unsigned char *)malloc(encryptedNewSize);
        unsigned char * digestNew = (unsigned char *) malloc(sessionKeySize);
        if (!ivNew || !concatNew || !encryptedNewFilename || !digestNew) {
            cout << "Error allocating buffers for receiving new encrypted filename\n";
            return 0;
        }
        ret = receiveEncrypted(encryptedNewSize, ivNew, concatNew, encryptedNewFilename, digestNew, clientfd);
        if (!ret) {
            cout << "Error receiving new encrypted filename\n";
            return 0;
        }

        // Check authenticity
        counter ++;
        ret = checkAuthenticity(encryptedNewSize, encryptedNewFilename, digestNew, authKey, counter);
        if (!ret) {
            // Free things
            free(ivNew);
            free(concatNew);
            free(encryptedNewFilename);
            free(digestNew);
            free(iv);
            free(concat);
            free(encryptedFilename);
            free(digest);
            free(filename);

            // Exit function
            cout << "New filename message could not be authenticated\n";
            return 0;
        }

        // Decrypt new filename
        unsigned char *newFilename = (unsigned char *)malloc(encryptedNewSize);
        int decryptedNewSize;
        decryptedNewSize = decryptSym(encryptedNewFilename, encryptedNewSize, newFilename, ivNew, sessionKey);
        if (!decryptedNewSize)
        {
            cout << "Error decrypting new filename\n";
            return 0;
        }

        // Rename file
        string snewFilename(newFilename, newFilename + decryptedNewSize);
        string soldPath = "./users_infos/" + clientUsername + "/files/" + sfilename;
        string snewPath = "./users_infos/" + clientUsername + "/files/" + snewFilename;
        filesystem::path oldPath(soldPath);
        filesystem::path newPath(snewPath);
        rename(oldPath, newPath);

        // Free eveything
        free(iv);
        free(concat);
        free(digest);
        free(filename);
        free(encryptedFilename);
        free(ivNew);
        free(concatNew);
        free(digestNew);
        free(newFilename);
        free(encryptedNewFilename);

        cout << "--- FILE RENAMED ---\n";

        return 1;
    }

    int logout()
    {

        // Free keys
        bzero(sessionKey, sessionKeySize);
        free(sessionKey);
        bzero(authKey, sessionKeySize);
        free(authKey);

        // Close connexion
        close(clientfd);

        // Change connexion status
        CONNEXION_STATUS = 0;

        cout << "Client disconnected\n\n";

        return 1;
    }

    int getCommand()
    {

        int ret;

        // Receive the number corresponding to the command to execute
        int *n = (int *)malloc(sizeof(int));
        if (!n)
        {
            cerr << "Error allocating buffer for current command number\n";
            return 0;
        }
        ret = readInt(clientfd, n);
        if (!ret)
        {
            cerr << "Error reading current command number\n";
            return 0;
        }
        int currentCommandNum = *n;
        free(n);

        // Execute the corresponding function
        switch (currentCommandNum)
        {

        case 1:
        {
            ret = uploadFile();
            return ret;
            break;
        }
        case 2:
        {
            ret = downloadFile();
            return ret;
            break;
        }
        case 3:
        {
            ret = deleteFile();
            return ret;
            break;
        }
        case 4:
        {
            ret = listFiles();
            return ret;
            break;
        }
        case 5:
        {
            ret = renameFile();
            return ret;
            break;
        }
        case 6:
        {
            ret = logout();
            return ret;
            break;
        }
        }

        return 1;
    }

    int test() {

        int ret;

        // Get size needed for buffer
        int size = i2d_PublicKey(servTempPubKey, NULL);
        unsigned char * keychar = (unsigned char *) malloc(size);
        cout << "after size\n";

        // Read keychar
        i2d_PublicKey(servTempPubKey, &keychar);
        cout << "after read char\n";

        // Convert back into a key
        EVP_PKEY * key = EVP_PKEY_new();
        d2i_PublicKey(EVP_PKEY_RSA, &key, (const unsigned char **) &keychar, size);
        cout << "after convert\n";

        // TEST
        cout << "converted key\n";
        BIO_dump_fp(stdout, (const char *) key, tempKeySize);

        return 0;

    }

};

int main()
{

    int ret;

    Server serv;
    cout << "Starting server...\n";
    serv.startSocket();
    cout << "Socket connection established\n";

    while (1)
    {

        cout << "Waiting for connection...\n";
        ret = serv.acceptClient();
        if (!ret)
        {
            cerr << "Error accepting client connection, communication stopped\n\n";
            continue;
        }
        cout << "Client " << serv.getClientUsername() << " connected, creating temporary RSA key pair\n";

        ret = serv.generateSessionKeyPair();
        if (!ret)
        {
            cerr << "Error generating temporary RSA key pair, communication stopped\n\n";
            continue;
        }
        cout << "Temporary RSA key pair generated\n";

        cout << "Creating ID proof\n";
        ret = serv.createIdProof();
        if (!ret) {
            cerr << "Error creating ID proof, communication stopped\n\n";
            continue;
        }
        cout << "Proof of ID created\n";

        // cout << "\nTEST\n";
        // serv.test();
        // cout << "TEST END\n\n";

        ret = serv.sendMessage2();
        if (!ret) {
            cerr << "Error sending ID proof\n\n";
            continue;
        }
        cout << "ID proof sent\n";
        
        ret = serv.receiveMessage3();
        if (!ret) {
            cerr << "Error receiving message 3\n\n";
            continue;
        }
        cout << "Message 3 received\n";

        ret = serv.retreiveSessionKey();
        if (!ret) {
            cerr << "Error retreiving session key from client's envelope\n\n";
            continue;
        }
        cout << "Session key retreived\n";

        ret = serv.authenticateClient();
        if (!ret) {
            cerr << "Client could not be authenticated, communication stopped\n\n";
            continue;
        }
        cout << "Client authenticated\n";

        ret = serv.sendMessage4();
        if (!ret) {
            cerr << "Error sending message 4\n";
            continue;
        }
        cout << "Message 4 sent successfully, session started\n";

        while (serv.getConnexionStatus())
        {
            cout << "\nWaiting for user input\n";
            serv.getCommand();
        }
    }

    return 0;
}