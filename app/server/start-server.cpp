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

    // Keys
    EVP_PKEY * servTempPubKey;
    unsigned char * charTempPubKey;
    EVP_PKEY * servTempPrvKey;
    unsigned char *sessionKey;
    unsigned char * envelope;
    int envelopeSize;

    // Signatures
    unsigned char * serverSig;
    unsigned int serverSigSize;
    unsigned char * clientSig;
    unsigned int clientSigSize;

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

    // Send an encrypted value
    int sendEncrypted(unsigned char *ciphertext, int cipherSize, unsigned char *iv)
    {

        int ret;

        ret = send(clientfd, iv, ivSize, 0);
        if (!ret)
        {
            return 0;
        }
        ret = sendInt(clientfd, cipherSize);
        if (!ret)
        {
            return 0;
        }
        ret = send(clientfd, ciphertext, cipherSize, 0);
        if (!ret)
        {
            return 0;
        }

        return 1;
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
        unsigned char *buffer = (unsigned char *)malloc(*usernameLen);
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
        clientUsername = std::string(reinterpret_cast<char *>(buffer));
        free(usernameLen);
        free(buffer);

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

        // Put the public key inside a char
        charTempPubKey = (unsigned char *) malloc(tempKeySize);
        memcpy(charTempPubKey, servTempPubKey, tempKeySize);

        // TEST
        cout << "Pub key:\n";
        BIO_dump_fp(stdout, (const char *) servTempPubKey, 256);

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

        // Concatenate serverNonce and public key
        unsigned char * concat = (unsigned char *) malloc(nonceSize + tempKeySize);
        if (!concat) {
            cerr << "Error allocating buffer for concat\n";
            close(clientfd);
            return 0;
        }
        memcpy(concat, clientNonce, nonceSize);
        memcpy(concat + nonceSize, charTempPubKey, tempKeySize);
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
        ret = EVP_SignUpdate(ctx, concat, nonceSize + tempKeySize);
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

        return 1;
    }

    int sendMessage2() {

        int ret;
        int totalSize = tempKeySize + serverSigSize + nonceSize;

        // Concatenate temp public key, server's signature and serer nonce
        unsigned char * concat = (unsigned char *) malloc(totalSize);
        if (!concat) {
            cerr << "Error allocating buffer for message 2\n";
            close(clientfd);
            return 0;
        }
        memcpy(concat, charTempPubKey, tempKeySize);
        memcpy(concat + tempKeySize, serverSig, serverSigSize);
        memcpy(concat + tempKeySize + serverSigSize, serverNonce, nonceSize);
        free(serverSig);

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

        // EVP_PKEY_free(servTempPubKey);
        // cout << "after free\n";

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
        int totalSize = *totalSizePtr;;;;
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
        envelopeSize = totalSize - clientSigSize;
        envelope = (unsigned char *) malloc(envelopeSize);
        clientSig = (unsigned char *) malloc(clientSigSize);
        if (!envelope || !clientSig) {
            cerr << "Error allocating buffer for message 3\n";
            close(clientfd);
            return 0;
        }
        memcpy(envelope, concat, envelopeSize);
        memcpy(clientSig, concat + envelopeSize, clientSigSize);
        free(concat);

        return 1;
    }

    // Receive user's envelope and decrypt it to retreive session key
    int retreiveSessionKey()
    {

        int ret;

        // Allocate buffers
        int encryptedSize = tempKeySize + blockSize;
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

        // Create buffer for session key
        sessionKey = (unsigned char *) malloc(sessionKeySize);
        if (!sessionKey) {
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
        ret = EVP_OpenUpdate(ctx, sessionKey, &bytesWritten, encryptedSecret, encryptedSize);
        if (ret <= 0)
        {
            cerr << "Error during update for envelope decryption\n";
            close(clientfd);
            return 0;
        }
        decryptedSize = bytesWritten;
        ret = EVP_OpenFinal(ctx, sessionKey + decryptedSize, &bytesWritten);
        if (ret <= 0)
        {
            cerr << "Error during finalization for envelope decryption\n";
            close(clientfd);
            return 0;
        }
        decryptedSize += bytesWritten;

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
        unsigned char * concat = (unsigned char *) malloc(nonceSize + sessionKeySize);
        if (!concat) {
            cerr << "Error allocating buffer for concat\n";
            close(clientfd);
            return 0;
        }
        memcpy(concat, serverNonce, nonceSize);
        memcpy(concat + nonceSize, sessionKey, sessionKeySize);
        free(serverNonce);

        // Retreive user's pubkey to encrypt session key
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
        ret = EVP_VerifyUpdate(mdCtx, concat, nonceSize + sessionKeySize);
        if (ret <= 0) {
            cerr << "Error during update for verifying sig\n";
            close(clientfd);
            return 0;
        }
        ret = EVP_VerifyFinal(mdCtx, clientSig, clientSigSize, clientPubKey);
        if (!ret) {
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
        free(serverNonce);
        EVP_PKEY_free(clientPubKey);
        
        CONNEXION_STATUS = 1;

        return 1;
    }

    int uploadFile() {
        
        int ret;

        cout << "Client "<< clientUsername << " upload request\n";

        // Read File Path
        int * filepathEncLen = (int *) malloc(sizeof(int));
        unsigned char * iv = (unsigned char *) malloc(ivSize);
        if (!filepathEncLen || !iv) {
            cout << "Error allocating buffers to receive encrypted filename\n";
            return 0;
        }
        if (!filepathEncLen) {
            cerr << "Error allocating buffer for upload filepath length\n";
            return 0;
        }
        ret = readInt(clientfd, filepathEncLen);
        if (!ret) {
            cerr << "Error upload filepath length\n";
            return 0;
        }
        unsigned char * filepathEnc = (unsigned char *) malloc(*filepathEncLen);
        if (!filepathEnc) {
            cerr << "Error allocating buffer for upload filepath\n";
            return 0;
        }
        ret = read(clientfd, filepathEnc, *filepathEncLen);
        if (!ret) {
            cerr << "Error reading upload filepath\n";
            return 0;
        }
        ret = read(clientfd, iv, ivSize);
        if (!ret) {
            cerr << "Error reading iv for upload filepath\n";
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

        // Create file in user's file folder
        ofstream wf(path, ios::out | ios::binary);
        if(!wf) {
            cout << "Cannot open file to write upload file!" << endl;
            return 0;
        }

        // Read file content
        while(remainedBlock>0){

            // Receive data
            int * uploadBlockLen = (int *) malloc(sizeof(int));
            ret = readInt(clientfd, uploadBlockLen);
            if (!ret) {
                cerr << "Error upload block length\n";
                return 0;
            }
            unsigned char * iv = (unsigned char *) malloc(ivSize);
            unsigned char * cyberBuffer = (unsigned char *) malloc(*uploadBlockLen);
            unsigned char * plainBuffer = (unsigned char *) malloc(UPLOAD_BUFFER_SIZE);
            if (!iv || !cyberBuffer || !plainBuffer) {
                cerr << "Error allocating buffers for file block decryption\n";
                return 0;
            }
            ret = read(clientfd, cyberBuffer, *uploadBlockLen);
            if (!ret) {
                cerr << "Error reading encrypted upload block\n";
                close(clientfd);
                return 0;
            }
            ret = read(clientfd, iv, ivSize);
            if (!ret) {
                cerr << "Error reading iv for upload block\n";
                close(clientfd);
                return 0;
            }

            // Decrypt data
            ret = decryptSym(cyberBuffer, *uploadBlockLen, plainBuffer, iv, sessionKey);
            if (!ret) {
                cerr << "Error decrypting the upload block\n";
                return 0;
            }
            int plaintextLen = ret; 

            // Write decrypted content into the file on user's filesystem
            for(int i = 0; i < plaintextLen; i++){
                wf.write((char *) &plainBuffer[i], sizeof(char));
            }
            remainedBlock -= plaintextLen;
        }
        wf.close();

        if(!wf.good()) {
            cout << "Error occurred at writing time while saving uploaded file!" << endl;
            return 0;
        }

        cout << "--- FILE UPLOADED ---\n";
        
        return 1;
    }

    int downloadFile() {

        int ret;

        cout << "Client "<< clientUsername << " download request\n";
        
        //Read File Path
        int * filepathEncLen = (int *) malloc(sizeof(int));
        unsigned char * iv = (unsigned char *) malloc(ivSize);
        if (!filepathEncLen || !iv) {
            cerr << "Error allocating buffers for enrypted filename\n";
            return 0;
        }
        if (!filepathEncLen) {
            cerr << "Error allocating buffer for upload filepath length\n";
            return 0;
        }
        ret = readInt(clientfd, filepathEncLen);
        if (!ret) {
            cerr << "Error upload filepath length\n";
            return 0;
        }
        unsigned char * filepathEnc = (unsigned char *) malloc(*filepathEncLen);
        if (!filepathEnc) {
            cerr << "Error allocating buffer for upload filepath\n";
            return 0;
        }
        ret = read(clientfd, filepathEnc, *filepathEncLen);
        if (!ret) {
            cerr << "Error reading upload filepath\n";
            return 0;
        }
        ret = read(clientfd, iv, ivSize);
        if (!ret) {
            cerr << "Error reading iv for upload filepath\n";
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

        // Check existence of the file and send the response to the client
        ret = existsFile(filepath, clientUsername);
        int exists = ret;
        ret = sendInt(clientfd, exists);
        if (!ret) {
            cout << "File does not exists\n";
            return 0;
        }

        cout << "Requested file: " << filepath << "\n";

        // Get complete path to the file
        string sfullPath = "users_info/" + clientUsername + "/files" + filepath;
        fs::path fullPath(sfullPath);

        free(filepathEncLen);
        free(iv);
        free(filepathEnc);
        free(decryptedFilepath);

        // open file
        std::ifstream infile(fullPath);

        // Send file size to client 
        infile.seekg(0, std::ios::end);
        int upload_size = infile.tellg();
        ret = sendInt(clientfd, upload_size);
        if (!ret) {
            cerr << "Error sending upload filesize to client\n";
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
            
            // Encrypt the block
            unsigned char * cyperBuffer = (unsigned char *) malloc(readlength + blockSize);
            unsigned char * iv = (unsigned char *) malloc(ivSize);
            if (!cyperBuffer || !iv) {
                cerr << "Error allocating buffer for encrypting file block\n";
                return 0;
            }
            int ret = encryptSym((unsigned char *)plainBuffer, readlength, cyperBuffer, iv, sessionKey);
            if (!ret) {
                cerr << "Error encrypting the upload block\n";
                return 0;
            }
            int encryptedSize = ret;

            // Send encrypted block
            ret = sendInt(clientfd, encryptedSize);
            if (!ret) {
                cerr << "Error sending upload buffer size to server\n";
                return 0;
            }
            ret = send(clientfd, cyperBuffer, encryptedSize, 0);
            if (ret <= 0) {
                cerr << "Error sending encrypted upload buffer to server\n";
                return 0;
            }
            ret = send(clientfd, iv, ivSize, 0);
            if (ret <= 0) {
                cerr << "Error sending upload buffer iv to server\n";
                return 0;
            }
        }
        infile.close();
        
        cout << "--- FILE DOWNLOADED ---\n";
        
        return 1;
    }

    int deleteFile()
    {
        int ret;

        // Receive filename
        unsigned char *iv = (unsigned char *)malloc(ivSize);
        ret = read(clientfd, iv, ivSize);
        if (!ret)
        {
            cout << "Error reading iv\n";
            return 0;
        }
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
        unsigned char *encryptedFilename = (unsigned char *)malloc(encryptedSize);
        ret = read(clientfd, encryptedFilename, encryptedSize);

        // Decrypt new filename
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
            return 1; // If the file does not exists we get out of the function without doing anything
        }

        // Delete file
        error_code ec;
        string spath = "./users_infos/" + clientUsername + "/files/" + sfilename;
        filesystem::path path(spath);
        remove(path, ec);

        // Free Buffers
        free(iv);
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
                cout << ">> Error during encryption\n";
                return 0;
            }
            free(charFilename);
            encryptedSize = ret;

            // Send the encrypted filename to the server
            ret = sendEncrypted(encryptedFilename, encryptedSize, iv);
            if (!ret) {
                cout << "Error sending encrypted filename\n";
                return 0;
            }
        }

        cout << "--- FILES LISTED ---\n";

        return 1;
    }

    int renameFile()
    {

        int ret;

        // Receive filename
        unsigned char *iv = (unsigned char *)malloc(ivSize);
        ret = read(clientfd, iv, ivSize);
        if (!ret)
        {
            cout << "Error reading iv\n";
            return 0;
        }
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
        unsigned char *encryptedFilename = (unsigned char *)malloc(encryptedSize);
        ret = read(clientfd, encryptedFilename, encryptedSize);

        // Decrypt new filename
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
            return 1; // If the file does not exists we get out of the function without doing anything
        }

        // Receive new encrypted filename
        unsigned char *ivNew = (unsigned char *)malloc(ivSize);
        ret = read(clientfd, ivNew, ivSize);
        if (!ret)
        {
            cout << "Error reading ivNew\n";
            return 0;
        }
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
        unsigned char *encryptedNewFilename = (unsigned char *)malloc(encryptedNewSize);
        ret = read(clientfd, encryptedNewFilename, encryptedNewSize);

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
        free(filename);
        free(encryptedFilename);
        free(ivNew);
        free(newFilename);
        free(encryptedNewFilename);

        cout << "--- FILE RENAMED ---\n";

        return 1;
    }

    int logout()
    {

        // Free key
        bzero(sessionKey, sessionKeySize);
        free(sessionKey);

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
            cerr << "Error creating ID proof, communication stopped\n";
            continue;
        }
        cout << "Proof of ID created\n";

        // cout << "\nTEST\n";
        // serv.test();
        // cout << "TEST END\n\n";

        ret = serv.sendMessage2();
        if (!ret) {
            cerr << "Error sending ID proof\n";
            continue;
        }
        cout << "ID proof sent\n";
        
        ret = serv.receiveMessage3();
        if (!ret) {
            cerr << "Error receiving message 3\n";
            continue;
        }
        cout << "Message 3 received\n";

        ret = serv.retreiveSessionKey();
        if (!ret) {
            cerr << "Error retreiving session key from client's envelope\n";
            continue;
        }
        cout << "Session key retreived\n";

        ret = serv.authenticateClient();
        if (!ret) {
            cerr << "Client could not be authenticated, communication stopped\n\n";
            continue;
        }
        cout << "Client authenticated, session started\n";

        while (serv.getConnexionStatus())
        {
            cout << "\nWaiting for user input\n";
            serv.getCommand();
        }
    }

    return 0;
}