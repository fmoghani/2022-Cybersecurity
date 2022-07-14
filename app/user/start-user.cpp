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
#include <vector>
#include "../utils.h"
#include "../const.h"

using namespace std;

#define PORT 1805
namespace fs = std::experimental::filesystem;

class Client
{

    // Sockets
    int socketfd, clientfd;
    struct sockaddr_in serverAddr;

    // Connexion status
    int CONNEXION_STATUS = 0;

    // Client variables
    unsigned char * serverNonce;
    unsigned char *nonce;
    string username;

    // Keys
    unsigned char *sessionKey;

    // Available commands
    vector<string> commands = {"upload", "download", "delete", "list", "rename", "logout"};
    map<string, int> commandsMap;
    string currentCommand;

public:
    // Retreive connexion status
    int getConnexionStatus()
    {

        return CONNEXION_STATUS;
    }

    // Send an encrypted value
    int sendEncrypted(unsigned char *ciphertext, int cipherSize, unsigned char *iv)
    {

        int ret;

        ret = send(socketfd, iv, ivSize, 0);
        if (!ret)
        {
            return 0;
        }
        ret = sendInt(socketfd, cipherSize);
        if (!ret)
        {
            return 0;
        }
        ret = send(socketfd, ciphertext, cipherSize, 0);
        if (!ret)
        {
            return 0;
        }

        return 1;
    }

    // Generate a random and fresh nonce
    int createNonce()
    {

        int ret;

        // Generate a 16 bytes random number to ensure unpredictability
        unsigned char *randomBuf = (unsigned char *)malloc(randBytesSize);
        if (!randomBuf)
        {
            cerr << "Error allocating unsigned buffer for random bytes\n";
            close(clientfd);
            return 0;
        }
        RAND_poll();
        ret = RAND_bytes(randomBuf, randBytesSize);
        if (!ret)
        {
            cerr << "Error generating random bytes\n";
            close(clientfd);
            return 0;
        }
        char *random = (char *)malloc(randBytesSize);
        if (!random)
        {
            cerr << "Error allocating buffer for random bytes *\n";
            close(clientfd);
            return 0;
        }
        memcpy(random, randomBuf, randBytesSize);
        free(randomBuf);

        // Generate a char timestamp to ensure uniqueness
        char *now = (char *)malloc(timeBufferSize);
        if (!now)
        {
            cerr << "Error allocating buffer for date and time\n";
            close(clientfd);
            return 0;
        }
        time_t currTime;
        tm *currentTime;
        time(&currTime);
        currentTime = localtime(&currTime);
        if (!currentTime)
        {
            cerr << "Error creating pointer containing current time\n";
            close(clientfd);
            return 0;
        }
        ret = strftime(now, timeBufferSize, "%Y%j%H%M%S", currentTime);
        if (!ret)
        {
            cerr << "Error putting time in a char array\n";
            close(clientfd);
            return 0;
        }

        // Concatenate random number and timestamp
        char *tempNonce = (char *)malloc(randBytesSize + timeBufferSize);
        if (!tempNonce)
        {
            cerr << "Error allocating char buffer for nonce\n";
            close(clientfd);
            return 0;
        }
        memcpy(tempNonce, random, randBytesSize);
        free(random);
        strcat(tempNonce, now);
        free(now);
        serverNonce = (unsigned char *)malloc(nonceSize);
        if (!nonce)
        {
            cerr << "Error allocating buffer for nonce\n";
            close(clientfd);
            return 0;
        }
        memcpy(serverNonce, tempNonce, nonceSize);
        free(tempNonce);

        return 1;
    }

    // Create a socket connexion
    void connectClient()
    {

        int ret;

        // Socket creation
        socketfd = socket(AF_INET, SOCK_STREAM, 0);
        if (!socketfd)
        {
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
        if (clientfd < 0)
        {
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
        if (!ret)
        {
            cerr << "Error sending username length\n";
            exit(1);
        }
        ret = send(socketfd, username.c_str(), username.size(), 0);
        if (ret <= 0)
        {
            cerr << "Error sending username to the server\n";
            exit(1);
        }
        file.close();
    }

    // Create and send challenge to the server
    void sendChallenge() {

        int ret;

        // Create nonce
        ret = createNonce();
        if (!ret) {
            cerr << "Error creating nonce for server\n";
            exit(1);
        }

        // Send the challenge
        ret = send(socketfd, serverNonce, nonceSize, 0);
        if (ret <= 0) {
            cerr << "Error sending nonce to the server\n";
            exit(1);
        }
    }

    // Authenticate server
    void authenticateServer()
    {

        int ret;

        // Read CA certificate
        string CACertPath = "../certificates/CAcert.pem";
        X509 *CACert = readCertificate(CACertPath); // Function from utils.h
        if (!CACert)
        {
            cerr << "Error reading server CA certificate\n";
            exit(1);
        }

        // Read CA crl
        string CACrlPath = "../certificates/CAcrl.pem";
        X509_CRL *CACrl = readCrl(CACrlPath); // Function from utils.h
        if (!CACrl)
        {
            cerr << "Error reading CA Crl\n";
            exit(1);
        }

        // Create a store with CA certificate and crl
        X509_STORE *store = X509_STORE_new();
        if (!store)
        {
            cerr << "Error : cannot create store\n";
            exit(1);
        }
        ret = X509_STORE_add_cert(store, CACert);
        if (!ret)
        {
            cerr << "Error : cannot add CA certificate to the store\n";
            exit(1);
        }
        ret = X509_STORE_add_crl(store, CACrl);
        if (!ret)
        {
            cerr << "Error cannot add CA CRL to the store\n";
            exit(1);
        }

        // Make sure crl will be checked when authenticating server
        ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
        if (!ret)
        {
            cerr << "Error setting certificate store flag\n";
            exit(1);
        }

        // Read server certificate
        string serverCertPath = "../certificates/servcert.pem";
        X509 *serverCert = readCertificate(serverCertPath); // Function from utils.h
        if (!ret)
        {
            cerr << "Error reading server certificate\n";
            exit(1);
        }

        // Verify server's certificate
        X509_STORE_CTX *ctx = X509_STORE_CTX_new();
        if (!ret)
        {
            cerr << "Error during certificate verification context creation\n";
            exit(1);
        }
        ret = X509_STORE_CTX_init(ctx, store, serverCert, NULL);
        if (!ret)
        {
            cerr << "Error initializing certificate verification\n";
            exit(1);
        }
        ret = X509_verify_cert(ctx);
        if (ret <= 0)
        {
            cerr << "Error server not authenticated\n";
            exit(1);
        }
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);

        // Receive server sig
        int * sizePtr = (int *) malloc(sizeof(int));
        if (!sizePtr) {
            cerr << "Error allocating buffer for sig size\n";
            exit(1);
        }
        ret = readInt(socketfd, sizePtr);
        if (!ret) {
            cerr << "Error reading sig size\n";
            exit(1);
        }
        int sigSize = *sizePtr;
        free(sizePtr);
        unsigned char * sig = (unsigned char *) malloc(sigSize);
        if (!sig) {
            cerr << "Error allocating buffer for signature\n";
            exit(1);
        }
        ret = read(socketfd, sig, sigSize);
        if (ret <= 0) {
            cerr << "Error reading sig\n";
            exit(1);
        }

        // Verify signature
        const EVP_MD * md = EVP_sha256();
        EVP_MD_CTX * mdCtx = EVP_MD_CTX_new();
        if (!ctx) {
            cerr << "Error creating context for verifying sig\n";
            exit(1);
        }
        ret = EVP_VerifyInit(mdCtx, md);
        if (!ret) {
            cerr << "Error during init for verifying sig\n";
            exit(1);
        }
        ret = EVP_VerifyUpdate(mdCtx, serverNonce, nonceSize);
        if (ret <= 0) {
            cerr << "Error during update for verifying sig\n";
            exit(1);
        }
        ret = EVP_VerifyFinal(mdCtx, sig, sigSize, X509_get0_pubkey(serverCert));
        if (!ret) {
            cerr << "Server could not be authenticated\n";
            exit(1);
        }
        if (ret < 0) {
            cerr << "Error during finalization for verifying sig\n";
            exit(1);
        }
    }

    // Receive server's envelope and decrypt it to retreive session key
    void retreiveSessionKey()
    {

        int ret;

        // Receive encrypted key
        int *sizeKey = (int *)malloc(sizeof(int));
        if (!sizeKey)
        {
            cerr << "Error allocating buffer for encrypted key size\n";
            exit(1);
        }
        ret = readInt(socketfd, sizeKey);
        if (!ret)
        {
            cerr << "Error reading enrypted key size\n";
            exit(1);
        }
        int encryptedKeySize = (*sizeKey);
        free(sizeKey);
        unsigned char * tempEncryptedKey = (unsigned char *) malloc(encryptedKeySize);
        if (!tempEncryptedKey) {
            cerr << "Error allocating buffer for encrypted key\n";
        }
        ret = read(socketfd, tempEncryptedKey, encryptedKeySize);
        if(ret <= 0) {
            cerr << "Error reading encrypted key\n";
            exit(1);
        }
        unsigned char * encryptedKey = (unsigned char *) malloc(encryptedKeySize);
        memcpy(encryptedKey, tempEncryptedKey, encryptedKeySize);
        free(tempEncryptedKey);

        // Receive encrypted session key
        int *size = (int *)malloc(sizeof(int));
        if (!size)
        {
            cerr << "Error allocating buffer for encrypted session key size\n";
            exit(1);
        }
        ret = readInt(socketfd, size);
        if (!ret)
        {
            cerr << "Error reading encrypted session key size\n";
            exit(1);
        }
        int encryptedSize = *size;
        free(size);
        unsigned char * tempEncryptedSecret = (unsigned char *) malloc(encryptedSize);
        if (!tempEncryptedSecret) {
            cerr << "Error allocating buffer for encrypted session key\n";
            exit(1);
        }
        ret = read(socketfd, tempEncryptedSecret, encryptedSize);
        if (ret <= 0) {
            cerr << "Error reading encrypted session key\n";
            exit(1);
        }
        unsigned char * encryptedSecret = (unsigned char *) malloc(encryptedSize);
        memcpy(encryptedSecret, tempEncryptedSecret, encryptedSize);
        free(tempEncryptedSecret);

        // Receive iv
        int *sizeIv = (int *)malloc(sizeof(int));
        if (!sizeIv)
        {
            cerr << "Error allocating buffer for iv size\n";
            exit(1);
        }
        ret = readInt(socketfd, sizeIv);
        if (!ret)
        {
            cerr << "Error reading iv\n";
            exit(1);
        }
        int ivLength = *sizeIv;
        free(sizeIv);
        unsigned char * tempIv = (unsigned char *) malloc(ivLength);
        if (!tempIv) {
            cerr << "Error allocating buffer for iv\n";
            exit(1);
        }
        ret = read(socketfd, tempIv, ivLength);
        if(ret <= 0) {
            cerr << "Error reading iv\n";
            exit(1);
        }
        unsigned char * iv = (unsigned char *) malloc(ivLength);
        memcpy(iv, tempIv, ivLength);
        free(tempIv);

        // Retreive user's prvkey
        string path = "user_infos/key.pem";
        FILE *keyFile = fopen(path.c_str(), "r");
        if (!keyFile)
        {
            cerr << "Error could not open client private key file\n";
            exit(1);
        }
        const char *password = "password";
        EVP_PKEY *clientPrvKey = PEM_read_PrivateKey(keyFile, NULL, NULL, (void *)password);
        fclose(keyFile);
        if (!clientPrvKey)
        {
            cerr << "Error cannot read client private key from pem file\n";
            exit(1);
        }

        // Decrypt the challenge envelope

        // Useful variables
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();
        int decryptedSize;

        // Create buffer for temporary session key
        sessionKey = (unsigned char *) malloc(sessionKeySize);
        if (!sessionKey) {
            cerr << "Error allocating buffer for session key\n";
            exit(1);
        }

        // Digital envelope
        int bytesWritten;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            cerr << "Error creating context for envelope decryption\n";
            exit(1);
        }
        ret = EVP_OpenInit(ctx, cipher, encryptedKey, encryptedKeySize, iv, clientPrvKey);
        if (ret <= 0)
        {
            cerr << "Error during initialization for envelope decryption\n";
            exit(1);
        }
        ret = EVP_OpenUpdate(ctx, sessionKey, &bytesWritten, encryptedSecret, encryptedSize);
        if (ret <= 0)
        {
            cerr << "Error during update for envelope decryption\n";
            exit(1);
        }
        decryptedSize = bytesWritten;
        ret = EVP_OpenFinal(ctx, sessionKey + decryptedSize, &bytesWritten);
        if (ret <= 0)
        {
            cerr << "Error during finalization for envelope decryption\n";
            exit(1);
        }
        decryptedSize += bytesWritten;

        EVP_CIPHER_CTX_free(ctx);
        free(encryptedKey);
        free(iv);
        free(encryptedSecret);
    }

    // Send to the server a proof of identity using the nonce
    void proveIdentity()
    {

        int ret;

        // Receive encrypted nonce
        int *size = (int *)malloc(sizeof(int));
        if (!size)
        {
            cerr << "Error allocating buffer for size of encrypted nonce\n";
        }
        ret = readInt(socketfd, size);
        if (!ret)
        {
            cerr << "Error reading encrypted nonce size\n";
            exit(1);
        }
        int encryptedSize = *size;
        free(size);
        unsigned char *encryptedNonce = (unsigned char *)malloc(encryptedSize);
        if (!encryptedNonce)
        {
            cerr << "Error allocating buffer for encrypted nonce\n";
            exit(1);
        }
        ret = read(socketfd, encryptedNonce, encryptedSize);
        if (ret <= 0)
        {
            cerr << "Error reading encrypted nonce\n";
            exit(1);
        }

        // Receive iv
        unsigned char *iv = (unsigned char *)malloc(ivSize);
        if (!iv)
        {
            cerr << "Error allocating buffer for iv\n";
            exit(1);
        }
        ret = read(socketfd, iv, ivSize);
        if (ret <= 0)
        {
            cerr << "Error reading iv for nonce decryption\n";
            exit(1);
        }

        // Decrypt nonce using the shared session key
        unsigned char *nonce = (unsigned char *)malloc(encryptedSize);
        if (!nonce)
        {
            cerr << "Error allocating buffer for decrypted nonce\n";
            exit(1);
        }
        ret = decryptSym(encryptedNonce, encryptedSize, nonce, iv, sessionKey);
        if (!ret)
        {
            cerr << "Error decrypting the nonce\n";
            exit(1);
        }

        // Send nonce to the server
        ret = send(socketfd, nonce, nonceSize, 0);
        if (ret <= 0) {
            cerr << "Error sending nonce to the server\n";
            exit(1);
        }

        // Free everything
        free(encryptedNonce);
        free(iv);
        free(nonce);

        CONNEXION_STATUS = 1;
    }

    int uploadFile() {

        int ret;

        cout << ">> To upload a file, please write the file name :\n>> ";

        // Get Upload File path from User
        string filepath;
        getline(cin, filepath);

        // Check valididy of filename
        ret = checkFilename(filepath);
        if (!ret) {
            cout << "Filename not valid\n";
            return 0;
        }

        // Check File Existence
        FILE * file = fopen(filepath.c_str(), "rb");
        if (!file) {
            cout << ">> File doesn't exists\n";
            return 0;
        }

        // Check file size
        std::ifstream infile(filepath);
        infile.seekg(0, std::ios::end);
        int upload_size = infile.tellg();
        if(upload_size > MAX_FILE_SIZE_FOR_UPLOAD){
            cout << "File size is larger than supported (maxSize = " << upload_size << " bytes)\n";    
            return 0;
        }

        // Send encrypted filename to server 
        unsigned char * encryptedFilepath = (unsigned char *) malloc(filepath.size() + blockSize);
        unsigned char * iv = (unsigned char *) malloc(ivSize);
        if (!encryptedFilepath || !iv) {
            cout << "Error allocating buffer to encrypt filename\n";
            return 0;
        }
        unsigned char * charFilepath = (unsigned char *) malloc(filepath.size());
        copy(filepath.begin(), filepath.end(), charFilepath);
        ret = encryptSym(charFilepath, filepath.size(), encryptedFilepath, iv, sessionKey);
        if (!ret) {
            cerr << "Error encrypting the upload filepath\n";
            return 0;
        }
        int encryptedSize = ret;
        ret = sendInt(socketfd, encryptedSize);
        if (!ret) {
            cerr << "Error sending encrypted size for upload filepath to server\n";
            return 0;
        }
        ret = send(socketfd, encryptedFilepath, encryptedSize, 0);
        if (ret <= 0) {
            cerr << "Error sending encrypted upload filepath to server\n";
            return 0;
        }
        // Send iv
        ret = send(socketfd, iv, ivSize, 0);
        if (ret <= 0) {
            cerr << "Error sending iv for upload filepath decryption to server\n";
            return 0;
        }

        // Send filesize to the server
        cout << ">> File Size is " << upload_size<<"\n";
        ret = sendInt(socketfd, upload_size);
        if (!ret) {
            cerr << "Error sending upload filesize to server\n";
            return 0;
        }

        //send file block by block
        infile.seekg(0, std::ios::beg);
        char plainBuffer[UPLOAD_BUFFER_SIZE];
        int remainbytes = upload_size;
        while((!infile.eof()) && (remainbytes > 0)){

            int readlength = sizeof(plainBuffer);
            readlength = std::min(readlength,remainbytes);
            remainbytes -= readlength;
            infile.read(plainBuffer, readlength);
            unsigned char * cyperBuffer = (unsigned char *) malloc(readlength + blockSize);
            unsigned char * iv = (unsigned char *) malloc(ivSize);
            if (!cyperBuffer || !iv) {
                cerr << "Error allocating buffers for file block encryption\n";
                return 0;
            }
            int ret = encryptSym((unsigned char *)plainBuffer, readlength, cyperBuffer, iv, sessionKey);
            if (!ret) {
                cerr << "Error encrypting the upload block\n";
                return 0;
            }
            int encryptedSize = ret;

            // Send encrypted block
            ret = sendInt(socketfd, encryptedSize);
            if (!ret) {
                cerr << "Error sending upload buffer size to server\n";
                return 0;
            }
            ret = send(socketfd, cyperBuffer, encryptedSize, 0);
            if (ret <= 0) {
                cerr << "Error sending encrypted upload buffer to server\n";
                return 0;
            }
            ret = send(socketfd, iv, ivSize, 0);
            if (ret <= 0) {
                cerr << "Error sending upload buffer iv to server\n";
                return 0;
            }
        }
        infile.close();

        cout << ">> File uploaded successfully\n";

        return 1;
    }

    int downloadFile() {

        int ret;

        cout << ">> Please type the name of the file to download:\n>> ";

        // Get Upload File path from User
        string filepath;
        getline(cin, filepath);

        // Check validity of filename
        ret = checkFilename(filepath);
        if (!ret) {
            cout << ">> Filename not valid\n";
            return 0;
        }

        // Encrypt filename
        unsigned char * encryptedFilepath = (unsigned char *) malloc(filepath.length() + blockSize);
        unsigned char * iv = (unsigned char *) malloc(ivSize);
        if (!encryptedFilepath || !iv) {
            cerr << "Error allocating buffers to encrypt filename\n";
            return 0;
        }
        ret = encryptSym((unsigned char *)filepath.c_str(), filepath.length(), encryptedFilepath, iv, sessionKey);
        if (!ret) {
            cerr << "Error encrypting the upload filepath\n";
            return 0;
        }

        // Send encrypted filename
        int encryptedSize = ret;
        ret = sendInt(socketfd, encryptedSize);
        if (!ret) {
            cerr << "Error sending encrypted size for upload filepath to server\n";
            return 0;
        }
        ret = send(socketfd, encryptedFilepath, encryptedSize, 0);
        if (ret <= 0) {
            cerr << "Error sending encrypted upload filepath to server\n";
            return 0;
        }

        // Send iv
        ret = send(socketfd, iv, ivSize, 0);
        if (ret <= 0) {
            cerr << "Error sending iv for upload filepath decryption to server\n";
            return 0;
        }

        // Receive server's existence of file
        int * responsePtr = (int *) malloc(sizeof(int));
        ret = readInt(socketfd, responsePtr);
        if (!(*responsePtr)) {
            cout << ">> File doesn't exists\n";
            return 0;
        }
        cout << "server response : " << *responsePtr << endl;
        free(responsePtr);

        // Receive file size
        int * upload_size = (int *) malloc(sizeof(int));
        ret = readInt(socketfd, upload_size);
        if (!ret) {
            cerr << "Error upload filepath length\n";
            return 0;
        }
        int remainedBlock = *upload_size;
        free(upload_size);

        // Create file to write in
        ofstream wf(filepath, ios::out | ios::binary);
        if(!wf) {
            cout << "Cannot open file to write upload file!" << endl;
            return 1;
        }

        // Read and decrypt every block files
        while(remainedBlock>0){

            // Receive everything for decryption
            int * uploadBlockLen = (int *) malloc(sizeof(int));
            ret = readInt(socketfd, uploadBlockLen);
            if (!ret) {
                cerr << "Error upload block length\n";
                return 0;
            }
            unsigned char * iv = (unsigned char *) malloc(ivSize);
            unsigned char * cyberBuffer = (unsigned char *) malloc(*uploadBlockLen);
            unsigned char * plainBuffer = (unsigned char *) malloc(UPLOAD_BUFFER_SIZE);
            if (!iv || !cyberBuffer || !plainBuffer) {
                cout << "Error allocating buffers to decrypt file block\n";
                return 0;
            }
            ret = read(socketfd, cyberBuffer, *uploadBlockLen);
            if (!ret) {
                cerr << "Error reading encrypted upload block\n";
                return 0;
            }
            ret = read(socketfd, iv, ivSize);
            if (!ret) {
                cerr << "Error reading iv for upload block\n";
                close(socketfd);
                return 0;
            }

            // Decrypt block
            ret = decryptSym(cyberBuffer, *uploadBlockLen, plainBuffer, iv, sessionKey);
            if (!ret) {
                cerr << "Error decrypting the upload block\n";
                return 0;
            }
            free(uploadBlockLen);
            int plaintextLen = ret;

            // Write decrypted block in the file
            for(int i = 0; i < plaintextLen; i++){
                wf.write((char *) &plainBuffer[i], sizeof(char));
            }

            remainedBlock -= plaintextLen;
        }
        wf.close();

        if(!wf.good()) {
            cout << "Error occurred at writing time while saving uploaded file!" << endl;
            return 1;
        }

        cout << ">> Files downloaded successfully\n";

        return 1;
    }

    int deleteFile()
    {
        int ret;

        cout << ">> Please input the file you want to delete: \n>> ";
        string fileName;
        getline(cin, fileName);

        // Check if filename does not contain restricted chars
        ret = checkFilename(fileName);
        if (!ret)
        {
            cout << ">> Filename is not valid \n";
            return 0;
        }

        // Encrypt filename and send to server
        int encryptedFileSize;
        unsigned char *encryptedFileName = (unsigned char *)malloc(fileName.size() + blockSize);
        unsigned char *iv = (unsigned char *)malloc(ivSize);
        if (!encryptedFileName || !iv)
        {
            cout << ">> Error allocating buffers for encryption\n";
            return 0;
        }
        unsigned char * charFilename = (unsigned char *) malloc(fileName.size());
        copy(fileName.begin(), fileName.end(), charFilename);
        ret = encryptSym(charFilename, fileName.size(), encryptedFileName, iv, sessionKey);
        if (!ret)
        {
            cout << ">> Error during decryption\n";
            return 0;
        }
        free(charFilename);
        encryptedFileSize = ret;

        // Send data for decryption to server
        ret = sendEncrypted(encryptedFileName, encryptedFileSize, iv);
        if (!ret)
        {
            cout << ">> Error sending encrypted filename\n";
            return 0;
        }

        // Receive server info : does the file exists or not
        int *responsePtr = (int *)malloc(sizeof(int));
        ret = readInt(socketfd, responsePtr);
        if (!ret)
        {
            cout << ">> Error reading server's response\n";
            return 0;
        }
        int response = *responsePtr;
        free(responsePtr);
        if (!response)
        {
            cout << ">> File does not exists\n";
            return 0;
        }

        cout << ">> File was deleted successfully.\n";
        return 1;
    }

    int listFiles()
    {
        int ret;

        // Receive number of files
        int * numPtr = (int *) malloc(sizeof(int));
        ret = readInt(socketfd, numPtr);
        if (!ret) {
            cout << "Error reading number of files\n";
            return 0;
        }
        int filesNumber = *numPtr;
        free(numPtr);

        // Iterate the correct number of times, read and decrypt the filenames
        for (int i = 0; i < filesNumber; i++) {

            // Read filename
            unsigned char *iv = (unsigned char *)malloc(ivSize);
            ret = read(socketfd, iv, ivSize);
            if (!ret) {
                cout << "Error reading iv\n";
                return 0;
            }
            int *encryptedSizePtr = (int *)malloc(sizeof(int));
            if (!encryptedSizePtr) {
                cout << "Error allocating buffer for encrypted filename size\n";
                return 0;
            }
            ret = readInt(socketfd, encryptedSizePtr);
            if (!ret) {
                cout << "Error reading encrypted filename size\n";
                return 0;
            }
            int encryptedSize = *encryptedSizePtr;
            free(encryptedSizePtr);
            unsigned char *encryptedFilename = (unsigned char *)malloc(encryptedSize);
            ret = read(socketfd, encryptedFilename, encryptedSize);

            // Decrypt filename
            unsigned char *buggedFilename = (unsigned char *)malloc(encryptedSize);
            int decryptedSize;
            decryptedSize = decryptSym(encryptedFilename, encryptedSize, buggedFilename, iv, sessionKey);
            if (!decryptedSize)
            {
                cout << "Error decrypting filename\n";
                return 0;
            }
            unsigned char *filename = (unsigned char *)malloc(decryptedSize);
            memcpy(filename, buggedFilename, decryptedSize);
            free(buggedFilename);

            // Display the filename
            string sfilename(filename, filename + decryptedSize);
            cout << sfilename << endl;
        }

        cout << ">> Files listed\n";

        return 1;
    }

    int renameFile()
    {

        int ret;

        cout << ">> Please input the name of the file you want to rename :\n>> ";
        string filename;
        getline(cin, filename);

        // First check that file does not contain blacklisted characters
        ret = checkFilename(filename);
        if (!ret)
        {
            cout << ">> Filename not valid\n";
            return 0;
        }

        // Encrypt filename
        int encryptedSize;
        unsigned char *encryptedFilename = (unsigned char *)malloc(filename.size() + blockSize);
        unsigned char *iv = (unsigned char *)malloc(ivSize);
        if (!encryptedFilename || !iv)
        {
            cout << ">> Error allocating buffers for encryption\n";
            return 0;
        }
        unsigned char * charFilename = (unsigned char *) malloc(filename.size());
        copy(filename.begin(), filename.end(), charFilename);
        ret = encryptSym(charFilename, filename.size(), encryptedFilename, iv, sessionKey);
        if (!ret)
        {
            cout << ">> Error during encryption\n";
            return 0;
        }
        free(charFilename);
        encryptedSize = ret;

        // Send infos necessary for decryption
        ret = sendEncrypted(encryptedFilename, encryptedSize, iv);
        if (!ret)
        {
            cout << ">> Error sending encrypted filename\n";
            return 0;
        }

        // Receive server info : does the file exists or not
        int *responsePtr = (int *)malloc(sizeof(int));
        ret = readInt(socketfd, responsePtr);
        if (!ret)
        {
            cout << ">> Error reading server's response\n";
            return 0;
        }
        int response = *responsePtr;
        free(responsePtr);
        if (!response)
        {
            cout << ">> File does not exists\n";
            return 0;
        }

        // Ask for new name and check its validity
        string newFilename;
        cout << ">> Please type the name of the new file :\n>> ";
        getline(cin, newFilename);
        ret = checkFilename(newFilename);
        if (!ret)
        {
            cout << ">> New filename not valid\n";
            return 0;
        }

        // Encrypt new filename
        int encryptedSizeNew;
        unsigned char *encryptedNewFilename = (unsigned char *)malloc(newFilename.size() + blockSize);
        unsigned char *ivNew = (unsigned char *)malloc(ivSize);
        if (!encryptedNewFilename || !ivNew)
        {
            cout << ">> Error allocating buffers for encryption\n";
            return 0;
        }
        unsigned char * charNewFilename = (unsigned char *) malloc(newFilename.size());
        copy(newFilename.begin(), newFilename.end(), charNewFilename);
        ret = encryptSym(charNewFilename, newFilename.size(), encryptedNewFilename, ivNew, sessionKey);
        if (!ret)
        {
            cout << ">> Error during encryption\n";
            return 0;
        }
        free(charNewFilename);
        encryptedSizeNew = ret;

        // Send the encrypted filename
        ret = sendEncrypted(encryptedNewFilename, encryptedSizeNew, ivNew);
        if (!ret)
        {
            cout << ">> Error sending encrypted new filename\n";
            return 0;
        }

        // Free everything
        free(encryptedFilename);
        free(iv);
        free(encryptedNewFilename);
        free(ivNew);

        cout << ">> File was renamed successfully\n";

        return 1;
    }

    int logout()
    {

        // Free key
        bzero(sessionKey, sessionKeySize);
        free(sessionKey);

        // Close connexion
        close(socketfd);

        // Change connexion status
        CONNEXION_STATUS = 0;

        cout << ">> Client disconnected\n";

        return 1;
    }

    // Update the map containing references to the functions for every command
    void updateCommands()
    {

        commandsMap["upload"] = 1;
        commandsMap["download"] = 2;
        commandsMap["delete"] = 3;
        commandsMap["list"] = 4;
        commandsMap["rename"] = 5;
        commandsMap["logout"] = 6;
    }

    // Nothing to explain here
    void displayCommands()
    {

        cout << ">> ";
        for (size_t index = 0; index < commands.size() - 1; index++)
        {
            cout << commands[index] << ", ";
        }
        cout << commands.back() << "\n";
    }

    // Get a command from the user, verify it matches a possible action and start the action
    int getCommand()
    {

        string command;

        cout << ">> ";
        getline(cin, command);

        for (string s : commands)
        {
            if (!command.compare(s))
            {
                currentCommand = s;
                return 1; // Command matches a possible command
            }
        }

        return 0;
    }

    // Start the action corresponding to the current command
    int startAction()
    {

        int ret;
        int currentCommandNum = commandsMap[currentCommand];

        // First send the function to execute to the server
        ret = sendInt(socketfd, currentCommandNum);
        if (!ret)
        {
            cerr << "Error sending command number through socket\n";
            return 0;
        }

        // Then activate the correct function client side
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

};

int main()
{

    int ret;
    Client user1;

    cout << "Starting client, waiting for server to be available...\n";
    user1.connectClient();
    cout << "Client successfuly connected to the server\n";

    user1.sendChallenge();
    cout << "Challenge sent to the client\n";

    user1.authenticateServer();
    cout << "Server authenticated, waiting for server's envelope...\n";

    user1.retreiveSessionKey();
    cout << "Session key received\n";

    user1.proveIdentity();
    cout << "Proof of identity sent\n";

    user1.updateCommands();
    cout << "Session started\n";

    while (user1.getConnexionStatus())
    {

        cout << "\n>> Choose a command from the one below :\n";
        user1.displayCommands();

        ret = user1.getCommand();
        if (!ret)
        {
            cerr << ">> Command not valid, please try again\n\n";
            continue;
        }

        ret = user1.startAction();
        if (!ret)
        {
            cerr << ">> Command failed, please try again\n\n";
            continue;
        }
    }

    return 0;
}
