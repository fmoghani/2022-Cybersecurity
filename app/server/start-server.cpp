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
#include "users_infos/khabib/DH.h"
#include "../utils.h"
#include "../const.h"

using namespace std;
using namespace std::experimental;

class Server
{

    // Sockets
    int socketfd, clientfd;
    struct sockaddr_in serverAddr, clientAddr;

    // Connexion status
    int CONNEXION_STATUS = 0;

    // Client infos
    string clientUsername;
    unsigned char *nonce;

    // Map containing all the get_DH2048() functions specific to each user
    std::map<std::string, DH *> dhMap;

    // Keys
    EVP_PKEY *clientPubKey;
    EVP_PKEY *prvKey;

    // Keys
    unsigned char *sessionKey;
    unsigned char *tempKey;

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
        nonce = (unsigned char *)malloc(nonceSize);
        if (!nonce)
        {
            cerr << "Error allocating buffer for nonce\n";
            close(clientfd);
            return 0;
        }
        memcpy(nonce, tempNonce, nonceSize);
        free(tempNonce);

        return 1;
    }

    // Update server's map
    void updateDHMap()
    {

        // Add users and their corresponding dhparam function when needed
        dhMap["khabib"] = get_DH2048_khabib();
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

        CONNEXION_STATUS = 1;

        // Temporary key
        tempKey = (unsigned char *)"01234567890123450123456789012345";

        return 1;
    }

    int generateSessionKey()
    {

        int ret;

        // Create a random key for aes 256
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();
        unsigned char *secret = (unsigned char *)malloc(EVP_CIPHER_key_length(cipher));
        if (!secret)
        {
            cerr << "Symmetric session key could not be allocated\n";
            close(clientfd);
            return 0;
        }
        RAND_poll();
        ret = RAND_bytes(secret, sessionKeySize);
        if (!ret)
        {
            cerr << "Bytes for symmetric key could not be generated\n";
            close(clientfd);
            return 0;
        }

        // Hash the secret to get session key
        sessionKey = (unsigned char *)malloc(EVP_MD_size(EVP_sha256()));
        ret = createHash(secret, sessionKeySize, sessionKey);
        if (!ret)
        {
            cerr << "Error creating hash of the shared secret\n";
            close(clientfd);
            return 0;
        }
        bzero(secret, EVP_CIPHER_key_length(cipher));
        free(secret);

        return 1;
    }

    // Create and send a challenge to authenticate client
    int shareKey()
    {

        int ret;

        // Retreive user's pubkey to encrypt session key
        string path = "users_infos/" + clientUsername + "/pubkey.pem";
        FILE *keyFile = fopen(path.c_str(), "r");
        if (!keyFile)
        {
            cerr << "Error could not open client " << clientUsername << " public key file\n";
            close(clientfd);
            return 0;
        }
        clientPubKey = PEM_read_PUBKEY(keyFile, NULL, NULL, NULL);
        fclose(keyFile);
        if (!clientPubKey)
        {
            cerr << "Error could not read client " << clientUsername << " public key from pem file\n";
            close(clientfd);
            return 0;
        }

        // Encrypt session key using client public key

        // Variables for encryption
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();
        int encryptedKeySize = EVP_PKEY_size(clientPubKey);
        int ivLength = EVP_CIPHER_iv_length(cipher);
        int blockSizeEnvelope = EVP_CIPHER_block_size(cipher);
        int cipherSize = sessionKeySize + blockSizeEnvelope;
        int encryptedSize = 0;

        // Create buffers for encrypted session key, iv, encrypted key
        unsigned char *iv = (unsigned char *)malloc(ivLength);
        unsigned char *encryptedKey = (unsigned char *)malloc(encryptedKeySize);
        unsigned char *encryptedSecret = (unsigned char *)malloc(cipherSize);
        if (!iv || !encryptedKey || !encryptedSecret)
        {
            cout << "Error allocating buffers during nonce encryption\n";
            close(clientfd);
            return 0;
        }

        // Digital envelope
        int bytesWritten = 0;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            cerr << "Error creating context for nonce encryption\n";
            close(clientfd);
            return 0;
        }
        ret = EVP_SealInit(ctx, cipher, &encryptedKey, &encryptedKeySize, iv, &clientPubKey, 1);
        if (ret <= 0)
        {
            cerr << "Error during initialization of encrypted nonce envelope\n";
            close(clientfd);
            return 0;
        }
        ret = EVP_SealUpdate(ctx, encryptedSecret, &bytesWritten, sessionKey, sessionKeySize);
        if (ret <= 0)
        {
            cerr << "Error during update of encrypted nonce envelope\n";
            close(clientfd);
            return 0;
        }
        encryptedSize += bytesWritten;
        ret = EVP_SealFinal(ctx, encryptedSecret + encryptedSize, &bytesWritten);
        if (ret <= 0)
        {
            cerr << "Error during finalization of encrypted nonce envelope\n";
            close(clientfd);
            return 0;
        }
        EVP_CIPHER_CTX_free(ctx);

        // TEST
        cout << "\nENVELOPE TEST\n";
        cout << "encryptedSize = " << encryptedSize << "encrypted secret :\n";
        BIO_dump_fp(stdout, (const char *)encryptedSecret, encryptedSize);
        cout << "encryptedKeySize = " << encryptedKeySize << "encrypted key :\n";
        BIO_dump_fp(stdout, (const char *)encryptedKey, encryptedKeySize);
        cout << "sessionKey :\n";
        BIO_dump_fp(stdout, (const char *)sessionKey, sessionKeySize);
        cout << "ENVELOPE TEST END\n\n";

        // Send the encrypted key
        ret = sendInt(clientfd, encryptedKeySize);
        if (!ret)
        {
            cerr << "Error sending encrypted key size\n";
            close(clientfd);
            return 0;
        }
        ret = send(clientfd, encryptedKey, encryptedKeySize, 0);
        if (ret <= 0)
        {
            cerr << "Error sending encrypted key to " << clientUsername << "\n";
            close(clientfd);
            return 0;
        }
        free(encryptedKey);

        // Send the encrypted session key
        ret = sendInt(clientfd, encryptedSize);
        if (!ret)
        {
            cerr << "Error sending encrcypted size\n";
            close(clientfd);
            return 0;
        }
        ret = send(clientfd, encryptedSecret, encryptedSize, 0);
        if (ret <= 0)
        {
            cerr << "Error sending encrypted session key to " << clientUsername << "\n";
            close(clientfd);
        }
        free(encryptedSecret);

        // Send the iv
        ret = sendInt(clientfd, ivLength);
        if (!ret)
        {
            cerr << "Error sending iv size\n";
            close(clientfd);
            return 0;
        }
        ret = send(clientfd, iv, ivLength, 0);
        if (!ret)
        {
            cerr << "Error sending iv\n";
            close(clientfd);
            return 0;
        }
        free(iv);

        return 1;
    }

    int sendEncryptedNonce()
    {

        int ret;

        // First create nonce
        ret = createNonce();
        if (!ret)
        {
            cerr << "Error creating nonce\n";
            close(clientfd);
            return 0;
        }

        // Encrypt nonce using symmetric key
        int encryptedSize;
        unsigned char *encryptedNonce = (unsigned char *)malloc(nonceSize + blockSize);
        unsigned char *iv = (unsigned char *)malloc(ivSize);
        if (!encryptedNonce || !iv)
        {
            cerr << "Error allocating buffers for encryptedNonce and iv\n";
            close(clientfd);
            return 0;
        }

        ret = encryptSym(nonce, nonceSize, encryptedNonce, iv, tempKey);
        if (!ret)
        {
            cerr << "Error encrypting the nonce\n";
            close(clientfd);
            return 0;
        }
        encryptedSize = ret;

        // TEST
        cout << "\nTEST NONCE\n";
        cout << "encryptedNonceSize = " << encryptedSize << " encryptedNonce :\n";
        BIO_dump_fp(stdout, (const char *)encryptedNonce, encryptedSize);
        cout << "iv Size = " << ivSize << " iv :\n";
        BIO_dump_fp(stdout, (const char *)iv, ivSize);
        cout << "TEST NONCE END\n\n";

        // Send encrypted nonce
        ret = sendInt(clientfd, encryptedSize);
        if (!ret)
        {
            cerr << "Error sending encrypted size for nonce to client\n";
            close(clientfd);
            return 0;
        }
        ret = send(clientfd, encryptedNonce, encryptedSize, 0);
        if (ret <= 0)
        {
            cerr << "Error sending encrypted nonce to client\n";
            close(clientfd);
            return 0;
        }

        // Send iv
        ret = send(clientfd, iv, ivSize, 0);
        if (ret <= 0)
        {
            cerr << "Error sending iv for nonce decryption to client\n";
            close(clientfd);
            return 0;
        }

        return 1;
    }

    int uploadFile()
    {
        cout << "upload\n";
        return 1;
    }

    int downloadFile()
    {
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
        decryptedSize = decryptSym(encryptedFilename, encryptedSize, buggedFilename, iv, tempKey);
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
        exists = existsFile(filename, clientUsername, decryptedSize);
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
        string sfilename(filename, filename + decryptedSize);
        string soldPath = "./users_infos/" + clientUsername + "/files/" + sfilename;
        filesystem::path oldPath(soldPath);
        remove(oldPath, ec);

        if (existsFile(filename, clientUsername, decryptedSize))
        {
            cout << "File not Deleted\n";
        };

        // Free Buffers
        free(iv);
        free(filename);
        free(encryptedFilename);

        return 1;
    }

    int listFiles()
    {
        // Declare a pointer to the Dir type and structure
        int ret;
        DIR *directry;
        struct dirent *en;

        // Open the Client's directry
        string userpath = "./users_infos/" + clientUsername + "/files/";
        directry = opendir(userpath.c_str());

        // Loop through the directry and read out the files
        if (directry)
        {
            while ((en = readdir(directry)) != NULL)
            {
                /* Print all the files */
                // cout << "\n" << en->d_name;

                // Encrypt filename using symmetric key
                int encryptedSize;
                unsigned char *encryptedFilename = (unsigned char *)malloc(sizeof(en) + blockSize);
                unsigned char *iv = (unsigned char *)malloc(ivSize);

                // // Check for the encrypted buffers
                if (!encryptedFilename || !iv)
                {
                    cerr << "Error allocating buffers for encryption\n";
                    return 0;
                }

                ret = encryptSym((unsigned char *)en, sizeof(en), encryptedFilename, iv, tempKey);
                if (!ret)
                {
                    cout << ">> Error during encryption\n";
                    return 0;
                }
                encryptedSize = ret;

                // // Send the encrypted filename
                ret = send(clientfd, encryptedFilename, encryptedSize, 0);
                if (ret <= 0)
                {
                    cerr << "Error sending filenames to client\n";
                    return 0;
                }
            }
        }
        // Close the directry
        closedir(directry);
        return 0;
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
        decryptedSize = decryptSym(encryptedFilename, encryptedSize, buggedFilename, iv, tempKey);
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
        exists = existsFile(filename, clientUsername, decryptedSize);
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
        decryptedNewSize = decryptSym(encryptedNewFilename, encryptedNewSize, newFilename, ivNew, tempKey);
        if (!decryptedNewSize)
        {
            cout << "Error decrypting new filename\n";
            return 0;
        }

        // Rename file
        string sfilename(filename, filename + decryptedSize);
        string snewFilename(newFilename, newFilename + decryptedNewSize);
        string soldPath = "./users_infos/" + clientUsername + "/files/" + sfilename;
        string snewPath = "./users_infos/" + clientUsername + "/files/" + snewFilename;
        filesystem::path oldPath(soldPath);
        filesystem::path newPath(snewPath);
        cout << "old path : " << oldPath << endl;
        cout << "new path : " << newPath << endl;
        cout << "current path : " << filesystem::current_path() << endl;
        rename(oldPath, newPath);

        if (!existsFile(newFilename, clientUsername, decryptedNewSize))
        {
            cout << "didnt worked\n";
        };

        // Free eveything
        free(iv);
        free(filename);
        free(encryptedFilename);
        free(ivNew);
        free(newFilename);
        free(encryptedNewFilename);

        return 1;
    }

    int logout()
    {

        // Free key
        // free(sessionKey);

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

    int test()
    {

        // Test the send and receive functions

        int ret;

        // First create nonce
        ret = createNonce();
        if (!ret)
        {
            cerr << "Error creating nonce\n";
            close(clientfd);
            return 0;
        }

        // Encrypt nonce using symmetric key
        int encryptedSize;
        unsigned char *encryptedNonce = (unsigned char *)malloc(nonceSize + blockSize);
        unsigned char *ivNew = (unsigned char *)malloc(ivSize);
        if (!encryptedNonce || !ivNew)
        {
            cerr << "Error allocating buffers for encryptedNonce and ivNew\n";
            close(clientfd);
            return 0;
        }

        ret = encryptSym(nonce, nonceSize, encryptedNonce, ivNew, sessionKey);
        if (!ret)
        {
            cerr << "Error encrypting the nonce\n";
            close(clientfd);
            return 0;
        }
        encryptedSize = ret;

        // TEST
        cout << "nonce :\n";
        BIO_dump_fp(stdout, (const char *)nonce, nonceSize);

        // Decrypt
        unsigned char *decryptedNonce = (unsigned char *)malloc(encryptedSize);
        if (!decryptedNonce)
        {
            cerr << "Error allocating buffer for decrypted nonce\n";
            return 0;
        }
        ret = decryptSym(encryptedNonce, encryptedSize, decryptedNonce, ivNew, sessionKey);
        if (!ret)
        {
            cerr << "Error decrypting the nonce\n";
            return 0;
        }

        // TEST
        cout << "decryptedNonce :\n";
        BIO_dump_fp(stdout, (const char *)decryptedNonce, nonceSize);

        return 1;
    }

    int test2()
    {

        int ret;

        // Retreive user's pubkey to encrypt session key
        string path = "users_infos/" + clientUsername + "/pubkey.pem";
        FILE *keyFile = fopen(path.c_str(), "r");
        if (!keyFile)
        {
            cerr << "Error could not open client " << clientUsername << " public key file\n";
            close(clientfd);
            return 0;
        }
        clientPubKey = PEM_read_PUBKEY(keyFile, NULL, NULL, NULL);
        fclose(keyFile);
        if (!clientPubKey)
        {
            cerr << "Error could not read client " << clientUsername << " public key from pem file\n";
            close(clientfd);
            return 0;
        }

        // Encrypt session key using client public key

        // Variables for encryption
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();
        int encryptedKeySize = EVP_PKEY_size(clientPubKey);
        int ivLength = EVP_CIPHER_iv_length(cipher);
        int blockSizeEnvelope = EVP_CIPHER_block_size(cipher);
        int cipherSize = sessionKeySize + blockSizeEnvelope;
        int encryptedSize = 0;

        // Create buffers for encrypted session key, iv, encrypted key
        unsigned char *iv = (unsigned char *)malloc(ivLength);
        unsigned char *encryptedKey = (unsigned char *)malloc(encryptedKeySize);
        unsigned char *encryptedSecret = (unsigned char *)malloc(cipherSize);
        if (!iv || !encryptedKey || !encryptedSecret)
        {
            cout << "Error allocating buffers during nonce encryption\n";
            close(clientfd);
            return 0;
        }

        // Digital envelope
        int bytesWritten = 0;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            cerr << "Error creating context for nonce encryption\n";
            close(clientfd);
            return 0;
        }
        ret = EVP_SealInit(ctx, cipher, &encryptedKey, &encryptedKeySize, iv, &clientPubKey, 1);
        if (ret <= 0)
        {
            cerr << "Error during initialization of encrypted nonce envelope\n";
            close(clientfd);
            return 0;
        }
        ret = EVP_SealUpdate(ctx, encryptedSecret, &bytesWritten, sessionKey, sessionKeySize);
        if (ret <= 0)
        {
            cerr << "Error during update of encrypted nonce envelope\n";
            close(clientfd);
            return 0;
        }
        encryptedSize += bytesWritten;
        ret = EVP_SealFinal(ctx, encryptedSecret + encryptedSize, &bytesWritten);
        if (ret <= 0)
        {
            cerr << "Error during finalization of encrypted nonce envelope\n";
            close(clientfd);
            return 0;
        }
        EVP_CIPHER_CTX_free(ctx);

        // TEST
        cout << "sessionKey :\n";
        BIO_dump_fp(stdout, (const char *)sessionKey, sessionKeySize);

        // Envelope decryption

        // Retreive user's prvkey
        string pathd = "../user/user_infos/key.pem";
        FILE *keyFileD = fopen(pathd.c_str(), "r");
        if (!keyFileD)
        {
            cerr << "Error could not open client private key file\n";
            exit(1);
        }
        const char *password = "password";
        EVP_PKEY *clientPrvKey = PEM_read_PrivateKey(keyFileD, NULL, NULL, (void *)password);
        fclose(keyFileD);
        if (!clientPrvKey)
        {
            cerr << "Error cannot read client private key from pem file\n";
            exit(1);
        }

        // Decrypt the challenge envelope

        // Useful variables
        int decryptedSize;

        // Create buffer for session key
        unsigned char *sessionKeyDecrypted = (unsigned char *)malloc(encryptedSize);
        if (!sessionKeyDecrypted)
        {
            cerr << "Error allocating buffer for session key\n";
            exit(1);
        }

        // Digital envelope
        bytesWritten = 0;
        EVP_CIPHER_CTX *ctxD = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            cerr << "Error creating context for envelope decryption\n";
            exit(1);
        }
        ret = EVP_OpenInit(ctxD, cipher, encryptedKey, encryptedKeySize, iv, clientPrvKey);
        if (ret <= 0)
        {
            cerr << "Error during initialization for envelope decryption\n";
            exit(1);
        }
        ret = EVP_OpenUpdate(ctxD, sessionKeyDecrypted, &bytesWritten, encryptedSecret, encryptedSize);
        if (ret <= 0)
        {
            cerr << "Error during update for envelope decryption\n";
            exit(1);
        }
        decryptedSize = bytesWritten;
        ret = EVP_OpenFinal(ctx, sessionKeyDecrypted + decryptedSize, &bytesWritten);
        if (ret <= 0)
        {
            cerr << "Error during finalization for envelope decryption\n";
        }
        decryptedSize += bytesWritten;
        EVP_CIPHER_CTX_free(ctxD);
        free(encryptedKey);
        free(iv);
        free(encryptedSecret);

        // TEST
        cout << "session key decrypted :\n";
        BIO_dump_fp(stdout, (const char *)sessionKeyDecrypted, sessionKeySize);

        // First create nonce
        ret = createNonce();
        if (!ret)
        {
            cerr << "Error creating nonce\n";
            close(clientfd);
            return 0;
        }

        // Encrypt nonce using symmetric key
        int encryptedSizeN;
        unsigned char *encryptedNonce = (unsigned char *)malloc(nonceSize + blockSize);
        unsigned char *ivN = (unsigned char *)malloc(ivSize);
        if (!encryptedNonce || !ivN)
        {
            cerr << "Error allocating buffers for encryptedNonce and iv\n";
            close(clientfd);
            return 0;
        }

        ret = encryptSym(nonce, nonceSize, encryptedNonce, ivN, sessionKey);
        if (!ret)
        {
            cerr << "Error encrypting the nonce\n";
            close(clientfd);
            return 0;
        }
        encryptedSizeN = ret;

        // TEST
        cout << "nonce :\n";
        BIO_dump_fp(stdout, (const char *)nonce, nonceSize);

        // Decrypt
        unsigned char *decryptedNonce = (unsigned char *)malloc(encryptedSizeN);
        if (!decryptedNonce)
        {
            cerr << "Error allocating buffer for decrypted nonce\n";
            return 0;
        }
        ret = decryptSym(encryptedNonce, encryptedSizeN, decryptedNonce, ivN, sessionKeyDecrypted);
        if (!ret)
        {
            cerr << "Error decrypting the nonce\n";
            return 0;
        }

        // TEST
        cout << "decryptedNonce :\n";
        BIO_dump_fp(stdout, (const char *)decryptedNonce, nonceSize);

        return 1;
    }
};

int main()
{

    int ret;

    Server serv;
    serv.updateDHMap();
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
        cout << "Client " << serv.getClientUsername() << " connected\n";

        ret = serv.generateSessionKey();
        if (!ret)
        {
            cerr << "Error generating session key, communication stopped\n\n";
            continue;
        }
        cout << "Session symmetric key generated\n";

        // cout << "\nTEST\n";
        // serv.test2();
        // cout << "TEST END\n\n";

        ret = serv.shareKey();
        if (!ret)
        {
            cerr << "Error sharing key to the client, communication stopped\n\n";
            continue;
        }
        cout << "Session symmetric key sent to client\n";

        ret = serv.sendEncryptedNonce();
        if (!ret)
        {
            cerr << "Error sending encrypted nonce to the client, communication stopped\n\n";
            continue;
        }
        cout << "Encrypted nonce sent, waiting for client's proof of identity\n";

        while (serv.getConnexionStatus())
        {

            cout << "\nWaiting for user input\n";
            serv.getCommand();
        }
    }

    return 0;
}