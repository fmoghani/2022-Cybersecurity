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
#include "user_infos/DH.h"
#include "../utils.h"
#include "../const.h"

using namespace std;

#define PORT 1805

class Client
{

    // Sockets
    int socketfd, clientfd;
    struct sockaddr_in serverAddr;

    // Connexion status
    int CONNEXION_STATUS = 0;

    // Client variables
    unsigned char *nonce;
    unsigned char *clientResponse;
    string username;

    // Keys
    unsigned char *sessionKey;
    unsigned char *tempKey;

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

        CONNEXION_STATUS = 1;

        // Temporary key
        tempKey = (unsigned char *)"01234567890123450123456789012345";
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
        int encryptedKeySize = (*sizeKey); // Divided by 8 because encrypted key size is sent in bits
        free(sizeKey);
        unsigned char *encryptedKey = (unsigned char *)malloc(encryptedKeySize);
        if (!encryptedKey)
        {
            cerr << "Error allocating buffer for encrypted key\n";
        }
        ret = read(socketfd, encryptedKey, encryptedKeySize);
        if (ret <= 0)
        {
            cerr << "Error reading encrypted key\n";
            exit(1);
        }

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
        unsigned char *encryptedSecret = (unsigned char *)malloc(encryptedSize);
        if (!encryptedSecret)
        {
            cerr << "Error allocating buffer for encrypted session key\n";
            exit(1);
        }
        ret = read(socketfd, encryptedSecret, encryptedSize);
        if (ret <= 0)
        {
            cerr << "Error reading encrypted session key\n";
            exit(1);
        }

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
        unsigned char *iv = (unsigned char *)malloc(ivLength);
        if (!iv)
        {
            cerr << "Error allocating buffer for iv\n";
            exit(1);
        }
        ret = read(socketfd, iv, ivLength);
        if (ret <= 0)
        {
            cerr << "Error reading iv\n";
            exit(1);
        }

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

        // Create buffer for session key
        unsigned char *sessionKey = (unsigned char *)malloc(sessionKeySize);
        if (!sessionKey)
        {
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
        }
        decryptedSize += bytesWritten;

        // TEST
        cout << "\nENVELOPE TEST\n";
        cout << "encryptedSize = " << encryptedSize << "encrypted secret :\n";
        BIO_dump_fp(stdout, (const char *)encryptedSecret, encryptedSize);
        cout << "theoric encrypted size = " << EVP_PKEY_size(clientPrvKey) << "\n";
        cout << "encryptedKeySize = " << encryptedKeySize << "encrypted key :\n";
        BIO_dump_fp(stdout, (const char *)encryptedKey, encryptedKeySize);
        cout << "session key :\n";
        BIO_dump_fp(stdout, (const char *)sessionKey, sessionKeySize);
        cout << "ENVELOPE TEST END\n\n";

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

        // TEST
        cout << "\nTEST NONCE\n";
        cout << "encryptedNonceSize = " << encryptedSize << " encryptedNonce :\n";
        BIO_dump_fp(stdout, (const char *)encryptedNonce, encryptedSize);
        cout << "iv Size = " << ivSize << " iv :\n";
        BIO_dump_fp(stdout, (const char *)iv, ivSize);
        cout << "TEST NONCE END\n\n";

        // Decrypt nonce using the shared session key
        unsigned char *nonce = (unsigned char *)malloc(encryptedSize);
        if (!nonce)
        {
            cerr << "Error allocating buffer for decrypted nonce\n";
            exit(1);
        }
        ret = decryptSym(encryptedNonce, encryptedSize, nonce, iv, tempKey);
        if (!ret)
        {
            cerr << "Error decrypting the nonce\n";
            exit(1);
        }

        // TEST
        cout << "nonce :\n";
        BIO_dump_fp(stdout, (const char *)nonce, nonceSize);

        // Send nonce to the server
        // ret = send(socketfd, nonce, nonceSize, 0);
        // if (ret <= 0) {
        //     cerr << "Error sending nonce to the server\n";
        //     exit(1);
        // }
    }

    int uploadFile()
    {
        cout << ">> upload\n";
        return 1;
    }

    int downloadFile()
    {
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
        ret = encryptSym((unsigned char *)fileName.c_str(), fileName.size(), encryptedFileName, iv, tempKey);
        if (!ret)
        {
            cout << ">> Error during decryption\n";
            return 0;
        }
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

        // Receive encrypted filename
        int *size = (int *)malloc(sizeof(int));
        if (!size)
        {
            cerr << "Error allocating buffer for encrypted filename\n";
            exit(1);
        }
        ret = readInt(socketfd, size);
        if (!ret)
        {
            cerr << "Error reading encrypted filesize\n";
            exit(1);
        }
        int encryptedSize = *size;
        free(size);
        cout << "Encrypted Size: " << encryptedSize; // Debug purposes
        unsigned char *encryptedSecret = (unsigned char *)malloc(encryptedSize);
        if (!encryptedSecret)
        {
            cerr << "Error allocating buffer for encrypted filesize key\n";
            exit(1);
        }
        ret = read(socketfd, encryptedSecret, encryptedSize);
        if (ret <= 0)
        {
            cerr << "Error reading encrypted filename key\n";
            exit(1);
        }
        cout << ret;

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
        ret = encryptSym((unsigned char *)filename.c_str(), filename.size(), encryptedFilename, iv, tempKey);
        if (!ret)
        {
            cout << ">> Error during encryption\n";
            return 0;
        }
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
        ret = encryptSym((unsigned char *)newFilename.c_str(), newFilename.size(), encryptedNewFilename, ivNew, tempKey);
        if (!ret)
        {
            cout << ">> Error during encryption\n";
            return 0;
        }
        encryptedSizeNew = ret;

        // Send the encrypted filename
        ret = sendEncrypted(encryptedNewFilename, encryptedSizeNew, ivNew);
        if (!ret)
        {
            cout << ">> Error sending encrypted new filename\n";
            return 0;
        }

        cout << ">> File was renamed successfully\n";

        return 1;
    }

    int logout()
    {

        // Free key
        // free(sessionKey);

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

    void test()
    {

        // Test the send and receive functions
    }
};

int main()
{

    int ret;
    Client user1;

    cout << "Starting client...\n";
    user1.connectClient();
    cout << "Client successfuly connected to the server\n";

    user1.authenticateServer();
    cout << "Server authenticated, waiting for server's envelope...\n";

    user1.retreiveSessionKey();
    cout << "Session key received\n";

    user1.proveIdentity();
    cout << "Proof of identity sent\n";

    user1.updateCommands();

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