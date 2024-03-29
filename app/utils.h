#include <iostream>
#include <string>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <experimental/filesystem>
// #include <filesystem>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cerrno>
#include "const.h"

using namespace std;
using namespace std::experimental;
using std::experimental::filesystem::directory_iterator;



// Function returning the X509 certificate specified by path
X509 * readCertificate(string path) {

    FILE *certFile = fopen(path.c_str(), "r");
    if (!certFile) {
        cerr << "Error : cannot open " << path << " certificate\n";
    }
    X509 * cert = PEM_read_X509(certFile, NULL, NULL, NULL);
    fclose(certFile);
    if (!cert) {
        cerr << "Error : cannot read " << path << " certificate\n";
    }

    return cert;
}

X509_CRL * readCrl(string path) {

    FILE * crlFile = fopen(path.c_str(), "r");
    if (!crlFile)
    {
        cerr << "Error cannot open " << path << " crl\n";
    }
    X509_CRL * crl = PEM_read_X509_CRL(crlFile, NULL, NULL, NULL);
    fclose(crlFile);
    if (!crl)
    {
        cerr << "Error cannot read " << path << " crl\n";
    }

    return crl;
}

int sendInt(int socketfd, unsigned int n) {

    int ret;
    
    ret = send(socketfd, (char *) &n, sizeof(n), 0);
    if (ret < 0) {
        cerr << "Error sending int\n";
        return 0;
    }

    return 1;
}

int sendLongInt(int socketfd, uint32_t n) {

    int ret;
    
    ret = send(socketfd, (char *) &n, sizeof(uint32_t), 0);
    if (ret < 0) {
        cerr << "Error sending int\n";
        return 0;
    }

    return 1;
}

int readInt(int socketfd, unsigned int * n) {

    int ret;

    ret = read(socketfd, (char *) n, sizeof(unsigned int));
    if (ret < 0) {
        cerr << "Error reading int\n";
        return 0;
    }

    return 1;
}

long int readLongInt(int socketfd, uint32_t * n) {

    long int ret;

    ret = read(socketfd, (char *) n, sizeof(uint32_t));
    if (ret < 0) {
        cerr << "Error reading int\n";
        return 0;
    }

    return 1;
}

int createHash256(unsigned char * inBuffer, size_t inBufferLen, unsigned char * digest) {

    int ret;

    // Create params for the digest
    unsigned int digestLen;

    // Init context
    EVP_MD_CTX * ctx = EVP_MD_CTX_new();
    if (!ctx) {
        cerr << "Error creating context for digest\n";
        return 0;
    }

    // Init, update and finalize digest
    ret = EVP_DigestInit(ctx, EVP_sha256());
    if (ret <= 0) {
        cerr << "Error initializing digest\n";
        return 0;
    }
    ret = EVP_DigestUpdate(ctx, inBuffer, inBufferLen);
    if (ret <= 0) {
        cerr << "Error updating digest\n";
        return 0;
    }
    ret = EVP_DigestFinal(ctx, digest, &digestLen);
    if (ret <= 0) {
        cerr << "Error finalizing digest\n";
        return 0;
    }

    // Free everything
    EVP_MD_CTX_free(ctx);

    return digestLen;
}

int createHash512(unsigned char * inBuffer, size_t inBufferLen, unsigned char * digest) {

    int ret;

    // Create params for the digest
    unsigned int digestLen;

    // Init context
    EVP_MD_CTX * ctx = EVP_MD_CTX_new();
    if (!ctx) {
        cerr << "Error creating context for digest\n";
        return 0;
    }

    // Init, update and finalize digest
    ret = EVP_DigestInit(ctx, EVP_sha512());
    if (ret <= 0) {
        cerr << "Error initializing digest\n";
        return 0;
    }
    ret = EVP_DigestUpdate(ctx, inBuffer, inBufferLen);
    if (ret <= 0) {
        cerr << "Error updating digest\n";
        return 0;
    }
    ret = EVP_DigestFinal(ctx, digest, &digestLen);
    if (ret <= 0) {
        cerr << "Error finalizing digest\n";
        return 0;
    }

    // Free everything
    EVP_MD_CTX_free(ctx);

    return digestLen;
}

// Function to encrypt a message unsing symmetric encyption (aes cbc 256)
int encryptSym(unsigned char * plaintext, int plainSize, unsigned char * ciphertext, unsigned char * iv, unsigned char * privKey) {

    int ret;

    // Encryption params
    const EVP_CIPHER * cipher = EVP_aes_256_cbc();
    int ivLen = EVP_CIPHER_iv_length(cipher);

    // Create iv
    RAND_poll();
    ret = RAND_bytes(iv, ivLen);
    if (!ret) {
        cerr << "Error randomizing iv for symmetric encrytpion\n";
        return 0;
    }

    // Create context
    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "Error creating context for symmetric encryption\n";
        return 0;
    }
    int bytesWritten;
    int encryptedSize;

    // Encrypt plaintext
    ret = EVP_EncryptInit(ctx, cipher, privKey, iv);
    if (ret <= 0) {
        cerr << "Error during initialization for symmetric encryption\n";
        return 0;
    }
    ret = EVP_EncryptUpdate(ctx, ciphertext, &bytesWritten, plaintext, plainSize);
    encryptedSize = bytesWritten;
    if (ret <= 0) {
        cerr << "Error during update for symmetric encryption\n";
        return 0;
    }
    ret = EVP_EncryptFinal(ctx, ciphertext + encryptedSize, &bytesWritten);
    encryptedSize += bytesWritten;
    if (ret == 0) {
        cerr << "Error during finalization for symmetric encryption\n";
        return 0;
    }
    EVP_CIPHER_CTX_free(ctx);

    return encryptedSize;
}

int decryptSym(unsigned char * ciphertext, int cipherSize, unsigned char * plaintext, unsigned char * iv, unsigned char * privKey) {
    
    int ret;

    // Decryption params
    const EVP_CIPHER * cipher = EVP_aes_256_cbc();

    // Create context
    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "Error creating context for symmetric decryption\n";
        return 0;
    }
    int bytesWritten;
    int decryptedSize;

    // Decrypt
    ret = EVP_DecryptInit(ctx, cipher, privKey, iv);
    if (ret <= 0) {
        cerr << "Error during initialization for symmetric decryption\n";
        return 0;
    }
    ret = EVP_DecryptUpdate(ctx, plaintext, &bytesWritten, ciphertext, cipherSize);
    if (ret <= 0) {
        cerr << "Error during update for symmetric decryption\n";
        return 0;
    }
    decryptedSize = bytesWritten;
    ret = EVP_DecryptFinal(ctx, plaintext + decryptedSize, &bytesWritten);
    if (ret <= 0) {
        cerr << "Error during finalization for symmetric decryption\n";
        ERR_print_errors_fp(stderr);
        return 0;
    }
    decryptedSize += bytesWritten;
    EVP_CIPHER_CTX_free(ctx);

    return decryptedSize;
}

// This function checks if a filename contains any banned symbol
int checkFilename(string filename) {

    if (filename.find("/") != string::npos) {
        return 0;
    }
     
    return 1;
}

// This function checks that a given file exists in the user filesystem (has to be called from server side)
int existsFile(string filename, string username) {

    string spath = "./users_infos/" + username + "/files/" + filename;

    FILE * file = fopen(spath.c_str(), "rb");
    if (!file) {
        return 0;
    }

    return 1;
}

// Generate a random and fresh nonce
int createNonce(unsigned char * buffer)
    {

        int ret;

        // Generate a 16 bytes random number to ensure unpredictability
        unsigned char *randomBuf = (unsigned char *)malloc(randBytesSize);
        if (!randomBuf)
        {
            cerr << "Error allocating unsigned buffer for random bytes\n";
            return 0;
        }
        RAND_poll();
        ret = RAND_bytes(randomBuf, randBytesSize);
        if (!ret)
        {
            cerr << "Error generating random bytes\n";
            return 0;
        }
        char *random = (char *)malloc(randBytesSize);
        if (!random)
        {
            cerr << "Error allocating buffer for random bytes *\n";
            return 0;
        }
        memcpy(random, randomBuf, randBytesSize);
        free(randomBuf);

        // Generate a char timestamp to ensure uniqueness
        char *now = (char *)malloc(timeBufferSize);
        if (!now)
        {
            cerr << "Error allocating buffer for date and time\n";
            return 0;
        }
        time_t currTime;
        tm *currentTime;
        time(&currTime);
        currentTime = localtime(&currTime);
        if (!currentTime)
        {
            cerr << "Error creating pointer containing current time\n";
            return 0;
        }
        ret = strftime(now, timeBufferSize, "%Y%j%H%M%S", currentTime);
        if (!ret)
        {
            cerr << "Error putting time in a char array\n";
            return 0;
        }

        // Concatenate random number and timestamp
        char *tempNonce = (char *)malloc(randBytesSize + timeBufferSize);
        if (!tempNonce)
        {
            cerr << "Error allocating char buffer for nonce\n";
            return 0;
        }
        bzero(tempNonce, randBytesSize + timeBufferSize);
        memcpy(tempNonce, random, randBytesSize);
        free(random);
        strcat(tempNonce, now);
        free(now);
        memcpy(buffer, tempNonce, nonceSize);
        free(tempNonce);

        return 1;
    }

// Create the digest of auth key, counter and ciphertext and concatenate the digest with the ciphertext
int hashAndConcat(unsigned char * concat, unsigned char * ciphertext, int encryptedSize, unsigned char * authKey, int counter) {

    int ret;

    string strCounter = to_string(counter);
    int totalSize = sessionKeySize + strCounter.length() + encryptedSize;

    // Create the digest of auth key, counter and ciphertext
    unsigned char * toDigest = (unsigned char *) malloc(totalSize);
    unsigned char * digest = (unsigned char *) malloc(sessionKeySize);
    if (!toDigest || !digest) {
        cerr << "Error allocating buffers for toDigest or digest\n";
        return 0;
    }
    memcpy(toDigest, authKey, sessionKeySize);
    memcpy(toDigest + sessionKeySize, strCounter.data(), strCounter.size());
    memcpy(toDigest + sessionKeySize + strCounter.length(), ciphertext, encryptedSize);
    ret = createHash256(toDigest, totalSize, digest);
    if (!ret) {
        cerr << "Error creating hash of concat\n";
        return 0;
    }

    // Concatenate digest and ciphertext
    memcpy(concat, digest, sessionKeySize);
    memcpy(concat + sessionKeySize, ciphertext, encryptedSize);

    // Free
    free(toDigest);
    free(digest);

    return 1;
}

// Send an encrypted message
int sendEncrypted(int cipherSize, unsigned char *iv, unsigned char * concat, int socketfd) {

    int ret;

    ret = sendInt(socketfd, cipherSize);
    if (!ret)
    {
        return 0;
    }
    ret = send(socketfd, iv, ivSize, 0);
    if (!ret)
    {
        return 0;
    }
    ret = send(socketfd, concat, cipherSize + sessionKeySize, 0);
    if (!ret)
    {
        return 0;
    }

    return 1;
}

// Receive an encrypted message and separate digest from ciphertext
int receiveEncrypted(int cipherSize, unsigned char * iv, unsigned char * concat, unsigned char * ciphertext, unsigned char * digest, int socketfd) {

    int ret;

    // Receive everything
    ret = read(socketfd, iv, ivSize);
    if (!ret) {
        return 0;
    }
    ret = read(socketfd, concat, cipherSize + sessionKeySize);
    if (!ret) {
        return 0;
    }

    // Separate ciphertext and digest
    memcpy(digest, concat, sessionKeySize);
    memcpy(ciphertext, concat + sessionKeySize, cipherSize);

    return 1;
}

// Decrypt the message and check its authenticity
int checkAuthenticity(int cipherSize, unsigned char * ciphertext, unsigned char * digest, unsigned char * authKey, int counter) {

    int ret;

    // Compute the digest
    int totalSize = cipherSize + sessionKeySize;
    unsigned char * concatCheck = (unsigned char *) malloc(totalSize);
    if (!concatCheck) {
        cerr << "Error allocating buffer for concat\n";
        return 0;
    }
    ret = hashAndConcat(concatCheck, ciphertext, cipherSize, authKey, counter);
    if (!ret) {
        cerr << "Error hashing and concatenating\n";
        return 0;
    }

    // Compare digest with actual digest
    ret = memcmp(digest, concatCheck, sessionKeySize);
    if (ret) {
        cerr << "Message not authenticated\n";
        return 0;
    }

    free(concatCheck);
    
    return 1;
}

// Check if the counter wraps around and returns 1 if so
int checkCounter(unsigned int counter) {

    if (counter > UINT_MAX - 1) {
        cout << "Counter too big, wrapping around\n";
        return 1;
    }

    return 0;
}