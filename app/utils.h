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
#include <cerrno>

using namespace std;

// Function returning the X509 certificate specified by path
int readCertificate(string path, X509 * CAcert)
{

    FILE *certFile = fopen(path.c_str(), "r");
    if (!certFile)
    {
        cerr << "Error : cannot open " << path << " certificate\n";
        return 0;
    }
    CAcert = PEM_read_X509(certFile, NULL, NULL, NULL);
    fclose(certFile);
    if (!CAcert)
    {
        cerr << "Error : cannot read " << path << " certificate\n";
        return 0;
    }

    return 1;
}

X509_CRL *readCrl(string path) {

    FILE *CACrlFile = fopen(path.c_str(), "r");
    if (!CACrlFile)
    {
        cerr << "Error cannot open " << path << " crl\n";
    }
    X509_CRL *CACrl = PEM_read_X509_CRL(CACrlFile, NULL, NULL, NULL);
    fclose(CACrlFile);
    if (!CACrl)
    {
        cerr << "Error cannot read " << path << " crl\n";
    }

    return CACrl;
}

// Need to free the unsigned char * after using this fction
unsigned char * prvKeyToChar(EVP_PKEY * key) {

    int ret;

    int prvKeyLength = i2d_PrivateKey(key, NULL);
    unsigned char * buffer = (unsigned char *) malloc(prvKeyLength);
    if (!buffer) {
        cerr << "Error allocating buffer for the private key\n";
    }
    ret = i2d_PrivateKey(key, &buffer);
    if (!ret) {
        cerr << "Error writing key inside the buffer\n";
    }

    return buffer;
}

// Need to free the unsigned char * after using this fction
unsigned char * pubKeyToChar(EVP_PKEY * key) {

    int ret;

    // int keyLength = EVP_PKEY_size(key);

    // BIO * bio = BIO_new(BIO_s_mem());
    // if (!bio) {
    //     cerr << "Error allocating bio for public key conversion\n";
    // }
    
    // ret = PEM_write_bio_PUBKEY(bio, key);
    // if (!ret) {
    //     cerr << "Error writing public key in bio\n";
    // }

    // BIO_flush(bio);
    // unsigned char * charKey = (unsigned char *) malloc(keyLength);
    // BIO_get_mem_data(bio, charKey);

    // return charKey;

    int pubKeyLength = EVP_PKEY_size(key);
    unsigned char * buffer = (unsigned char *) malloc(pubKeyLength);
    if (!buffer) {
        cerr << "Error allocating buffer for the public key\n";
    }
    ret = i2d_PublicKey(key, &buffer);
    if (ret < 0) {
        cerr << "Error writing key inside the buffer\n";
    }

    return buffer;
}

// Convert an unsigned char back to a EVP_PKEY *
EVP_PKEY * charToPubkey(unsigned char * buffer) {

    int bufferLength = sizeof(buffer);
    EVP_PKEY * pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, (const unsigned char **) &buffer, bufferLength);
    if (!pkey) {
        cerr << "Error converting unsigned char into EVP_PKEY *";
        return 0;
    }

    return pkey;
}

// Send a character through a socket without encryption (only works with the receive function below)
int sendChar(int socketfd, unsigned char * buff) {

    int ret;

    // First send the size of the message
    int length = strlen((char *) buff);
    ret = send(socketfd, (char *) &length, sizeof(length), 0);
    if (ret < 0) {
        cerr << "Error sending message size\n";
        return 0;
    }

    // Then send the message
    ret = send(socketfd, buff, length, 0);
    if (ret < 0) {
        cerr << "Error sending message\n";
        return 0;
    }

    return 1;
}

// Receive a character through a socket without encryption
unsigned char * readChar(int socketfd) {

    int ret;

    int length;
    ret = read(socketfd, (char *) &length, sizeof(length));
    if (ret < 0) {
        cerr << "Error reading message size\n";
    }

    // Receive the actual message
    unsigned char * buffer = (unsigned char *) malloc(length);
    ret = read(socketfd, buffer, length);
    if (ret < 0) {
        cerr << "Error reading message\n";
    }

    return buffer;
}

int sendInt(int socketfd, int n) {

    int ret;
    ret = send(socketfd, (char *) &n, sizeof(n), 0);
    if (ret < 0) {
        cerr << "Error sending int\n";
        return 0;
    }

    return 1;
}

int readInt(int socketfd) {

    int ret;
    int n = 0;
    ret = read(socketfd, (char *) &n, sizeof(int));
    if (ret < 0) {
        cerr << "Error reading int\n";
    }

    return n;
}

unsigned char * createHash(unsigned char * inBuffer, size_t bufferLen) {

    int ret;

    // Create params for the digest
    unsigned int digestLen;
    unsigned char * digest = (unsigned char *) malloc(EVP_MD_size(EVP_sha256()));

    // Init context
    EVP_MD_CTX * ctx = EVP_MD_CTX_new();
    if (!ctx) {
        cerr << "Error creating context for digest\n";
    }

    // Init, update and finalize digest
    ret = EVP_DigestInit(ctx, EVP_sha256());
    if (ret <= 0) {
        cerr << "Error initializing digest\n";
    }
    ret = EVP_DigestUpdate(ctx, inBuffer, bufferLen);
    if (ret <= 0) {
        cerr << "Error updating digest\n";
    }
    ret = EVP_DigestFinal(ctx, digest, &digestLen);
    if (ret <= 0) {
        cerr << "Error finalizing digest\n";
    }

    // Free everything
    EVP_MD_CTX_free(ctx);

    return digest;
}