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

// Need to free the unsigned char * after using this fction
int prvKeyToChar(EVP_PKEY * key, unsigned char * buffer) {

    int ret;

    int prvKeyLength = i2d_PrivateKey(key, NULL);
    free(buffer);
    buffer = (unsigned char *) malloc(prvKeyLength);
    if (!buffer) {
        cerr << "Error allocating buffer for the private key\n";
        return 0;
    }
    ret = i2d_PrivateKey(key, &buffer);
    if (!ret) {
        cerr << "Error writing key inside the buffer\n";
        return 0;
    }

    return 1;
}

// Need to free the unsigned char * after using this fction
int pubKeyToChar(EVP_PKEY * key, unsigned char * buffer) {

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
    buffer = (unsigned char *) malloc(pubKeyLength);
    if (!buffer) {
        cerr << "Error allocating buffer for the public key\n";
        return 0;
    }
    ret = i2d_PublicKey(key, &buffer);
    if (ret < 0) {
        cerr << "Error writing key inside the buffer\n";
        return 0;
    }

    return 1;
}

// Convert an unsigned char back to a EVP_PKEY *
int charToPubkey(unsigned char * buffer, EVP_PKEY * pkey) {

    int bufferLength = sizeof(buffer);
    pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, (const unsigned char **) &buffer, bufferLength);
    if (!pkey) {
        cerr << "Error converting unsigned char into EVP_PKEY *\n";
        return 0;
    }

    return 1;
}

// Convert an unsigned char back to a EVP_PKEY *
int charToPrvkey(unsigned char * buffer, EVP_PKEY * pkey) {

    int bufferLength = sizeof(buffer);
    pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, (const unsigned char **) &buffer, bufferLength);
    if (!pkey) {
        cerr << "Error converting unsigned char into EVP_PKEY *\n";
        return 0;
    }

    return 1;
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
int readChar(int socketfd, unsigned char * buffer) {

    int ret;

    int length;
    ret = read(socketfd, (char *) &length, sizeof(length));
    if (ret < 0) {
        cerr << "Error reading message size\n";
        return 0;
    }

    // Receive the actual message
    free(buffer); // Free the dummy allocation realized before in the main scripts
    buffer = (unsigned char *) malloc(length);
    ret = read(socketfd, buffer, length);
    if (ret < 0) {
        cerr << "Error reading message\n";
        return 0;
    }

    return 1;
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

int readInt(int socketfd, int * n) {

    int ret;

    ret = read(socketfd, (char *) n, sizeof(int));
    if (ret < 0) {
        cerr << "Error reading int\n";
        return 0;
    }

    return 1;
}

int createHash(unsigned char * inBuffer, size_t inBufferLen, unsigned char * digest) {

    int ret;

    // Create params for the digest
    unsigned int digestLen;
    digest = (unsigned char *) malloc(EVP_MD_size(EVP_sha256()));

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