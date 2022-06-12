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
X509 *readCertificate(string path)
{

    FILE *certFile = fopen(path.c_str(), "r");
    if (!certFile)
    {
        cerr << "Error : cannot open " << path << " certificate\n";
    }
    X509 *CAcert = PEM_read_X509(certFile, NULL, NULL, NULL);
    fclose(certFile);
    if (!CAcert)
    {
        cerr << "Error : cannot read " << path << " certificate\n";
    }

    return CAcert;
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
int prvKeyToChar(EVP_PKEY * key, unsigned char * buffer) {

    int ret;

    int prvKeyLength = i2d_PrivateKey(key, NULL);
    buffer = (unsigned char *) realloc(buffer, prvKeyLength);
    if (!buffer) {
        cerr << "Error reallocating buffer for the private key\n";
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

    int pubKeyLength = i2d_PublicKey(key, NULL);
    buffer = (unsigned char *) realloc(buffer, pubKeyLength);
    if (!buffer) {
        cerr << "Error reallocating buffer for the public key\n";
        return 0;
    }
    ret = i2d_PublicKey(key, &buffer);
    if (!ret) {
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
        cerr << "Error converting unsigned char into EVP_PKEY *";
        return 0;
    }

    return 1;
}

// Send a character through a socket without encryption (only works with the receive function below)
int sendChar(int socketfd, unsigned char * buff) {

    int ret;

    // First send the size of the message
    int length = strlen((char *) buff);
    ret = send(socketfd, (char *)&length, sizeof(length), 0);
    if (ret < 0) {
        cerr << "Error sending message length\n";
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

    // Receive the size of the message
    int length;
    ret = read(socketfd, (char *)&length, sizeof(length));
    if (ret < 0) {
        cerr << "Error reading message size";
        return 0;
    }

    // Receive the actual message
    buffer = (unsigned char *) realloc(buffer, length);
    ret = read(socketfd, buffer, length);
    if (ret < 0) {
        cerr << "Error reading message\n";
        return 0;
    }

    return 1;
}