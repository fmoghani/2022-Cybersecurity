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

using namespace std;

// Function returning the X509 certificate specified by path
X509 *readCertificate(string path)
{

    FILE *certFile = fopen(path.c_str(), "r");
    if (!certFile)
    {
        cerr << "Error : cannot open " << path << " certificate\n";
        exit(1);
    }
    X509 *CAcert = PEM_read_X509(certFile, NULL, NULL, NULL);
    fclose(certFile);
    if (!CAcert)
    {
        cerr << "Error : cannot read " << path << " certificate\n";
        exit(1);
    }
}

X509_CRL *readCrl(string path) {

    FILE *CACrlFile = fopen(path.c_str(), "r");
    if (!CACrlFile)
    {
        cerr << "Error cannot open " << path << " crl\n";
        exit(1);
    }
    X509_CRL *CACrl = PEM_read_X509_CRL(CACrlFile, NULL, NULL, NULL);
    fclose(CACrlFile);
    if (!CACrl)
    {
        cerr << "Error cannot read " << path << " crl\n";
        exit(1);
    }
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
}

// Need to free the unsigned char * after using this fction
unsigned char * pubKeyToChar(EVP_PKEY * key) {

    int ret;

    int pubKeyLength = i2d_PublicKey(key, NULL);
    unsigned char * buffer = (unsigned char *) malloc(pubKeyLength);
    if (!buffer) {
        cerr << "Error allocating buffer for the public key\n";
    }
    ret = i2d_PublicKey(key, &buffer);
    if (!ret) {
        cerr << "Error writing key inside the buffer\n";
    }
}

// Convert an unsigned char back to a EVP_PKEY *
EVP_PKEY * charToPubkey(unsigned char * buffer) {

    int ret;

    int bufferLength = sizeof(buffer);
    EVP_PKEY * key = d2i_PublicKey(EVP_PKEY_RSA, NULL, &buffer, bufferLength);
    if (!key) {
        cerr << "Error converting unsigned char into EVP_PKEY *";
    }

    return key;
}

// Send a character through a socket without encryption (only works with the receive function below)
void sendChar(int socketfd, unsigned char * buff) {

    int ret;

    // First send the size of the message
    int length = sizeof(buff);
    ret = send(socketfd, (char *)&length, sizeof(length), 0);
    if (ret < 0) {
        cerr << "Error sending message length\n";
    }

    // Then send the message
    ret = send(socketfd, buff, length, 0);
    if (ret < 0) {
        cerr << "Error sending message\n";
    }
}

// Receive a character through a socket without encryption
unsigned char * readChar(int socketfd) {

    int ret;

    // Receive the size of the message
    int length;
    ret = read(socketfd, (char *)&length, sizeof(length));
    if (ret < 0) {
        cerr << "Error reading message size";
    }

    // Receive the actual message
    unsigned char * buffer = (unsigned char *) malloc(length);
    ret = read(socketfd, buffer, length);
    if (ret < 0) {
        cerr << "Error reading message\n";
    }

    return buffer;
}