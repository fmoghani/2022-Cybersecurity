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
    cout << ret << "\n";
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
    // char * lenghtChar = (char *) &length;
    // int left = sizeof(length);
    // // This block ensure message is transmitted even if send does not transfer all the bytes on the first time
    // do {
    //     ret = send(socketfd, lenghtChar, left, 0);
    //     if (ret < 0) {
    //         cerr << "Error sending message length\n";
    //         return 0;
    //     } else {
    //         lenghtChar += ret;
    //         left -= ret;
    //     }
    // } while (left > 0);
    ret = send(socketfd, (char *) &length, sizeof(length), 0);
    if (ret < 0) {
        cerr << "Error sending message size\n";
        return 0;
    }

    // Then send the message
    // left = length;
    // do {
    //     ret = send(socketfd, buff, length, 0);
    //     if (ret < 0) {
    //         cerr << "Error sending message\n";
    //         return 0;
    //     } else {
    //         buff += ret;
    //         left -= ret;
    //     }
    // } while (left > 0);
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

    // Receive the size of the message
    // int length;
    // char * lengthChar = (char *) &length;
    // int left = sizeof(length);
    // // Block to ensure length is receive even if it is in multiple times
    // do {
    //     ret = read(socketfd, lengthChar, left);
    //     if (ret < 0) {
    //         cerr << "Error reading message size";
    //         return 0;
    //     } else {
    //         lengthChar += ret;
    //         left -= ret;
    //     }
    // } while (left > 0);
    int length;
    ret = read(socketfd, (char *) &length, sizeof(length));
    if (ret < 0) {
        cerr << "Error reading message size\n";
    }

    // Receive the actual message
    unsigned char * buffer = (unsigned char *) malloc(length);
    // left = length;
    // do {
    //     ret = read(socketfd, buffer, length);
    //     if (ret < 0) {
    //         cerr << "Error reading message\n";
    //         return 0;
    //     } else {
    //         buffer += ret;
    //         left -= ret;
    //     }
    // } while (left > 0);
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

unsigned char * encryptSym(unsigned char * plaintext, int plainSize, unsigned char * key, int * cipherSize) {

    int ret;

    const EVP_CIPHER * cipher = EVP_aes_256_cbc();
    int blockSize = EVP_CIPHER_block_size(cipher);
    int encryptedSize = plainSize + blockSize;
    unsigned char * ciphertext = (unsigned char *) malloc(encryptedSize);
    if (!ciphertext) {
        cerr << "Error allocating buffer for cipher text symmetric encryption\n";
    }

    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "Error creating context for symmetric encryption\n";
    }

    ret = EVP_EncryptInit(ctx, cipher, key, NULL);
    if (ret != 1) {
        cerr << "Error during symmetric encryption initialization\n";
    }  

    int updateLength = 0;
    int totalLength = 0;
    ret = EVP_EncryptUpdate(ctx, ciphertext, &updateLength, plaintext, plainSize);
    if (ret != 1) {
        cerr << "Error during symmetric encryption update\n";
    }
    totalLength += updateLength;

    ret = EVP_EncryptFinal(ctx, ciphertext+totalLength, &updateLength);
    if (ret != 1) {
        cerr << "Error during symmetric encryption finalization\n";
    }
    totalLength += updateLength;
    EVP_CIPHER_CTX_free(ctx);

    *cipherSize = totalLength;
    return ciphertext;

}

unsigned char * decryptSym(unsigned char * ciphertext, int cipherSize, unsigned char * key) {

    int ret;

    const EVP_CIPHER * cipher = EVP_aes_256_ecb();
    unsigned char * plaintext = (unsigned char *) malloc(cipherSize);
    if (!plaintext) {
        cerr << "Error allocating buffer for ciphertext during simmetric decryption\n";
    }

    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "Error creating context for symmetric decryption\n";
    }

    ret = EVP_DecryptInit(ctx, cipher, key, NULL);
    if (ret != 1) {
        cerr << "Error during symmetric decryption initialization\n";
    }

    int updateLength = 0;
    int totalLength = 0;
    ret = EVP_DecryptUpdate(ctx, plaintext, &updateLength, ciphertext, cipherSize);
    if (ret != 1) {
        cerr << "Error during symmetric decryption update\n";
    }
    totalLength += updateLength;
    cout << totalLength << "\n";

    ret = EVP_DecryptFinal(ctx, plaintext+totalLength, &updateLength);
    if (ret != 1) {
        cerr << "Error during symmetric decryption finalization\n";
    }
    totalLength += updateLength;
    cout << cipherSize << "\n";
    EVP_CIPHER_CTX_free(ctx);

    return plaintext;

}