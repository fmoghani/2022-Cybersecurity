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

using namespace std;
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
    cout << "size sent : " << length << "\n";

    // Then send the message
    ret = send(socketfd, buff, length, 0);
    if (ret < 0) {
        cerr << "Error sending message\n";
        return 0;
    }
    cout << "size actually sent = " << ret << "\n";

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
    cout << "size received : " << length << "\n";

    // Receive the actual message
    free(buffer); // Free the dummy allocation realized before in the main scripts
    buffer = (unsigned char *) malloc(length);
    ret = read(socketfd, buffer, length);
    if (ret < 0) {
        cerr << "Error reading message\n";
        return 0;
    }
    cout << "bytes read = " << ret << "\n";

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
int existsFile(unsigned char * filename, string username, int filenameSize) {

    string filesPath = "users_infos/" + username + "/files/";

    for (const auto &file : directory_iterator(filesPath)) {
        cout << file.path().string() << "\n";
        std::experimental::filesystem::path currentPath = file.path().filename();
        const char * currentFilename = currentPath.string().c_str();
        if (!memcmp(currentFilename, (const char *) filename, filenameSize)) {
            return 1;
        }
    }

    return 0;
}