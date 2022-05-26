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
    if (!CACrl)
    {
        cerr << "Error cannot read " << path << " crl\n";
        exit(1);
    }
}