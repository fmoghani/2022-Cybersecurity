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

#define PORT 1804

using namespace std;

class Server {

    // Variables
    int socketfd;
    struct sockaddr_in serverAddr, clientAddr;

public:

    // Build function
    Server() {
        
        // Initialize server certificate
        // Initialize authorized users list
        startSocket();
    }

    // Creates a socket and makes it listen
    void startSocket() {

        int ret;

        // Socket creation
        socketfd = socket(AF_INET, SOCK_STREAM, 0);
        if (!socketfd) {
            cerr << "Error creating socket" << "\n";
            exit(1);
        }

        // Socket parameters setup
        memset(&serverAddr, 0, sizeof(serverAddr));
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(PORT);
        serverAddr.sin_addr.s_addr = INADDR_ANY;

        // Bind the socket to the adress
        ret = bind(socketfd, (sockaddr*)&serverAddr, sizeof(serverAddr));
        if (!ret) {
            cerr << "Error binding socket" << "\n";
            close(socketfd);
        }

        // Start listening for requests
        ret = listen(socketfd, 10);
        if (!ret) {
            cerr << "Error listening" << "\n";
            exit(1);
        }
        cout << "Listening to port : " << PORT << "\n";
    }

    // Establish session private key
    void createSessionKey() {

        
    }

};

int main() {

    int ret;

    // Create a socket connexion

    return 0;
}