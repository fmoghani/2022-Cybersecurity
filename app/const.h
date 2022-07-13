#define PORT 1805

// Authentication constants
#define randBytesSize 16 // Sizes in bytes
#define timeBufferSize 64
#define nonceSize 29

// Key constants
#define sessionKeySize 32 // Size in bytes

// Symmetric cipher constants
#define blockSize 16
#define ivSize 16

// Constant relative to user
#define maxCommandSize 32
#define UPLOAD_BUFFER_SIZE 8
#define MAX_FILE_SIZE_FOR_UPLOAD 4000000000