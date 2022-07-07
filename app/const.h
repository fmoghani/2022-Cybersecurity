#define PORT 1805

// Authentication constants
#define randBytesSize 16
#define timeBufferSize 120
#define nonceSize randBytesSize + timeBufferSize

// Key constants
#define sessionKeySize 256