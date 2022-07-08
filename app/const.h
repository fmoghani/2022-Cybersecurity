#define PORT 1805

// Authentication constants
#define randBytesSize 16 // Sizes in bytes
#define timeBufferSize 64
#define nonceSize randBytesSize + timeBufferSize

// Key constants
#define sessionKeySize 32 // Size in bytes