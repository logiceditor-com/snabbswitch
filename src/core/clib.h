// usleep(3) - suspend execution for microsecond intervals
int usleep(unsigned long usec);

// memcpy(3) - copy memory area
void memcpy(void *dest, const void *src, size_t n);

// memset(3) - fill memory with a constant byte
void *memset(void *s, int c, size_t n);

// memcmp(3)
int memcmp(const void *s1, const void *s2, int n);

// strncpy(3) - copy a string
char *strncpy(char *dest, const char *src, size_t n);

// read(2) - read from a file descriptor
int read(int fd, void *buf, size_t count);

// write(2) - write to a file descriptor
int write(int fd, void *buf, size_t count);

// fork(2) - create a child process
int fork();

// pread(2), pwrite(2) - read/write from a file descriptor at an offset
size_t pread(int fd, void *buf, int count, int offset);
size_t pwrite(int fd, const void *buf, int count, int offset);

// malloc(3) - allocate dynamic memory
void *malloc(int size);

// readlink(2) - get link's target
int64_t readlink(const char *path, char *buf, size_t bufsiz);
char *dirname(char *path);
char *basename(char *path);

// inet_pton(3) - convert IPv4 and IPv6 addresses from text to binary form
int inet_pton(int af, const char *src, void *dst);
