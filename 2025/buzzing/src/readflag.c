#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#define FLAG_FILE "/flag"
#define BUFFER_SIZE 256

int main(void) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    int fd = open(FLAG_FILE, O_RDONLY);

    if (fd == -1) {
        printf("Error: flag file not found\n");
        return 1;
    }

    bytes_read = read(fd, buffer, BUFFER_SIZE - 1);
    close(fd);

    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        printf("%s", buffer);
        return 0;
    }

    printf("Error: cannot read flag file\n");
    return 1;
}
