#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

char buf[512];

int main(int argc, char *argv[])
{
	FILE *f = fopen("/flag", "r");
	if (!f) {
		puts("Failed to access /flag");
		return 1;
	}
	fread(buf, 1, sizeof(buf), f);
	fclose(f);
	puts(buf);
	return 0;
}
