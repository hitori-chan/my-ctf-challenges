#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#define dbg(fmt, ...) fprintf(stderr, "[%s:%d] " fmt, __func__, __LINE__, ##__VA_ARGS__)
#else
#define dbg(fmt, ...)                                                                                                  \
    do {                                                                                                               \
    } while (0)
#endif

static volatile sig_atomic_t keep_running = 1;

void sig_handler(int signo) {
    dbg("Received signal %d, shutting down\n", signo);
    keep_running = 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
#if DEBUG
    return vfprintf(stderr, format, args);
#else
    return 0;
#endif
}

int main(void) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    int err = 0;

    /* dbg("Starting loader\n"); */
    /**/
    /* if (geteuid() != 0) { */
    /*     dbg("ERROR: Must run as root (euid=%d)\n", geteuid()); */
    /*     return 1; */
    /* } */
    /**/
    /* dbg("Running as root, proceeding\n"); */

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    libbpf_set_print(libbpf_print_fn);

    obj = bpf_object__open_file("locker.bpf.o", NULL);
    if (!obj) {
        dbg("ERROR: Failed to open BPF object file\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        dbg("ERROR: Failed to load BPF object (err=%d)\n", err);
        goto cleanup;
    }

    prog = bpf_object__find_program_by_name(obj, "e");
    if (!prog) {
        dbg("ERROR: Failed to find kprobe_execve program\n");
        goto cleanup;
    }

    link = bpf_program__attach(prog);
    if (!link) {
        dbg("ERROR: Failed to attach BPF program\n");
        err = -1;
        goto cleanup;
    }

    dbg("Locker loaded successfully\n");

    while (keep_running)
        pause();

    dbg("Cleaning up\n");

cleanup:
    if (link)
        bpf_link__destroy(link);
    if (obj)
        bpf_object__close(obj);
    dbg("Exiting\n");
    return err != 0;
}
