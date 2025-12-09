#include <bits/time.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/syscall.h>

#include "types.h"
#include "locker.skel.h"

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#define dbg(fmt, ...) fprintf(stderr, "[%s:%d] " fmt, __func__, __LINE__, ##__VA_ARGS__)
#else
#define dbg(fmt, ...) \
	do {          \
	} while (0)
#endif

#ifndef KERNEL_VERSION
#define KERNEL_VERSION "6.17.9-arch1-1"
#endif

#ifndef CPU_NAME
#define CPU_NAME "13th Gen Intel(R) Core(TM) i7-13800H"
#endif

static volatile sig_atomic_t keep_running = 1;
u64 *time_map = NULL;

void sig_handler(int signo)
{
	dbg("Received signal %d, shutting down\n", signo);
	keep_running = 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
#if DEBUG
	return vfprintf(stderr, format, args);
#else
	return 0;
#endif
}

char buf[1024];

int security_check()
{
	FILE *f = fopen("/proc/version", "r");
	if (!f) {
		dbg("Failed to acccess /proc/version");
		return 1;
	}
	fread(buf, 1, sizeof(buf), f);
	fclose(f);

	if (!strstr(buf, KERNEL_VERSION)) {
		dbg("Kernel version mismatch");
		return 1;
	}

	f = fopen("/proc/cpuinfo", "r");
	if (!f) {
		dbg("Failed to access /proc/cpuinfo\n");
		return 1;
	}
	fread(buf, 1, sizeof(buf), f);
	fclose(f);

	if (!strstr(buf, CPU_NAME)) {
		dbg("CPU mismatch\n");
		return 1;
	}

	return 0;
}

void *timer(void *arg)
{
	while (keep_running) {
		if (time_map) {
			struct {
				u64 sec;
				u64 nsec;
			} t;

			syscall(SYS_clock_gettime, 0, &t);
			time_map[0] = t.sec;
		}
		sleep(1);
	}
	return NULL;
}

__attribute__((constructor)) int init_bpf()
{
	pthread_t t;
	pthread_create(&t, NULL, timer, NULL);
	return 0;
}

int main(int argc, char **argv)
{
	struct locker_bpf *skel;
	int err;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	libbpf_set_print(libbpf_print_fn);

	skel = locker_bpf__open_and_load();
	if (!skel) {
		dbg("Failed to open and load BPF skeleton\n");
		return 1;
	}

	memset(skel->data->key, 0, 32);

	err = locker_bpf__attach(skel);
	if (err) {
		dbg("Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	int fd = bpf_map__fd(skel->maps.time_map);
	time_map = mmap(NULL, sysconf(_SC_PAGESIZE), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (time_map == MAP_FAILED) {
		dbg("Failed to mmap time_map");
		goto cleanup;
	}

	if (security_check()) {
		dbg("Security check failed");
		goto cleanup;
	}

	dbg("Locker loaded successfully\n");

	while (keep_running) {
		sleep(1);
	}

cleanup:
	locker_bpf__destroy(skel);
	return -err;
}
