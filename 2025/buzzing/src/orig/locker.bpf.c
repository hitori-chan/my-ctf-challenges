// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/ptrace.h>

#include <bpf/bpf_helpers.h>

#define __TARGET_ARCH_x86
#include <bpf/bpf_tracing.h>

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#define bpf_debug(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define bpf_debug(fmt, ...)                                                                                            \
    do {                                                                                                               \
    } while (0)
#endif

#define SECRET_LEN 34
#define EACCES 13

// XOR key as volatile to prevent optimization
const volatile unsigned char xor_key = 0x36;

// XOR-encoded secret: "https://youtu.be/BoZ0Zwab6Oc?id=$$"
const unsigned char encoded_secret[SECRET_LEN] = {
    0x5e, 0x42, 0x42, 0x46, 0x45, 0x0c, 0x19, 0x19,
    0x4f, 0x59, 0x43, 0x42, 0x43, 0x18, 0x54, 0x53,
    0x19, 0x74, 0x59, 0x6c, 0x06, 0x6c, 0x41, 0x57,
    0x54, 0x00, 0x79, 0x55, 0x09, 0x5f, 0x52, 0x0b,
    0x12, 0x12
};

char LICENSE[] SEC("license") = "GPL";

static char filename[128];
static char password[SECRET_LEN + 1];

// Helper function to check if string contains "readflag"
static __always_inline int contains_readflag(const char *str, int max_len) {
    const char pattern[] = "readflag";

    for (int i = 0; i < max_len - 7; i++) {
        int match = 1;
#pragma unroll
        for (int j = 0; j < 8; j++) {
            if (str[i + j] != pattern[j]) {
                match = 0;
                break;
            }
        }
        if (match)
            return 1;
    }
    return 0;
}

// Helper function to verify password with constant-time comparison
static __always_inline int verify_password(const char *password) {
    int match = 1;

    // Compare with XOR decoding at runtime
    #pragma unroll
    for (int i = 0; i < SECRET_LEN; i++) {
        if (password[i] != (encoded_secret[i] ^ xor_key)) {
            match = 0;
        }
    }
    return match;
}

SEC("kprobe/__x64_sys_execve")
int kprobe_execve(struct pt_regs *ctx) {
    const char *filename_ptr;
    const char **argv;
    const char *password_ptr;

    __builtin_memset(filename, 0, sizeof(filename));
    __builtin_memset(password, 0, sizeof(password));

    // Get real pt_regs containing syscall arguments
    struct pt_regs *real_regs = (struct pt_regs *)PT_REGS_PARM1(ctx);

    // Read filename and argv pointers from syscall args
    bpf_probe_read_kernel(&filename_ptr, sizeof(filename_ptr), &PT_REGS_PARM1(real_regs));
    bpf_probe_read_kernel(&argv, sizeof(argv), &PT_REGS_PARM2(real_regs));

    // Read filename string from userspace
    if (bpf_probe_read_user_str(filename, sizeof(filename), filename_ptr) <= 0) {
        return 0;
    }

    bpf_debug("execve PID %d: %s\n", bpf_get_current_pid_tgid() >> 32, filename);

    // Quick check: only process if filename contains "readflag"
    if (!contains_readflag(filename, sizeof(filename))) {
        return 0;
    }

    bpf_debug("readflag detected\n");

    // Read password from argv[1]
    if (bpf_probe_read_user(&password_ptr, sizeof(password_ptr), &argv[1]) < 0 || !password_ptr) {
        bpf_debug("no password, blocking\n");
        bpf_override_return(ctx, -EACCES);
        return 0;
    }

    if (bpf_probe_read_user_str(password, sizeof(password), password_ptr) <= 0) {
        bpf_debug("failed to read password, blocking\n");
        bpf_override_return(ctx, -EACCES);
        return 0;
    }

    bpf_debug("password: %s\n", password);

    // Verify password
    if (verify_password(password)) {
        bpf_debug("correct password, allowing\n");
    } else {
        bpf_debug("wrong password, blocking\n");
        bpf_override_return(ctx, -EACCES);
    }

    return 0;
}
