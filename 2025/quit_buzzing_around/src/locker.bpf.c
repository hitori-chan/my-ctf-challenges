#include "/usr/src/linux/vmlinux.h"
#include <linux/limits.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "chacha20.bpf.c"
#include "./fnv1a.c"

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#define dbg(fmt, ...) bpf_printk("[%s:%d] " fmt, __func__, __LINE__, ##__VA_ARGS__)
#else
#define dbg(fmt, ...) \
	do {          \
	} while (0)
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct access_info {
	u64 buf_addr;
	u8 is_proc_version;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, struct access_info);
} c SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_MMAPABLE);
	__type(key, u32);
	__type(value, u64);
} d SEC(".maps");

u64 e = 0;
u64 k = 0;
u8 f[512];
u8 g[32] = { 151, 139, 139, 143, 140, 197, 208, 208, 134, 144, 138, 139, 138, 209, 157, 154,
	     208, 136, 172, 171, 157, 155, 142, 144, 210, 149, 200, 203, 192, 140, 150, 194 };

SEC("tp/syscalls/sys_enter_openat")
int h(struct trace_event_raw_sys_enter *ctx)
{
	// Filter by Mount Namespace
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	u64 mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

	dbg("pid=%d mnt_ns=%llu filter=%llu", bpf_get_current_pid_tgid() >> 32, mnt_ns,
	    filter_mnt_ns);

	if (k && mnt_ns != k)
		return 0;

	char path[256];

	// BUG: https://github.com/iovisor/bcc/issues/3175
	s32 res = bpf_probe_read_user_str(path, sizeof(path), (char *)ctx->args[1]);
	if (res < 0) {
		dbg("Failed to read path");
		return 0;
	}

	u32 pid = bpf_get_current_pid_tgid();

	if (!e && fnv1a((const u8 *)path, res) == 0x93b9a1eb4054d0b) {
		dbg("/proc/version is accessed by pid %d", pid);

		struct access_info info = { 1, 1 };
		if (bpf_map_update_elem(&c, &pid, &info, BPF_ANY)) {
			dbg("/proc/version failed to add pid %d to access map", pid);
			return 0;
		};
	}

	char flag_path[] = "/flag";
	for (u16 i = 0; i < sizeof(flag_path); ++i) {
		if (path[i] != flag_path[i]) {
			return 0;
		}
	}

	dbg("Flag is accessed by pid %d", pid);

	struct access_info info = { 1, 0 };
	if (bpf_map_update_elem(&c, &pid, &info, BPF_ANY)) {
		dbg("Failed to add pid %d to access map", pid);
	}

	return 0;
}

SEC("tp/syscalls/sys_enter_read")
int i(struct trace_event_raw_sys_enter *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();

	struct access_info *info = bpf_map_lookup_elem(&c, &pid);
	if (!info || info->buf_addr != 1) {
		return 0;
	}

	struct access_info new_info = { ctx->args[1], info->is_proc_version };
	dbg("Add pid %d, buf %llx to access map", pid, new_info.buf_addr);

	if (bpf_map_update_elem(&c, &pid, &new_info, BPF_EXIST)) {
		dbg("Failed to update buf of pid %d in access map", pid);
	}

	return 0;
}

SEC("tp/syscalls/sys_exit_read")
int j(struct trace_event_raw_sys_exit *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();

	struct access_info *info = bpf_map_lookup_elem(&c, &pid);
	if (!info || !info->buf_addr) {
		return 0;
	}

	u32 bytes_read = ctx->ret;
	if (bytes_read <= 0) {
		dbg("pid %d, bytes read <= 0", pid);
		goto cleanup;
	}

	if (info->is_proc_version) {
		s32 res = bpf_probe_read_user_str(f, sizeof(f), (u8 *)info->buf_addr);
		if (res <= 0) {
			dbg("Failed to read /proc/version from userspace process");
			goto cleanup;
		}

		e = fnv1a(f, res);

		dbg("%d, %s", res, f);
		goto cleanup;
	}

	u32 zero = 0;
	u64 *now = bpf_map_lookup_elem(&d, &zero);
	if (!now || !*now) {
		dbg("Failed to get current time");
		goto cleanup;
	}

	dbg("Current time: %llu", *now);
	dbg("/proc/version hash: %llx", e);

	u64 sum = *now + e;
	u64 totp = fnv1a((u8 *)&sum, 8);

	u8 nonce[12];
	*(u64 *)nonce = totp;
	*(u32 *)(nonce + 8) = 0;

	u8 decoded_key[32];
	for (u8 i = 0; i < 32; ++i) {
		decoded_key[i] = g[i] ^ 0xff;
	}

	dbg("Encrypt buffer of pid %d", pid);
	chacha20_docrypt((u8 *)info->buf_addr, bytes_read, decoded_key, nonce, 0, 0);

cleanup:
	bpf_map_delete_elem(&c, &pid);
	return 0;
}
