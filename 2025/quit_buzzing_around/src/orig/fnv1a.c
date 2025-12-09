#pragma once

#include "/usr/src/linux/vmlinux.h"

static inline u64 fnv1a(const u8 *data, u32 len)
{
	u64 hash = 0xcbf29ce484222325;
	u64 fnv_prime = 0x00000100000001b3;

	while (len--) {
		hash ^= *data++;
		hash *= fnv_prime;
	}

	return hash;
}
