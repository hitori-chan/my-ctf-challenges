DEBUG ?= 0
KERNEL_VERSION ?= $(shell uname -r)
CPU_NAME ?= $(shell awk -F': ' '/model name/ {print $$2; exit}' /proc/cpuinfo)

all: locker.skel.h loader readflag

locker.bpf.o: locker.bpf.c
	clang -g -O3 -target bpf -DDEBUG=$(DEBUG) -DKERNEL_VERSION='"$(KERNEL_VERSION)"' -DCPU_NAME='"$(CPU_NAME)"' -c locker.bpf.c -o locker.bpf.o
	llvm-strip -d locker.bpf.o
	./btf-strip ./locker.bpf.o

locker.skel.h: locker.bpf.o
	bpftool gen skeleton locker.bpf.o > locker.skel.h

loader: locker.skel.h loader.c
	clang -O3 -s -DDEBUG=$(DEBUG) -DKERNEL_VERSION='"$(KERNEL_VERSION)"' -DCPU_NAME='"$(CPU_NAME)"' -o loader loader.c -lbpf

readflag: readflag.c
	clang -O3 -s readflag.c -o readflag

clean:
	rm -f locker.bpf.o locker.skel.h loader readflag
