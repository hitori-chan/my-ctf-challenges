DEBUG ?= 0

all: locker.bpf.o loader readflag

locker.bpf.o: locker.bpf.c
	clang -O2 -target bpf -D__TARGET_ARCH_x86_64 -DDEBUG=$(DEBUG) -c locker.bpf.c -o locker.bpf.o

loader: loader.c
	clang -O2 -s -DDEBUG=$(DEBUG) -o loader loader.c -lbpf

readflag: readflag.c
	clang -O2 -s -o readflag readflag.c

clean:
	rm -f locker.bpf.o loader readflag
