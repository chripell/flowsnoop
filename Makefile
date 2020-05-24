CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
LLVM_STRIP ?= llvm-strip

all: flowsnoop

.PHONY: flowsnoop
flowsnoop: ebpf1/flowsnoop1.go
	go build ./...
	go build -o flowsnoop flowsnoop.go

.PHONY: clean
clean:
	rm -f flowsnoop
	find . -name '*~' -exec rm {} \;

ebpf1/flowsnoop1.go: ebpf1/c/flowsnoop1.c
	cd ebpf1 ; go generate

ebpf2/c/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

ebpf2/c/flowsnoop2.o: ebpf2/c/flowsnoop2.c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) -c $(filter %.c,$^) -o $@ && \
	$(LLVM_STRIP) -g $@

ebpf2/c/flowsnoop2_skel.h: ebpf2/c/flowsnoop2.o
	bpftool gen skeleton $^ > $@
