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

skeltons = ebpf2/c/flowsnoop2_skel.h

$(skeltons): %_skel.h: %.o
	bpftool gen skeleton $^ > $@

$(skeltons:_skel.h=.o): %.o: %.c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) -c $(filter %.c,$^) -o $@ && \
	$(LLVM_STRIP) -g $@

tcprogs = ebpf3/c/flowsnoop3.o

$(tcprogs): %.o: %.c
	$(CLANG) -O2 -target bpf $(INCLUDES) -c $(filter %.c,$^) -o $@

ebpf3/flowsnoop3.go: ebpf3/c/flowsnoop3.o
	cd ebpf3 ; go generate
