
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

