package ebpf2

// #cgo LDFLAGS: -lbpf
// #include "c/flowsnoop2_skel.h"
// #include "ebpf2_helpers.h"
import "C"

import (
	"context"
	"errors"
	"fmt"

	"github.com/chripell/flowsnoop/flow"
)

type Ebpf2 struct {
	consumer flow.Consumer
	obj      *C.struct_flowsnoop2
}

func (ebpf *Ebpf2) Init(consumer flow.Consumer) error {
	ebpf.consumer = consumer
	if ret := C.bump_memlock_rlimit(); ret != 0 {
		return fmt.Errorf("failed to increase mlock limit: %d", ret)
	}
	ebpf.obj = C.flowsnoop2__open()
	if ebpf.obj == nil {
		return errors.New("failed to open eBPF objectxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	}
	iface := "eth0\000"
	for i, ch := range []byte(iface) {
		ebpf.obj.rodata.targ_iface[i] = C.char(ch)
	}
	if ret := C.flowsnoop2__load(ebpf.obj); ret != 0 {
		return fmt.Errorf("failed to load eBPF program: %d", ret)
	}
	if ret := C.flowsnoop2__attach(ebpf.obj); ret != 0 {
		return fmt.Errorf("failed to attach eBPF program: %d", ret)
	}
	return nil
}

func (ebpf *Ebpf2) Run(ctx context.Context, flush <-chan (chan<- error)) {
}

func (ebpf *Ebpf2) Finalize() error {
	return nil
}

func New() *Ebpf2 {
	return &Ebpf2{}
}
