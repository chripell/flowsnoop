package ebpf2

// #cgo LDFLAGS: -lbpf
// #include "c/flowsnoop2_skel.h"
// #include "ebpf2_helpers.h"
// #include <bpf/libbpf.h>
// #include <bpf/bpf.h>
import "C"

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
	"unsafe"

	"github.com/chripell/flowsnoop/flow"
	"gopkg.in/restruct.v1"
)

type Ebpf2 struct {
	consumer flow.Consumer
	obj      *C.struct_flowsnoop2
	conn4FD  C.int
	conn4K   []byte
	conn4KP  unsafe.Pointer
	conn4V   []byte
	conn4VP  unsafe.Pointer
	finished chan struct{}
}

func (ebpf *Ebpf2) Init(consumer flow.Consumer) error {
	ebpf.consumer = consumer
	if ret := C.bump_memlock_rlimit(); ret != 0 {
		return fmt.Errorf("failed to increase mlock limit: %d", ret)
	}
	ebpf.obj = C.flowsnoop2__open()
	if ebpf.obj == nil {
		return errors.New("failed to open eBPF object")
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
	ebpf.finished = make(chan struct{})
	ebpf.conn4FD = C.bpf_map__fd(ebpf.obj.maps.connections)
	conn4Def := C.bpf_map__def(ebpf.obj.maps.connections)
	ebpf.conn4K = make([]byte, conn4Def.key_size)
	ebpf.conn4KP = unsafe.Pointer(&ebpf.conn4K[0])
	ebpf.conn4V = make([]byte, conn4Def.value_size)
	ebpf.conn4VP = unsafe.Pointer(&ebpf.conn4V[0])
	// TODO: resize if entries different
	return nil
}

func memsetLoop(a []byte, v byte) {
	for i := range a {
		a[i] = v
	}
}

func (ebpf *Ebpf2) Run(ctx context.Context, flush <-chan (chan<- error)) {
	go func() {
		defer close(ebpf.finished)
		var (
			flows4 []flow.Sample4L
			flows6 []flow.Sample6L
		)
		for {
			var chErr chan<- error
			select {
			case <-ctx.Done():
				return
			case chErr = <-flush:
				break
			}
			// IPv4
			memsetLoop(ebpf.conn4K, 0xff)
			for {
				if C.bpf_map_get_next_key(ebpf.conn4FD,
					ebpf.conn4KP, ebpf.conn4KP) != 0 {
					break
				}
				if ret := C.bpf_map_lookup_and_delete_elem(ebpf.conn4FD,
					ebpf.conn4KP, ebpf.conn4VP); ret != 0 {
					chErr <- fmt.Errorf("cannot find key: %d", ret)
					return
				}
				var fl flow.Sample4
				if err := restruct.Unpack(ebpf.conn4K,
					binary.BigEndian, &fl); err != nil {
					chErr <- fmt.Errorf("unpacking of flow failed: %v", err)
					return
				}
				flows4 = append(flows4, flow.Sample4L{
					Flow: fl,
					Tot:  binary.LittleEndian.Uint64(ebpf.conn4V),
				})
			}
			// IPv6
			// Push to consumer
			if err := ebpf.consumer.Push(time.Now(), flows4, nil, flows6, nil); err != nil {
				chErr <- fmt.Errorf("error from consumer: %w\n", err)
				return
			}
			flows4 = flows4[:0]
			flows6 = flows6[:0]
			chErr <- nil
		}
	}()
}

func (ebpf *Ebpf2) Finalize() error {
	<-ebpf.finished
	C.flowsnoop2__destroy(ebpf.obj)
	return nil
}

func New() *Ebpf2 {
	return &Ebpf2{}
}
