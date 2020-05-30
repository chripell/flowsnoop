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
	"flag"
	"fmt"
	"time"
	"unsafe"

	"github.com/chripell/flowsnoop/flow"
	"gopkg.in/restruct.v1"
)

type connMap struct {
	fd C.int
	ks int
	v  []byte
	vp unsafe.Pointer
	z  []byte
	zp unsafe.Pointer
}

type Ebpf2 struct {
	consumer flow.Consumer
	obj      *C.struct_flowsnoop2
	finished chan struct{}
	conn4    *connMap
	bconn4   *connMap
	conn6    *connMap
	bconn6   *connMap
	currentB bool
}

func memsetLoop(a []byte, v byte) {
	for i := range a {
		a[i] = v
	}
}

func newConnMap(m *C.struct_bpf_map) *connMap {
	connDef := C.bpf_map__def(m)
	cm := &connMap{
		fd: C.bpf_map__fd(m),
		ks: int(connDef.key_size),
		v:  make([]byte, connDef.value_size),
		z:  make([]byte, connDef.key_size),
	}
	cm.vp = unsafe.Pointer(&cm.v[0])
	memsetLoop(cm.z, 0xff)
	cm.zp = unsafe.Pointer(&cm.z[0])
	return cm
}

const (
	// Keep the default in sync with BUCKETS in the eBPF program.
	BUCKETS = 10240
)

var (
	iface = flag.String("ebpf2_iface", "all",
		"Interface on which should listed or all.")
	buckets = flag.Int("ebpf2_buckets", BUCKETS, "buckets for in-kernel tables.")
)

func (ebpf *Ebpf2) Init(consumer flow.Consumer) error {
	ebpf.consumer = consumer
	if ret := C.bump_memlock_rlimit(); ret != 0 {
		return fmt.Errorf("failed to increase mlock limit: %d", ret)
	}
	ebpf.obj = C.flowsnoop2__open()
	if ebpf.obj == nil {
		return errors.New("failed to open eBPF object")
	}
	target_iface := "\000"
	if *iface != "all" {
		target_iface = *iface + "\000"
	}
	for i, ch := range []byte(target_iface) {
		ebpf.obj.rodata.targ_iface[i] = C.char(ch)
	}
	if ret := C.flowsnoop2__load(ebpf.obj); ret != 0 {
		return fmt.Errorf("failed to load eBPF program: %d", ret)
	}
	if ret := C.flowsnoop2__attach(ebpf.obj); ret != 0 {
		return fmt.Errorf("failed to attach eBPF program: %d", ret)
	}
	ebpf.finished = make(chan struct{})
	ebpf.conn4 = newConnMap(ebpf.obj.maps.connections)
	ebpf.bconn4 = newConnMap(ebpf.obj.maps.bconnections)
	ebpf.conn6 = newConnMap(ebpf.obj.maps.connections6)
	ebpf.bconn6 = newConnMap(ebpf.obj.maps.bconnections6)
	if *buckets != BUCKETS {
		C.bpf_map__resize(ebpf.obj.maps.connections, C.uint(*buckets))
		C.bpf_map__resize(ebpf.obj.maps.bconnections, C.uint(*buckets))
		C.bpf_map__resize(ebpf.obj.maps.connections6, C.uint(*buckets))
		C.bpf_map__resize(ebpf.obj.maps.bconnections6, C.uint(*buckets))
	}
	return nil
}

func loopMap(m *connMap, fl interface{}, k [][]byte, appEntry func(len uint64)) ([][]byte, error) {
	n := 0
	for {
		if n == len(k) {
			k = append(k, make([]byte, m.ks))
		}
		p := m.zp
		if n > 0 {
			p = unsafe.Pointer(&(k[n-1])[0])
		}
		np := unsafe.Pointer(&(k[n])[0])
		if C.bpf_map_get_next_key(m.fd,
			p, np) != 0 {
			break
		}
		if ret, errno := C.bpf_map_lookup_elem(m.fd,
			np, m.vp); ret != 0 {
			return nil, fmt.Errorf("cannot lookup elem: %d %d", ret, errno)
		}
		if err := restruct.Unpack(k[n],
			binary.BigEndian, fl); err != nil {
			return nil, fmt.Errorf("unpacking of flow failed: %v", err)
		}
		appEntry(binary.LittleEndian.Uint64(m.v))
		n++
	}
	for _, ck := range k[:n] {
		kp := unsafe.Pointer(&ck[0])
		if ret, errno := C.bpf_map_delete_elem(m.fd,
			kp); ret != 0 {
			return nil, fmt.Errorf("cannot delete elem: %d %d", ret, errno)
		}
	}
	return k, nil
}

func (ebpf *Ebpf2) Run(ctx context.Context, flush <-chan (chan<- error)) {
	go func() {
		defer close(ebpf.finished)
		var (
			flows4 []flow.Sample4L
			flows6 []flow.Sample6L
			k4     [][]byte
			k6     [][]byte
			err    error
			read4  *connMap
			read6  *connMap
		)
		for {
			var chErr chan<- error
			select {
			case <-ctx.Done():
				return
			case chErr = <-flush:
				break
			}
			// Select which map we are reading and
			// redirect recording to the other
			if ebpf.currentB {
				read4 = ebpf.bconn4
				read6 = ebpf.bconn6
				ebpf.obj.bss.use_map = 0
			} else {
				read4 = ebpf.conn4
				read6 = ebpf.conn6
				ebpf.obj.bss.use_map = 1
			}
			// Give time for eBPF update to finish on the
			// current map. This looks *plenty* of time.
			time.Sleep(10 * time.Millisecond)
			ebpf.currentB = !ebpf.currentB
			// IPv4
			var fl4 flow.Sample4
			k4, err = loopMap(read4, &fl4, k4,
				func(n uint64) {
					flows4 = append(flows4, flow.Sample4L{
						Flow: fl4,
						Tot:  n,
					})
				})
			if err != nil {
				chErr <- err
				return
			}
			// IPv6
			var fl6 flow.Sample6
			k6, err = loopMap(read6, &fl6, k6,
				func(n uint64) {
					flows6 = append(flows6, flow.Sample6L{
						Flow: fl6,
						Tot:  n,
					})
				})
			if err != nil {
				chErr <- err
				return
			}
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
