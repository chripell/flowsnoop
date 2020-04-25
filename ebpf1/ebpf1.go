package ebpf1

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/chripell/flowsnoop/flow"
	bpf "github.com/iovisor/gobpf/bcc"
	"gopkg.in/restruct.v1"
)

//go:generate esc -o flowsnoop1.go -pkg ebpf1 -private c/flowsnoop1.c
//
// Note that we need:
// go get -u github.com/mjibson/esc
// to regenerate ebpf code with:
// go generate

type Ebpf1 struct {
	m        *bpf.Module
	consumer flow.Consumer
	table    *bpf.Table
	finished chan struct{}
}

func tracepointProbe(category, event string) string {
	return fmt.Sprintf("tracepoint__%s__%s", category, event)
}

func LoadAttach(m *bpf.Module, category, event string) error {
	name := tracepointProbe(category, event)
	fd, err := m.LoadTracepoint(name)
	if err != nil {
		return fmt.Errorf("loading tracepoint %s failed: %w", name, err)
	}
	name = category + ":" + event
	if err := m.AttachTracepoint(name, fd); err != nil {
		return fmt.Errorf("attaching tracepoint %s failed: %w", name, err)
	}
	return nil
}

var iface = flag.String("ebpf1_iface", "",
	"Interfaces on which should listed")

func (ebpf *Ebpf1) Init(consumer flow.Consumer) error {
	ebpf.consumer = consumer
	f, err := _escLocal.Open("flowsnoop1.c")
	if err != nil {
		return fmt.Errorf("cannot open ebpf source: %w", err)
	}
	src, err := ioutil.ReadAll(f)
	if err != nil {
		return fmt.Errorf("cannot read ebpf source: %w", err)
	}
	ebpf.m = bpf.NewModule(string(src), []string{})
	for _, probe := range []string{"netif_receive_skb", "net_dev_start_xmit"} {
		if err := LoadAttach(ebpf.m, "net", probe); err != nil {
			return fmt.Errorf("error loading/attaching probe %s: %w", probe, err)
		}
	}
	tableId := ebpf.m.TableId("connections")
	ebpf.table = bpf.NewTable(tableId, ebpf.m)
	ebpf.finished = make(chan struct{})
	return nil
}

func (ebpf *Ebpf1) Run(ctx context.Context, flush <-chan (chan<- error)) {
	go func() {
		defer close(ebpf.finished)
		var flows4 []flow.Sample4L
		for {
			var chErr chan<- error
			select {
			case <-ctx.Done():
				return
			case chErr = <-flush:
				break
			}
			for it := ebpf.table.Iter(); it.Next(); {
				var fl flow.Sample4
				if err := restruct.Unpack(it.Key(), binary.BigEndian, &fl); err != nil {
					chErr <- fmt.Errorf("unpacking of flow failed: %v", err)
					return
				}
				flows4 = append(flows4, flow.Sample4L{
					Flow: fl,
					Tot:  binary.LittleEndian.Uint64(it.Leaf()),
				})
			}
			if err := ebpf.table.Iter().Err(); err != nil {
				chErr <- fmt.Errorf("error iterating table: %w\n", err)
			}
			if err := ebpf.table.DeleteAll(); err != nil {
				chErr <- fmt.Errorf("error deleting table: %w\n", err)
				return
			}
			if err := ebpf.consumer.Push(time.Now(), flows4, nil, nil, nil); err != nil {
				chErr <- fmt.Errorf("error from consumer: %w\n", err)
				return
			}
			flows4 = flows4[:0]
		}
	}()
}

func (ebpf *Ebpf1) Finalize() error {
	<-ebpf.finished
	ebpf.m.Close()
	return nil
}

func New() *Ebpf1 {
	return &Ebpf1{}
}
