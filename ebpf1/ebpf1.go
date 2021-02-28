package ebpf1

// Copyright 2021 Google LLC

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
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
	table6   *bpf.Table
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

var (
	iface = flag.String("ebpf1_iface", "all",
		"Interfaces on which should listed (comma separated) or all.")
	buckets = flag.Int("ebpf1_buckets", 1024, "buckets for in-kernel tables.")
)

func (ebpf *Ebpf1) Init(consumer flow.Consumer) error {
	ebpf.consumer = consumer
	f, err := _escStatic.Open("/c/flowsnoop1.c")
	if err != nil {
		return fmt.Errorf("cannot open ebpf source: %w", err)
	}
	bsrc, err := ioutil.ReadAll(f)
	if err != nil {
		return fmt.Errorf("cannot read ebpf source: %w", err)
	}
	src := string(bsrc)
	src = strings.Replace(src, "BUCKETS", strconv.Itoa(*buckets), -1)
	var (
		devs []string
		cmps []string
	)
	if *iface == "all" {
		devs = append(devs, "")
		cmps = append(cmps, "0")
	} else {
		ifaces := strings.Split(*iface, ",")
		for i, ifx := range ifaces {
			devs = append(devs, fmt.Sprintf(`char dev%d[] = "%s";`, i, ifx))
			cmps = append(cmps, fmt.Sprintf(`equal(dev%d, dev, %d)`, i, len(ifx)))
		}
	}
	src = strings.Replace(src, "DEVS;", strings.Join(devs, "\n"), -1)
	src = strings.Replace(src, "CMPS", strings.Join(cmps, "&&"), -1)
	ebpf.m = bpf.NewModule(src, []string{})
	for _, probe := range []string{"netif_receive_skb", "net_dev_start_xmit"} {
		if err := LoadAttach(ebpf.m, "net", probe); err != nil {
			return fmt.Errorf("error loading/attaching probe %s: %w", probe, err)
		}
	}
	tableId := ebpf.m.TableId("connections")
	ebpf.table = bpf.NewTable(tableId, ebpf.m)
	tableId6 := ebpf.m.TableId("connections6")
	ebpf.table6 = bpf.NewTable(tableId6, ebpf.m)
	ebpf.finished = make(chan struct{})
	return nil
}

func (ebpf *Ebpf1) Run(ctx context.Context, flush <-chan (chan<- error)) {
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
				return
			}
			if err := ebpf.table.DeleteAll(); err != nil {
				chErr <- fmt.Errorf("error deleting table: %w\n", err)
				return
			}
			// IPv6
			for it := ebpf.table6.Iter(); it.Next(); {
				var fl flow.Sample6
				if err := restruct.Unpack(it.Key(), binary.BigEndian, &fl); err != nil {
					chErr <- fmt.Errorf("unpacking of flow6 failed: %v", err)
					return
				}
				flows6 = append(flows6, flow.Sample6L{
					Flow: fl,
					Tot:  binary.LittleEndian.Uint64(it.Leaf()),
				})
			}
			if err := ebpf.table6.Iter().Err(); err != nil {
				chErr <- fmt.Errorf("error iterating table6: %w\n", err)
				return
			}
			if err := ebpf.table6.DeleteAll(); err != nil {
				chErr <- fmt.Errorf("error deleting table6: %w\n", err)
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

func (ebpf *Ebpf1) Finalize() error {
	<-ebpf.finished
	ebpf.m.Close()
	return nil
}

func New() *Ebpf1 {
	return &Ebpf1{}
}
