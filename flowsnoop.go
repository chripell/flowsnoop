package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"sort"
	"time"

	bpf "github.com/iovisor/gobpf/bcc"
	"gopkg.in/restruct.v1"
)

type Flow struct {
	SrcIP   [4]byte `struct:"[4]byte"`
	DstIP   [4]byte `struct:"[4]byte"`
	SrcPort uint16  `struct:"uint16"`
	DstPort uint16  `struct:"uint16"`
	Proto   uint8   `struct:"uint8"`
}

type FlowT struct {
	flow Flow
	tot  uint64
}

func tracepointProbe(category, event string) string {
	return fmt.Sprintf("tracepoint__%s__%s", category, event)
}

func loadAttach(m *bpf.Module, category, event string) error {
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

func protoToString(proto uint8) string {
	if proto == 17 {
		return "udp"
	}
	return "tcp"
}

func main() {
	ebpfSource := flag.String("ebpf_program", "flowsnoop.c", "ebpf program to load")

	flag.Parse()

	src, err := ioutil.ReadFile(*ebpfSource)
	if err != nil {
		log.Fatalf("Cannot load source file %q: %v", src, err)
	}
	m := bpf.NewModule(string(src), []string{})
	defer m.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	if err := loadAttach(m, "net", "netif_receive_skb"); err != nil {
		fmt.Printf("Error loading/attaching probe: %v", err)
	}
	if err := loadAttach(m, "net", "net_dev_start_xmit"); err != nil {
		fmt.Printf("Error loading/attaching probe: %v", err)
	}

	tableId := m.TableId("connections")
	tableDesc := m.TableDesc(uint64(tableId))
	if name, ok := tableDesc["name"].(string); ok {
		fmt.Printf("Table Name: %s\n", name)
	}
	if len, ok := tableDesc["key_size"].(uint64); ok {
		fmt.Printf("Key Size: %d\n", len)
	}
	if len, ok := tableDesc["leaf_size"].(uint64); ok {
		fmt.Printf("Leaf Size: %d\n", len)
	}
	if name, ok := tableDesc["key_desc"].(string); ok {
		fmt.Printf("Key Description: %s\n", name)
	}
	if name, ok := tableDesc["leaf_desc"].(string); ok {
		fmt.Printf("Leaf Description: %s\n", name)
	}
	fmt.Println("Press C-c to stop")

	table := bpf.NewTable(tableId, m)
	flows := make(map[Flow]uint64)
end_loop:
	for {
		select {
		case <-sig:
			break end_loop
		case <-time.After(time.Second):
		}
		fmt.Println("--------------")
		for it := table.Iter(); it.Next(); {
			var flow Flow
			data := it.Key()
			if err := restruct.Unpack(data, binary.BigEndian, &flow); err != nil {
				fmt.Printf("Unpacking of flow failed: %v\n", err)
				continue
			}
			flows[flow] += binary.LittleEndian.Uint64(it.Leaf())
		}
		if err := table.Iter().Err(); err != nil {
			fmt.Printf("Error iterating table: %v\n", err)
		}
		if err := table.DeleteAll(); err != nil {
			fmt.Printf("Error flushing table: %v", err)
		}
		flowList := make([]FlowT, 0, len(flows))
		for flow, tot := range flows {
			flowList = append(flowList, FlowT{flow, tot})
		}
		sort.Slice(flowList, func(i, j int) bool {
			if flowList[i].tot > flowList[j].tot {
				return true
			}
			return false
		})
		l := len(flowList)
		if l > 20 {
			l = 20
		}
		for _, el := range flowList[:l] {
			srcAddr := net.TCPAddr{
				IP:   net.IP(el.flow.SrcIP[:]),
				Port: int(el.flow.SrcPort),
			}
			dstAddr := net.TCPAddr{
				IP:   net.IP(el.flow.DstIP[:]),
				Port: int(el.flow.DstPort),
			}
			fmt.Printf("%s -> %s, %s: ", srcAddr.String(),
				dstAddr.String(), protoToString(el.flow.Proto))
			fmt.Printf("%d\n", el.tot)
		}
	}
}
