package ebpf3

//go:generate esc -o flowsnoop3.go -pkg ebpf3 -private c/flowsnoop3.o
//
// Note that we need:
// go get -u github.com/mjibson/esc
// to regenerate ebpf code with:
// go generate

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/chripell/flowsnoop/flow"
	"github.com/dropbox/goebpf"
	"gopkg.in/restruct.v1"
)

type Ebpf3 struct {
	consumer flow.Consumer
	finished chan struct{}
	ifaces   []string

	sw    *goebpf.EbpfMap
	ipv4a *goebpf.EbpfMap
	ipv4b *goebpf.EbpfMap
	ipv6a *goebpf.EbpfMap
	ipv6b *goebpf.EbpfMap
	curr  bool
}

var (
	iface = flag.String("ebpf3_iface", "",
		"Interfaces on which should listed (comma separated).")
	ebpfs = flag.String("ebpf3_ebpfs", "/sys/fs/bpf/tc/globals",
		"Path to ebpfs, where pinned maps are available..")
)

func run(warn bool, prog string, args ...string) (err error) {
	cmd := exec.Command(prog, args...)
	if err = cmd.Run(); err != nil {
		err = fmt.Errorf("%s: %s failed: %v", cmd.Path, strings.Join(cmd.Args, " "), err)
		if warn {
			fmt.Println(err)
		}
	}
	return err
}

func openMap(name string) (*goebpf.EbpfMap, error) {
	fpath := filepath.Join(*ebpfs, name)
	m, err := goebpf.NewMapFromExistingMapByPath(fpath)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", fpath, err)
	}
	return m, nil
}

func (ebpf *Ebpf3) cleanup(warn bool) {
	for _, fname := range []string{
		"flowsnoop_switch",
		"flowsnoop_4_0",
		"flowsnoop_4_1",
		"flowsnoop_6_0",
		"flowsnoop_6_1",
	} {
		if err := os.Remove(filepath.Join(*ebpfs, fname)); warn && err != nil {
			fmt.Printf("failed to delete %s: %v", fname, err)
		}
	}
	for _, iface := range ebpf.ifaces {
		run(warn, "tc", "filter", "del", "dev", iface, "ingress")
		run(warn, "tc", "filter", "del", "dev", iface, "egress")
		run(warn, "tc", "qdisc", "del", "dev", iface, "clsact")
	}
}

func (ebpf *Ebpf3) Init(consumer flow.Consumer) error {
	if *iface == "" {
		return errors.New("no interfaces specified")
	}
	ebpf.ifaces = strings.Split(*iface, ",")
	for i, s := range ebpf.ifaces {
		ebpf.ifaces[i] = strings.TrimSpace(s)
	}
	ebpf.cleanup(false)
	var err error
	defer func() {
		if err != nil {
			ebpf.cleanup(false)
		}
	}()
	ebpf.consumer = consumer
	var (
		fin     http.File
		objFile *os.File
	)
	fin, err = _escStatic.Open("/c/flowsnoop3.o")
	if err != nil {
		return fmt.Errorf("cannot open ebpf object: %w", err)
	}
	defer fin.Close()
	objFile, err = ioutil.TempFile("", "flowsnoop3.*.o")
	if err != nil {
		return fmt.Errorf("cannot create temp object file: %w", err)
	}
	objFname := objFile.Name()
	defer os.Remove(objFname)
	if _, err = io.Copy(objFile, fin); err != nil {
		return err
	}
	if err = objFile.Close(); err != nil {
		return err
	}
	for _, iface := range ebpf.ifaces {
		err = run(false, "tc", "qdisc", "add", "dev", iface, "clsact")
		if err != nil {
			return err
		}
		err = run(false, "tc", "filter", "add", "dev", iface, "ingress",
			"bpf", "da", "obj", objFname, "sec", "ingress")
		if err != nil {
			return err
		}
		err = run(false, "tc", "filter", "add", "dev", iface, "egress",
			"bpf", "da", "obj", objFname, "sec", "egress")
		if err != nil {
			return err
		}
	}
	ebpf.sw, err = openMap("flowsnoop_switch")
	if err != nil {
		return err
	}
	ebpf.ipv4a, err = openMap("flowsnoop_4_0")
	if err != nil {
		return err
	}
	ebpf.ipv4b, err = openMap("flowsnoop_4_1")
	if err != nil {
		return err
	}
	ebpf.ipv6a, err = openMap("flowsnoop_6_0")
	if err != nil {
		return err
	}
	ebpf.ipv6b, err = openMap("flowsnoop_6_1")
	if err != nil {
		return err
	}
	return nil
}

func (ebpf *Ebpf3) updateMaps() error {
	var (
		next   uint32
		rm4    *goebpf.EbpfMap
		flows4 []flow.Sample4L
		keys4  [][]byte
		rm6    *goebpf.EbpfMap
		flows6 []flow.Sample6L
		keys6  [][]byte
	)
	if ebpf.curr {
		rm4 = ebpf.ipv4b
		rm6 = ebpf.ipv6b
		next = 0
	} else {
		rm4 = ebpf.ipv4a
		rm6 = ebpf.ipv6a
		next = 1
	}
	// Give time for eBPF update to finish on the
	// current map. This looks *plenty* of time.
	time.Sleep(10 * time.Millisecond)
	ebpf.curr = !ebpf.curr
	if err := ebpf.sw.Upsert(0, next); err != nil {
		return fmt.Errorf("map switch failed: %w", err)
	}
	// Handle IPv4 maps.
	k4 := make([]byte, 13)
	for {
		nk, err := rm4.GetNextKey(k4)
		if err != nil {
			break
		}
		data, err := rm4.Lookup(nk)
		if err != nil {
			return fmt.Errorf("ipv4 table lookup failed: %w", err)
		}
		var fl flow.Sample4
		if err := restruct.Unpack(nk, binary.BigEndian, &fl); err != nil {
			return fmt.Errorf("unpacking of ipv4 flow failed: %w", err)
		}
		flows4 = append(flows4, flow.Sample4L{
			Flow: fl,
			Tot:  binary.LittleEndian.Uint64(data),
		})
		keys4 = append(keys4, nk)
		k4 = nk
	}
	for _, k := range keys4 {
		if err := rm4.Delete(k); err != nil {
			return fmt.Errorf("deleting of ipv4 flow failed: %w", err)
		}
	}
	keys4 = nil
	// Handle IPv6 maps.
	k6 := make([]byte, 37)
	for {
		nk, err := rm6.GetNextKey(k6)
		if err != nil {
			break
		}
		data, err := rm6.Lookup(nk)
		if err != nil {
			return fmt.Errorf("ipv6 table lookup failed: %w", err)
		}
		var fl flow.Sample6
		if err := restruct.Unpack(nk, binary.BigEndian, &fl); err != nil {
			return fmt.Errorf("unpacking of ipv6 flow failed: %w", err)
		}
		flows6 = append(flows6, flow.Sample6L{
			Flow: fl,
			Tot:  binary.LittleEndian.Uint64(data),
		})
		keys6 = append(keys6, nk)
		k6 = nk
	}
	for _, k := range keys6 {
		if err := rm6.Delete(k); err != nil {
			return fmt.Errorf("deleting of ipv6 flow failed: %w", err)
		}
	}
	keys6 = nil
	// Push maps.
	if err := ebpf.consumer.Push(time.Now(), flows4, nil, flows6, nil); err != nil {
		return fmt.Errorf("error from consumer: %w\n", err)
	}
	return nil
}

func (ebpf *Ebpf3) Run(ctx context.Context, flush <-chan (chan<- error)) {
	go func() {
		defer close(ebpf.finished)
		for {
			var chErr chan<- error
			select {
			case <-ctx.Done():
				return
			case chErr = <-flush:
				break
			}
			chErr <- ebpf.updateMaps()
		}
	}()
}

func (ebpf *Ebpf3) Finalize() error {
	ebpf.sw.Close()
	ebpf.ipv4a.Close()
	ebpf.ipv4b.Close()
	ebpf.cleanup(true)
	<-ebpf.finished
	return nil
}

func New() *Ebpf3 {
	return &Ebpf3{
		finished: make(chan struct{}),
	}
}
