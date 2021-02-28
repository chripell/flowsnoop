package showflows

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
	"flag"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/chripell/flowsnoop/flow"
)

type sflow struct {
	from, to, proto string
	n               uint64
}

type ShowFlows struct {
	header string
	flows  []sflow
}

var (
	header = flag.String("showflows_header", `---\n`, "print this string before every update, string is "+
		"unquoted so you can use \\f for reset to the top of the screen and \\n for new line.")
	sorted = flag.Bool("showflows_sorted", true, "sort flows by quantity of data")
)

func (sh *ShowFlows) Init() error {
	sh.header = strings.Replace(*header, `\n`, "\n", -1)
	sh.header = strings.Replace(sh.header, `\f`,
		"\033[H\033[2J", -1)
	return nil
}

func (sh *ShowFlows) appendFlow(srcIP []byte, srcPort uint16, dstIP []byte, dstPort uint16,
	proto uint8, tot uint64) {
	srcAddr := net.TCPAddr{
		IP:   net.IP(srcIP),
		Port: int(srcPort),
	}
	dstAddr := net.TCPAddr{
		IP:   net.IP(dstIP),
		Port: int(dstPort),
	}
	sh.flows = append(sh.flows, sflow{
		from:  srcAddr.String(),
		to:    dstAddr.String(),
		proto: flow.NewProto(proto).String(),
		n:     tot,
	})
}

func (sh *ShowFlows) Push(tick time.Time,
	flowsL4 flow.List4, flowsM4 flow.Map4,
	flowsL6 flow.List6, flowsM6 flow.Map6) error {
	fmt.Print(sh.header)
	for _, fl := range flowsL4 {
		sh.appendFlow(fl.Flow.SrcIP[:], fl.Flow.SrcPort,
			fl.Flow.DstIP[:], fl.Flow.DstPort, fl.Flow.Proto, fl.Tot)
	}
	for fl, tot := range flowsM4 {
		sh.appendFlow(fl.SrcIP[:], fl.SrcPort,
			fl.DstIP[:], fl.DstPort, fl.Proto, tot)
	}
	for _, fl := range flowsL6 {
		sh.appendFlow(fl.Flow.SrcIP[:], fl.Flow.SrcPort,
			fl.Flow.DstIP[:], fl.Flow.DstPort, fl.Flow.Proto, fl.Tot)
	}
	for fl, tot := range flowsM6 {
		sh.appendFlow(fl.SrcIP[:], fl.SrcPort,
			fl.DstIP[:], fl.DstPort, fl.Proto, tot)
	}
	sort.Slice(sh.flows, func(i, j int) bool {
		return sh.flows[i].n > sh.flows[j].n
	})
	for _, fl := range sh.flows {
		fmt.Printf("%s -> %s, %s: %d\n", fl.from, fl.to, fl.proto, fl.n)
	}
	sh.flows = sh.flows[:0]
	return nil
}

func (sh *ShowFlows) Finalize() error {
	return nil
}

func New() *ShowFlows {
	return &ShowFlows{}
}
