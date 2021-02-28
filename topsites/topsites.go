package topsites

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
	"sync"
	"time"

	"github.com/chripell/flowsnoop/flow"
	humanize "github.com/dustin/go-humanize"
)

type site struct {
	resolved string
	from     uint64
	to       uint64
	last     int64
}

type keyIP [16]byte

var prefixIP4 = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0}

func newKIP4(ip []byte) keyIP {
	kip := prefixIP4
	copy(kip[12:16], ip[0:4])
	return kip
}

type TopSites struct {
	header string
	m      map[keyIP]*site
	l      []*site
}

var (
	header = flag.String("topsites_header", `---\n`, "print this string before every update, string is "+
		"unquoted so you can use \\f for reset to the top of the screen and \\n for new line.")
	resolve = flag.Int("topsites_resolve", 5, "concurrent DNS resolutions. If 0, don't resolve IPs. ")
	topn    = flag.Int("topsites_n", 20, "Number of sites to show. ")
	pretty  = flag.Bool("topsites_pretty", true, "Pretty print numbers.")
)

func (ts *TopSites) Init() error {
	ts.header = strings.Replace(*header, `\n`, "\n", -1)
	ts.header = strings.Replace(ts.header, `\f`,
		"\033[H\033[2J", -1)
	ts.m = make(map[keyIP]*site)
	return nil
}

func (ts *TopSites) Push(tick time.Time,
	flowsL4 flow.List4, flowsM4 flow.Map4,
	flowsL6 flow.List6, flowsM6 flow.Map6) error {
	fmt.Print(ts.header)
	now := time.Now().Unix()
	for _, fl := range flowsL4 {
		fkip := newKIP4(fl.Flow.SrcIP[:])
		if s := ts.m[fkip]; s != nil {
			s.from += fl.Tot
			s.last = now
		} else {
			ts.m[fkip] = &site{
				from: fl.Tot,
				last: now,
			}
		}
		tkip := newKIP4(fl.Flow.DstIP[:])
		if s := ts.m[tkip]; s != nil {
			s.to += fl.Tot
			s.last = now
		} else {
			ts.m[tkip] = &site{
				to:   fl.Tot,
				last: now,
			}
		}
	}
	for fl, tot := range flowsM4 {
		fkip := newKIP4(fl.SrcIP[:])
		if s := ts.m[fkip]; s != nil {
			s.from += tot
			s.last = now
		} else {
			ts.m[fkip] = &site{
				from: tot,
				last: now,
			}
		}
		tkip := newKIP4(fl.DstIP[:])
		if s := ts.m[tkip]; s != nil {
			s.to += tot
			s.last = now
		} else {
			ts.m[tkip] = &site{
				to:   tot,
				last: now,
			}
		}
	}
	for _, fl := range flowsL6 {
		if s := ts.m[fl.Flow.SrcIP]; s != nil {
			s.from += fl.Tot
			s.last = now
		} else {
			ts.m[fl.Flow.SrcIP] = &site{
				from: fl.Tot,
				last: now,
			}
		}
		if s := ts.m[fl.Flow.DstIP]; s != nil {
			s.to += fl.Tot
			s.last = now
		} else {
			ts.m[fl.Flow.DstIP] = &site{
				to:   fl.Tot,
				last: now,
			}
		}
	}
	for fl, tot := range flowsM6 {
		if s := ts.m[fl.SrcIP]; s != nil {
			s.from += tot
			s.last = now
		} else {
			ts.m[fl.SrcIP] = &site{
				from: tot,
				last: now,
			}
		}
		if s := ts.m[fl.DstIP]; s != nil {
			s.to += tot
			s.last = now
		} else {
			ts.m[fl.DstIP] = &site{
				to:   tot,
				last: now,
			}
		}
	}
	if *resolve <= 0 {
		for kip, site := range ts.m {
			if site.resolved == "" {
				ip := net.IP(kip[:])
				site.resolved = ip.String()
			}
		}
	} else {
		tokens := make(chan struct{}, *resolve)
		var wg sync.WaitGroup
		for kip, si := range ts.m {
			if si.resolved != "" {
				continue
			}
			tokens <- struct{}{}
			wg.Add(1)
			go func(kip keyIP, si *site) {
				defer func() {
					wg.Done()
					<-tokens
				}()
				ip := net.IP(kip[:])
				ips := ip.String()
				addrs, err := net.LookupAddr(ips)
				if err != nil {
					si.resolved = ips
					return
				}
				si.resolved = strings.TrimRight(addrs[0], ".")
			}(kip, si)
		}
		wg.Wait()
	}
	for _, si := range ts.m {
		ts.l = append(ts.l, si)
	}
	sort.Slice(ts.l, func(i, j int) bool {
		if ts.l[i].from+ts.l[i].to > ts.l[j].from+ts.l[j].to {
			return true
		}
		return false
	})
	l := len(ts.l)
	if l > *topn {
		l = *topn
	}
	if *pretty {
		for _, si := range ts.l[:l] {
			fmt.Printf("%s: from %s to %s\n", si.resolved, humanize.Bytes(si.from), humanize.Bytes(si.to))
		}
	} else {
		for _, si := range ts.l[:l] {
			fmt.Printf("%s: from %d to %d\n", si.resolved, si.from, si.to)
		}
	}
	ts.l = ts.l[:0]
	return nil
}

func (ts *TopSites) Finalize() error {
	return nil
}

func New() *TopSites {
	return &TopSites{}
}
