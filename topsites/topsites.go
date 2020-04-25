package topsites

import (
	"flag"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/chripell/flowsnoop/flow"
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
	m map[keyIP]*site
	l []*site
}

var (
	header = flag.String("topsites_header", "---\\n", "print this string before every update, string is "+
		"unquoted so you can use \\0x0c for reset to the top of the screen.")
	resolve = flag.Int("topsites_resolve", 5, "concurrent DNS resolutions. If 0, don't resolve IPs. ")
	topn    = flag.Int("topsites_n", 20, "Number of sites to show. ")
)

func (ts TopSites) Init() error {
	ts.m = make(map[keyIP]*site)
	return nil
}

func (ts TopSites) Push(tick time.Time,
	flowsL4 flow.List4, flowsM4 flow.Map4,
	flowsL6 flow.List6, flowsM6 flow.Map6) error {
	fmt.Print(*header)
	now := time.Now().Unix()
	if len(flowsL4) > 0 {
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
				ts.m[fkip] = &site{
					to:   fl.Tot,
					last: now,
				}
			}
		}
	} else {
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
				ts.m[fkip] = &site{
					to:   tot,
					last: now,
				}
			}
		}
	}
	if *resolve > 0 {
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
				si.resolved = addrs[0]
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
	for _, si := range ts.l[:l] {
		fmt.Printf("%s: from %d to %d\n", si.resolved, si.from, si.to)
	}
	ts.l = ts.l[:0]
	return nil
}

func (ts TopSites) Finalize() error {
	return nil
}

func New() *TopSites {
	return &TopSites{}
}
