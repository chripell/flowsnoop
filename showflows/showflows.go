package showflows

import (
	"flag"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/chripell/flowsnoop/flow"
)

type ShowFlows struct {
	header string
}

var (
	header = flag.String("showflows_header", `---\n`, "print this string before every update, string is "+
		"unquoted so you can use \\f for reset to the top of the screen and \\n for new line.")
)

func (sh *ShowFlows) Init() error {
	sh.header = strings.Replace(*header, `\n`, "\n", -1)
	sh.header = strings.Replace(sh.header, `\f`,
		"\033[H\033[2J", -1)
	return nil
}

func (sh *ShowFlows) Push(tick time.Time,
	flowsL4 flow.List4, flowsM4 flow.Map4,
	flowsL6 flow.List6, flowsM6 flow.Map6) error {
	fmt.Print(sh.header)
	if len(flowsL4) > 0 {
		for _, fl := range flowsL4 {
			srcAddr := net.TCPAddr{
				IP:   net.IP(fl.Flow.SrcIP[:]),
				Port: int(fl.Flow.SrcPort),
			}
			dstAddr := net.TCPAddr{
				IP:   net.IP(fl.Flow.DstIP[:]),
				Port: int(fl.Flow.DstPort),
			}
			fmt.Printf("%s -> %s, %s: %d\n", srcAddr.String(), dstAddr.String(),
				flow.NewProto(fl.Flow.Proto), fl.Tot)
		}
	} else {
		for fl, tot := range flowsM4 {
			srcAddr := net.TCPAddr{
				IP:   net.IP(fl.SrcIP[:]),
				Port: int(fl.SrcPort),
			}
			dstAddr := net.TCPAddr{
				IP:   net.IP(fl.DstIP[:]),
				Port: int(fl.DstPort),
			}
			fmt.Printf("%s -> %s, %s: %d\n", srcAddr.String(), dstAddr.String(),
				flow.NewProto(fl.Proto), tot)
		}
	}
	return nil
}

func (sh *ShowFlows) Finalize() error {
	return nil
}

func New() *ShowFlows {
	return &ShowFlows{}
}
