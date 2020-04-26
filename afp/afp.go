package afp

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/chripell/flowsnoop/flow"
	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"

	_ "github.com/google/gopacket/layers"
)

var (
	iface = flag.String("afp_iface", "any", "Interface to read from")
)

type Afp struct {
	TPacket  *afpacket.TPacket
	finished chan struct{}
	consumer flow.Consumer
	flows4   flow.Map4
}

func (h *Afp) newAfpacketHandle(device string, timeout time.Duration) error {

	var err error

	if device == "any" {
		h.TPacket, err = afpacket.NewTPacket(
			afpacket.OptPollTimeout(timeout),
			afpacket.SocketRaw,
			afpacket.TPacketVersion3)
	} else {
		h.TPacket, err = afpacket.NewTPacket(
			afpacket.OptPollTimeout(timeout),
			afpacket.OptInterface(device),
			afpacket.SocketRaw,
			afpacket.TPacketVersion3)
	}
	return err
}

func (h *Afp) ZeroCopyReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	return h.TPacket.ZeroCopyReadPacketData()
}

func (h *Afp) LinkType() layers.LinkType {
	return layers.LinkTypeEthernet
}

// Close will close afpacket source.
func (h *Afp) Finalize() error {
	<-h.finished
	h.TPacket.Close()
	return nil
}

func (h *Afp) Init(consumer flow.Consumer) error {
	h.consumer = consumer
	h.finished = make(chan struct{})
	h.flows4 = make(flow.Map4)
	if err := h.newAfpacketHandle(*iface, time.Duration(100)*time.Millisecond); err != nil {
		return fmt.Errorf("afpacket library initialization failed: %w", err)
	}
	return nil
}

func hasLayer(layers []gopacket.LayerType, typ gopacket.LayerType) bool {
	for _, l := range layers {
		if l == typ {
			return true
		}
	}
	return false
}

func (h *Afp) Run(ctx context.Context, flush <-chan (chan<- error)) {
	go func() {
		defer close(h.finished)
		var (
			err  error
			data []byte
			eth  layers.Ethernet
			ip4  layers.IPv4
			ip6  layers.IPv6
			tcp  layers.TCP
			udp  layers.UDP
		)
		source := gopacket.ZeroCopyPacketDataSource(h)
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
			&eth, &ip4, &ip6, &tcp, &udp)
		parser.IgnoreUnsupported = true
		decoded := make([]gopacket.LayerType, 0, 10)
		for {
			data, _, err = source.ZeroCopyReadPacketData()
			if err == nil {
				err = parser.DecodeLayers(data, &decoded)
				if err == nil {
					if hasLayer(decoded, layers.LayerTypeIPv4) {
						s := flow.Sample4{
							Proto: uint8(ip4.Protocol),
						}
						copy(s.SrcIP[:4], ip4.SrcIP.To4())
						copy(s.DstIP[:4], ip4.DstIP.To4())
						if hasLayer(decoded, layers.LayerTypeTCP) {
							s.SrcPort = uint16(tcp.SrcPort)
							s.DstPort = uint16(tcp.DstPort)
						} else if hasLayer(decoded, layers.LayerTypeUDP) {
							s.SrcPort = uint16(udp.SrcPort)
							s.DstPort = uint16(udp.DstPort)
						}
						h.flows4[s] += uint64(len(data))
					}
				}
			}
			if err == afpacket.ErrTimeout {
				err = nil
			}
			for err != nil {
				select {
				case <-ctx.Done():
					return
				case chErr := <-flush:
					chErr <- err
				}
			}
			select {
			case <-ctx.Done():
				return
			case chErr := <-flush:
				chErr <- h.consumer.Push(time.Now(),
					nil, h.flows4,
					nil, nil)
				h.flows4 = make(flow.Map4)
			default:
				break
			}
		}
	}()
}

func New() *Afp {
	return &Afp{}
}
