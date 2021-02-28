package afp

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
	flows6   flow.Map6
}

func (h *Afp) newAfpacketHandle(device string, timeout time.Duration) error {

	var err error

	if device == "any" {
		h.TPacket, err = afpacket.NewTPacket(
			afpacket.OptPollTimeout(timeout),
			afpacket.SocketDgram,
			afpacket.TPacketVersion3)
	} else {
		h.TPacket, err = afpacket.NewTPacket(
			afpacket.OptPollTimeout(timeout),
			afpacket.OptInterface(device),
			afpacket.SocketDgram,
			afpacket.TPacketVersion3)
	}
	return err
}

func (h *Afp) ZeroCopyReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	return h.TPacket.ZeroCopyReadPacketData()
}

func (h *Afp) LinkType() layers.LinkType {
	return layers.LinkTypeNull
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
	h.flows6 = make(flow.Map6)
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
			ip4  layers.IPv4
			ip6  layers.IPv6
			tcp  layers.TCP
			udp  layers.UDP
		)
		source := gopacket.ZeroCopyPacketDataSource(h)
		parser4 := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4,
			&ip4, &tcp, &udp)
		parser6 := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6,
			&ip6, &tcp, &udp)
		parser4.IgnoreUnsupported = true
		parser6.IgnoreUnsupported = true
		decoded := make([]gopacket.LayerType, 0, 10)
		for {
			data, _, err = source.ZeroCopyReadPacketData()
			if err == nil {
				err := parser4.DecodeLayers(data, &decoded)
				if err == nil && hasLayer(decoded, layers.LayerTypeIPv4) {
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
				} else {
					err := parser6.DecodeLayers(data, &decoded)
					if err == nil && hasLayer(decoded, layers.LayerTypeIPv6) {
						s := flow.Sample6{
							Proto: uint8(ip6.NextHeader),
						}
						copy(s.SrcIP[:16], ip6.SrcIP)
						copy(s.DstIP[:16], ip6.DstIP)
						if hasLayer(decoded, layers.LayerTypeTCP) {
							s.SrcPort = uint16(tcp.SrcPort)
							s.DstPort = uint16(tcp.DstPort)
							s.Proto = 6
						} else if hasLayer(decoded, layers.LayerTypeUDP) {
							s.SrcPort = uint16(udp.SrcPort)
							s.DstPort = uint16(udp.DstPort)
							s.Proto = 17
						}
						h.flows6[s] += uint64(len(data))
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
					nil, h.flows6)
				h.flows4 = make(flow.Map4)
				h.flows6 = make(flow.Map6)
			default:
				break
			}
		}
	}()
}

func New() *Afp {
	return &Afp{}
}
