package flow

import (
	"context"
	"time"
)

type Sample4 struct {
	SrcIP   [4]byte `struct:"[4]byte"`
	DstIP   [4]byte `struct:"[4]byte"`
	SrcPort uint16  `struct:"uint16"`
	DstPort uint16  `struct:"uint16"`
	Proto   uint8   `struct:"uint8"`
}

type Sample4L struct {
	Flow Sample4
	Tot  uint64
}

type Map4 map[Sample4]uint64

type List4 []Sample4L

type Sample6 struct {
	SrcIP   [16]byte `struct:"[16]byte"`
	DstIP   [16]byte `struct:"[16]byte"`
	SrcPort uint16   `struct:"uint16"`
	DstPort uint16   `struct:"uint16"`
	Proto   uint8    `struct:"uint8"`
}

type Sample6L struct {
	Flow Sample4
	Tot  uint64
}

type Map6 map[Sample4]uint64

type List6 []Sample4L

type Consumer interface {
	Init() error
	Push(time.Time,
		List4, Map4,
		List6, Map6) error
	Finalize() error
}

type Producer interface {
	Init(Consumer) error
	Run(context.Context, <-chan (chan<- error))
	Finalize() error
}

type Proto uint8

func NewProto(proto uint8) Proto {
	return Proto(proto)
}

func (p Proto) String() string {
	switch p {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 58:
		return "ICMP6"
	}
	return "UNKNOWN"
}
