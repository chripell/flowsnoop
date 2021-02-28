package flow

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
	Flow Sample6
	Tot  uint64
}

type Map6 map[Sample6]uint64

type List6 []Sample6L

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
