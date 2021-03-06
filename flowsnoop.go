package main

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
	"log"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/chripell/flowsnoop/afp"
	"github.com/chripell/flowsnoop/ebpf1"
	"github.com/chripell/flowsnoop/ebpf2"
	"github.com/chripell/flowsnoop/ebpf3"
	"github.com/chripell/flowsnoop/flow"
	"github.com/chripell/flowsnoop/showflows"
	"github.com/chripell/flowsnoop/sqlflows"
	"github.com/chripell/flowsnoop/topsites"
)

func main() {
	producers := map[string]flow.Producer{
		"ebpf1": ebpf1.New(),
		"ebpf2": ebpf2.New(),
		"ebpf3": ebpf3.New(),
		"afp":   afp.New(),
	}
	consumers := map[string]flow.Consumer{
		"topsites":  topsites.New(),
		"showflows": showflows.New(),
		"sqlflows":  sqlflows.New(),
	}
	every := flag.Duration("every", time.Duration(30)*time.Second, "Interval between display refreshes. ")
	var (
		producersL []string
		consumersL []string
	)
	for n := range producers {
		producersL = append(producersL, n)
	}
	for n := range consumers {
		consumersL = append(consumersL, n)
	}
	consumerS := flag.String("consumer", "topsites", "consumer module: "+strings.Join(consumersL, ","))
	producerS := flag.String("producer", "ebpf3", "producer module: "+strings.Join(producersL, ","))
	flag.Parse()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	fmt.Println("Press C-c to stop")

	consumer, ok := consumers[*consumerS]
	if !ok {
		log.Fatalf("No such consumer: %s", *consumerS)
	}
	producer, ok := producers[*producerS]
	if !ok {
		log.Fatalf("No such producer: %s", *producerS)
	}
	if err := consumer.Init(); err != nil {
		log.Fatalf("Consumer init failed: %v", err)
	}
	if err := producer.Init(consumer); err != nil {
		log.Fatalf("Producer init failed: %v", err)
	}
	dump := make(chan (chan<- error))
	ctx, cancel := context.WithCancel(context.Background())
	producer.Run(ctx, dump)
end_loop:
	for {
		select {
		case <-sig:
			break end_loop
		case <-time.After(*every):
			break
		}
		errCh := make(chan error)
		dump <- errCh
		if err := <-errCh; err != nil {
			log.Printf("Error from producer: %v", err)
			break
		}
	}
	cancel()
	if err := consumer.Finalize(); err != nil {
		log.Printf("Consumer finalization failed: %v", err)
	}
	if err := producer.Finalize(); err != nil {
		log.Printf("Producer finalization  failed: %v", err)
	}
}
