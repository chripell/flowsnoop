package main

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
	"github.com/chripell/flowsnoop/flow"
	"github.com/chripell/flowsnoop/showflows"
	"github.com/chripell/flowsnoop/topsites"
)

func main() {
	producers := map[string]flow.Producer{
		"ebpf1": ebpf1.New(),
		"afp":   afp.New(),
	}
	consumers := map[string]flow.Consumer{
		"topsites":  topsites.New(),
		"showflows": showflows.New(),
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
	producerS := flag.String("producer", "ebpf1", "producer module: "+strings.Join(consumersL, ","))
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
