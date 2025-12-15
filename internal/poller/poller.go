package poller

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"

	"github.com/cilium/ebpf/ringbuf"
)

type EventParser interface {
	Unmarshal(data []byte) error
}

func Start[T any](rd *ringbuf.Reader, handler func(T)) {
	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("Poller error reading ringbuf: %v", err)
				continue
			}

			var event T

			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Poller parsing error: %v", err)
				continue
			}

			handler(event)
		}
	}()
}
