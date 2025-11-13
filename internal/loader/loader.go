package bpf

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

// Предположим, что bpf2go сгенерировал типы: OpenatObjects и LoadOpenatObjects.
func LoadAndAttach() error {
	var objs OpenatObjects
	if err := LoadOpenatObjects(&objs, nil); err != nil {
		return fmt.Errorf("load objects: %w", err)
	}
	// Автоотключение при выходе
	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpenat, nil)
	if err != nil {
		return fmt.Errorf("attach tracepoint: %w", err)
	}
	// Пример ringbuf: (bpf2go создаст карту ringbuf "events" и поле Events)
	rd, err := perf.NewReader(objs.Events, os.Getpagesize()*8)
	if err != nil {
		tp.Close()
		return fmt.Errorf("new reader: %w", err)
	}

	// Читаем события в горутине
	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				fmt.Println("read error:", err)
				return
			}
			// распарсить record.RawSample в вашу структуру (см. сгенерированные типы)
			fmt.Printf("raw event len=%d\n", len(record.RawSample))
		}
	}()

	// Ожидаем сигнала для graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig

	rd.Close()
	tp.Close()
	objs.Close()
	return nil
}
