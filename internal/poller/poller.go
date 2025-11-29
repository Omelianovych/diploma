package poller

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"

	"github.com/cilium/ebpf/ringbuf"
)

// EventParser описывает тип, который умеет "распаковать" себя из байтов.
// Мы используем указатель *T, чтобы метод Unmarshal мог менять данные.
type EventParser interface {
	Unmarshal(data []byte) error
}

// Start запускает бесконечный цикл чтения из RingBuffer.
// T - тип события (например, events.OpenatEvent)
// rd - откуда читать
// handler - функция, которая знает, что делать с готовым событием (из analyzer)
func Start[T any](rd *ringbuf.Reader, handler func(T)) {
	go func() {
		for {
			// 1. Блокирующее чтение
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return // Нормальное завершение
				}
				log.Printf("Poller error reading ringbuf: %v", err)
				continue
			}

			// 2. Создаем пустую структуру нашего типа T
			var event T

			// Нам нужно получить указатель на event, чтобы передать в binary.Read
			// В Go с дженериками это делается немного хитро, но binary.Read
			// принимает интерфейс, так что мы можем просто передать &event
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Poller parsing error: %v", err)
				continue
			}

			// 3. Отдаем в бизнес-логику (Analyzer)
			handler(event)
		}
	}()
}
