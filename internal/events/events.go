package events

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// OpenatEvent должна байт-в-байт совпадать с C-структурой.
type OpenatEvent struct {
	Pid      uint32
	Flags    int32
	Comm     [16]byte
	Filename [256]byte
}

// Unmarshal превращает сырые байты из ядра в структуру Go.
// Мы вынесли это из main.go, чтобы инкапсулировать логику бинарного чтениия.
func (e *OpenatEvent) Unmarshal(data []byte) error {
	return binary.Read(bytes.NewReader(data), binary.LittleEndian, e)
}

// String реализует интерфейс Stringer для красивого вывода (замена функции printEvent).
func (e OpenatEvent) String() string {
	// Очищаем C-строки от нуль-терминаторов
	comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
	filename := string(bytes.TrimRight(e.Filename[:], "\x00"))

	return fmt.Sprintf("PID:%d Comm:%s File:%s Flags:%d", e.Pid, comm, filename, e.Flags)
}
