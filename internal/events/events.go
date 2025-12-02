package events

import (
	"bytes"
	"fmt"
)

// CommonEvent - общая часть для всех событий (должна совпадать с C struct common_event)
type CommonEvent struct {
	CgroupId uint64
	Pid      uint32
	Ppid     uint32
	Uid      uint32
	Gid      uint32
	Comm     [16]byte
	Pcomm    [16]byte
}

// OpenatEvent (должна совпадать с C struct openat_event)
type OpenatEvent struct {
	Common   CommonEvent
	Flags    int32
	Dfd      int32
	Ret      int32
	Filename [128]byte
}

// ExecveEvent (должна совпадать с C struct execve_event)
type ExecveEvent struct {
	Common   CommonEvent
	Ret      int32
	Filename [128]byte
	Args     [4096]byte
}

// --- Методы String() ---
func cleanString(data []byte) string {
	// 1. Находим первый нулевой байт, чтобы отсечь хвост
	n := bytes.IndexByte(data, 0)
	if n == -1 {
		n = len(data)
	}
	// Но wait! У нас аргументы разделены нулями: "arg1\0arg2\0\0..."
	// Поэтому мы ищем ДВОЙНОЙ ноль или конец данных, либо просто заменяем все нули.

	// Правильный подход для Args:
	// Триммим правые нули
	trimmed := bytes.TrimRight(data, "\x00")
	// Заменяем оставшиеся нули (разделители) на пробелы
	return string(bytes.ReplaceAll(trimmed, []byte{0}, []byte{' '}))
}

func (e OpenatEvent) String() string {
	comm := string(bytes.TrimRight(e.Common.Comm[:], "\x00"))
	filename := string(bytes.TrimRight(e.Filename[:], "\x00"))

	status := "SUCCESS"
	if e.Ret < 0 {
		status = fmt.Sprintf("ERR:%d", e.Ret)
	} else {
		status = fmt.Sprintf("FD:%d", e.Ret)
	}

	return fmt.Sprintf("[OPENAT] PID:%d COMM:%s FILE:%s RET:%s",
		e.Common.Pid, comm, filename, status)
}

func (e ExecveEvent) String() string {
	comm := string(bytes.TrimRight(e.Common.Comm[:], "\x00"))
	filename := string(bytes.TrimRight(e.Filename[:], "\x00"))

	// Используем новую логику очистки для аргументов
	args := cleanString(e.Args[:])

	return fmt.Sprintf("[EXECVE] PID:%d COMM:%s EXEC:%s ARGS:%s",
		e.Common.Pid, comm, filename, args)
}
