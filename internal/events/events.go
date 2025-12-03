package events

import (
	"bytes"
	"fmt"
	"strings"
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

// ExecveEvent обновился! Теперь Args это массив массивов.
// [6][42]byte соответствует char args[6][42] в C
type ExecveEvent struct {
	Common   CommonEvent
	Ret      int32
	Filename [128]byte
	Args     [6][42]byte
}

// --- Методы String() ---

func cleanString(data []byte) string {
	// Триммим нули справа
	n := bytes.IndexByte(data, 0)
	if n == -1 {
		return string(data)
	}
	return string(data[:n])
}

func (e OpenatEvent) String() string {
	comm := cleanString(e.Common.Comm[:])
	filename := cleanString(e.Filename[:])

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
	comm := cleanString(e.Common.Comm[:])
	filename := cleanString(e.Filename[:])

	// Собираем аргументы из массива в одну строку
	var argsList []string
	for _, argRaw := range e.Args {
		// Очищаем каждый аргумент от нулей
		argStr := cleanString(argRaw[:])
		if argStr != "" {
			argsList = append(argsList, argStr)
		}
	}
	args := strings.Join(argsList, " ")

	return fmt.Sprintf("[EXECVE] PID:%d COMM:%s EXEC:%s ARGS:%s",
		e.Common.Pid, comm, filename, args)
}
