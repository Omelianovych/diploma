package events

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
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
	Argv     [24][64]byte
	Envp     [24][64]byte
}

type ConnectEvent struct {
	Common CommonEvent
	Ret    int32
	Fd     int32
	Ip     uint32 // IPv4 в формате u32
	Port   uint16 // Порт (Network Byte Order)
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

func int2ip(nn uint32) string {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, nn)
	return ip.String()
}

// Helper для конвертации порта (Big Endian -> Little Endian/Host)
func ntohs(port uint16) uint16 {
	return (port<<8)&0xff00 | (port>>8)&0x00ff
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

	// Собираем аргументы из массива Argv
	var argsList []string
	for _, argRaw := range e.Argv {
		argStr := cleanString(argRaw[:])
		if argStr != "" {
			argsList = append(argsList, argStr)
		}
	}
	args := strings.Join(argsList, " ")

	return fmt.Sprintf("[EXECVE] PID:%d COMM:%s EXEC:%s ARGS:%s",
		e.Common.Pid, comm, filename, args)
}

func (e ConnectEvent) String() string {
	comm := cleanString(e.Common.Comm[:])
	ipStr := int2ip(e.Ip)
	port := ntohs(e.Port) // Переворачиваем порт для человеческого вида

	status := "SUCCESS"
	if e.Ret < 0 {
		status = fmt.Sprintf("ERR:%d", e.Ret) // Например -115 (EINPROGRESS) - это нормально для неблокирующих сокетов
	}

	return fmt.Sprintf("[CONNECT] PID:%d COMM:%s ADDR:%s:%d RET:%s",
		e.Common.Pid, comm, ipStr, port, status)
}
