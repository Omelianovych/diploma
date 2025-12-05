package events

import (
	"bytes"
	"encoding/binary"
	"net"
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

type AcceptEvent struct {
	Common CommonEvent
	Ret    int32 // Это будет File Descriptor нового сокета
	Ip     uint32
	Port   uint16
}

type PtraceEvent struct {
	Common    CommonEvent
	Ret       int32
	Request   int64 // long в C это обычно 64 бит на 64-бит системах
	TargetPid int32
	Addr      uint64
}

// --- Методы String() ---

func BytesToString(data []byte) string {
	n := bytes.IndexByte(data, 0)
	if n == -1 {
		return string(data)
	}
	return string(data[:n])
}

// IntToIP - Конвертация uint32 в строку IP
func IntToIP(nn uint32) string {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, nn)
	return ip.String()
}

// Ntohs - Конвертация порта (Network to Host Short)
func Ntohs(port uint16) uint16 {
	return (port<<8)&0xff00 | (port>>8)&0x00ff
}

// ExtractArgs - Извлекает строки из фиксированного массива массивов байт
func ExtractArgs(raw [24][64]byte) []string {
	var res []string
	for _, chunk := range raw {
		// Используем наш правильный метод очистки строки
		str := BytesToString(chunk[:])
		if str != "" {
			res = append(res, str)
		}
	}
	return res
}
