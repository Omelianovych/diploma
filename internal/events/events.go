package events

import (
	"bytes"
	"encoding/binary"
	"net"
)

type EventGetter interface {
	GetType() string
	GetField(name string) (interface{}, bool)
}

type CommonEvent struct {
	CgroupId uint64
	Pid      uint32
	Ppid     uint32
	Uid      uint32
	Gid      uint32
	Comm     [16]byte
	Pcomm    [16]byte
}

type OpenatEvent struct {
	Common   CommonEvent
	Flags    int32
	Dfd      int32
	Ret      int32
	Filename [128]byte
}

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
	Ip     uint32
	Port   uint16
}

type AcceptEvent struct {
	Common CommonEvent
	Ret    int32
	Ip     uint32
	Port   uint16
}

type PtraceEvent struct {
	Common    CommonEvent
	Ret       int32
	Pad       int32
	Request   uint64
	TargetPid int32
	Pad2      int32
	Addr      uint64
}

type MemfdEvent struct {
	Common CommonEvent
	Ret    int32 // FD
	Flags  uint32
	Name   [128]byte
}

type ChmodEvent struct {
	Common   CommonEvent
	Ret      int32
	Mode     uint32
	Filename [128]byte
}

// --- String() ---

func BytesToString(data []byte) string {
	n := bytes.IndexByte(data, 0)
	if n == -1 {
		return string(data)
	}
	return string(data[:n])
}

func IntToIP(nn uint32) string {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, nn)
	return ip.String()
}

func Ntohs(port uint16) uint16 {
	return (port<<8)&0xff00 | (port>>8)&0x00ff
}

func ExtractArgs(raw [24][64]byte) []string {
	var res []string
	for _, chunk := range raw {
		str := BytesToString(chunk[:])
		if str != "" {
			res = append(res, str)
		}
	}
	return res
}
