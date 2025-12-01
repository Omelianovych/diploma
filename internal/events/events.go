package events

import (
	"bytes"
	"fmt"
)

// OpenatEvent должна байт-в-байт совпадать с C-структурой.
type OpenatEvent struct {
	CgroupId uint64   // 8 байт
	Pid      uint32   // 4 байта
	Ppid     uint32   // 4 байта
	Uid      uint32   // 4 байта
	Gid      uint32   // 4 байта
	Flags    int32    // 4 байта
	Dfd      int32    // 4 байта
	Ret      int32    // 4 байта (Результат)
	Comm     [16]byte // 16 байт
	Pcomm    [16]byte
	Filename [256]byte
}

func (e OpenatEvent) String() string {
	comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
	filename := string(bytes.TrimRight(e.Filename[:], "\x00"))

	// Пример вывода: [PID:123 UID:0] (ret:3) openat(filename)
	status := "SUCCESS"
	if e.Ret < 0 {
		status = fmt.Sprintf("ERR:%d", e.Ret)
	} else {
		status = fmt.Sprintf("FD:%d", e.Ret)
	}

	return fmt.Sprintf("PID:%d UID:%d GID:%d CGROUP:%d COMM:%s DFD:%d FLAGS:%d FILE:%s RET:%s",
		e.Pid, e.Uid, e.Gid, e.CgroupId, comm, e.Dfd, e.Flags, filename, status)
}
