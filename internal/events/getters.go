package events

import (
	"fmt"
	"strings"
)

func getCommonField(c *CommonEvent, name string) (interface{}, bool) {
	switch name {
	case "proc.pid":
		return int(c.Pid), true
	case "proc.ppid":
		return int(c.Ppid), true
	case "proc.uid":
		return int(c.Uid), true
	case "proc.gid":
		return int(c.Gid), true
	case "proc.cgroup":
		return int(c.CgroupId), true
	case "proc.name":
		return BytesToString(c.Comm[:]), true
	case "proc.pname":
		return BytesToString(c.Pcomm[:]), true
	}
	return nil, false
}

// --- OpenatEvent ---

func (e *OpenatEvent) GetType() string {
	return "openat"
}

func (e *OpenatEvent) GetField(name string) (interface{}, bool) {
	// Сначала ищем в специфичных полях
	switch name {
	case "fd.name", "evt.arg.filename":
		return BytesToString(e.Filename[:]), true
	case "evt.arg.flags":
		return int(e.Flags), true
	case "evt.res", "fd.num":
		return int(e.Ret), true // Если успех, ret = fd
	}
	// Если не нашли, ищем в общих
	return getCommonField(&e.Common, name)
}

// --- ExecveEvent ---

func (e *ExecveEvent) GetType() string {
	return "execve"
}

func (e *ExecveEvent) GetField(name string) (interface{}, bool) {
	switch name {
	case "proc.exepath", "evt.arg.filename":
		return BytesToString(e.Filename[:]), true
	case "proc.cmdline", "proc.args":
		// Склеиваем аргументы в одну строку
		args := ExtractArgs(e.Argv)
		return strings.Join(args, " "), true
	case "proc.env":
		envs := ExtractArgs(e.Envp)
		return strings.Join(envs, " "), true
	case "evt.res":
		return int(e.Ret), true
	}
	return getCommonField(&e.Common, name)
}

// --- ConnectEvent ---

func (e *ConnectEvent) GetType() string {
	return "connect"
}

func (e *ConnectEvent) GetField(name string) (interface{}, bool) {
	switch name {
	case "fd.num":
		return int(e.Fd), true
	case "fd.ip", "fd.sip": // Server IP
		return IntToIP(e.Ip), true
	case "fd.port", "fd.sport": // Server Port
		return int(Ntohs(e.Port)), true
	case "evt.res":
		return int(e.Ret), true
	}
	return getCommonField(&e.Common, name)
}

// --- AcceptEvent ---

func (e *AcceptEvent) GetType() string {
	return "accept"
}

func (e *AcceptEvent) GetField(name string) (interface{}, bool) {
	switch name {
	case "fd.num", "evt.res":
		return int(e.Ret), true // В accept возвращаемое значение - это новый FD
	case "fd.ip", "fd.rip": // Remote IP (клиента)
		return IntToIP(e.Ip), true
	case "fd.port", "fd.rport": // Remote Port
		return int(Ntohs(e.Port)), true
	}
	return getCommonField(&e.Common, name)
}

// --- PtraceEvent ---

func (e *PtraceEvent) GetType() string {
	return "ptrace"
}

func (e *PtraceEvent) GetField(name string) (interface{}, bool) {
	switch name {
	case "evt.arg.request":
		return int(e.Request), true
	case "proc.target_pid":
		return int(e.TargetPid), true
	case "evt.arg.addr":
		return fmt.Sprintf("0x%x", e.Addr), true // Адрес лучше отдавать строкой
	case "evt.res":
		return int(e.Ret), true
	}
	return getCommonField(&e.Common, name)
}
