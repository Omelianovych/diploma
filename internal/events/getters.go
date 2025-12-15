package events

import (
	"fmt"
	"log"
	"strings"
	"syscall"
)

func decodeOpenFlags(flags int32) []string {
	var res []string
	f := int(flags)

	// Проверяем режим доступа (Access Mode)
	switch f & syscall.O_ACCMODE {
	case syscall.O_RDONLY:
		res = append(res, "O_RDONLY")
	case syscall.O_WRONLY:
		res = append(res, "O_WRONLY")
	case syscall.O_RDWR:
		res = append(res, "O_RDWR")
	}

	// Проверяем остальные флаги
	if f&syscall.O_CREAT != 0 {
		res = append(res, "O_CREAT")
	}
	if f&syscall.O_EXCL != 0 {
		res = append(res, "O_EXCL")
	}
	if f&syscall.O_NOCTTY != 0 {
		res = append(res, "O_NOCTTY")
	}
	if f&syscall.O_TRUNC != 0 {
		res = append(res, "O_TRUNC")
	}
	if f&syscall.O_APPEND != 0 {
		res = append(res, "O_APPEND")
	}
	if f&syscall.O_NONBLOCK != 0 {
		res = append(res, "O_NONBLOCK")
	}
	if f&syscall.O_DSYNC != 0 {
		res = append(res, "O_DSYNC")
	}
	if f&syscall.O_SYNC != 0 {
		res = append(res, "O_SYNC")
	}
	if f&syscall.O_CLOEXEC != 0 {
		res = append(res, "O_CLOEXEC")
	}

	return res
}

var ptraceRequests = map[uint64]string{
	0:  "PTRACE_TRACEME",
	1:  "PTRACE_PEEKTEXT",
	2:  "PTRACE_PEEKDATA",
	3:  "PTRACE_PEEKUSER",
	4:  "PTRACE_POKETEXT",
	5:  "PTRACE_POKEDATA",
	6:  "PTRACE_POKEUSER",
	7:  "PTRACE_CONT",
	8:  "PTRACE_KILL",
	9:  "PTRACE_SINGLESTEP",
	16: "PTRACE_ATTACH",
	17: "PTRACE_DETACH",
	24: "PTRACE_SYSCALL",

	0x4200: "PTRACE_SETOPTIONS",  // 16896
	0x4201: "PTRACE_GETEVENTMSG", // 16897
	0x4202: "PTRACE_GETSIGINFO",  // 16898
	0x4203: "PTRACE_SETSIGINFO",
	0x4206: "PTRACE_SEIZE",     // 16902
	0x4207: "PTRACE_INTERRUPT", // 16903
	0x4208: "PTRACE_LISTEN",    // 16904
	0x420E: "PTRACE_GETREGSET", // 16910
	0x420F: "PTRACE_SETREGSET",
}

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
	switch name {
	case "fd.name", "evt.arg.filename":
		return BytesToString(e.Filename[:]), true
	case "evt.arg.flags":
		flags := decodeOpenFlags(e.Flags)
		return strings.Join(flags, ","), true
	case "evt.res", "fd.num":
		return int(e.Ret), true
	}

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
		return int(e.Ret), true
	case "fd.ip", "fd.rip":
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
		if name, ok := ptraceRequests[e.Request]; ok {
			log.Printf("%s", name)
			return name, true
		}
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

func (e *MemfdEvent) GetType() string {
	return "memfd_create"
}

func (e *MemfdEvent) GetField(name string) (interface{}, bool) {
	switch name {
	case "evt.arg.name":
		return BytesToString(e.Name[:]), true
	case "evt.arg.flags":
		return int(e.Flags), true
	case "evt.res", "fd.num":
		return int(e.Ret), true
	}
	return getCommonField(&e.Common, name)
}

// --- ChmodEvent ---

func (e *ChmodEvent) GetType() string {
	return "chmod"
}

func (e *ChmodEvent) GetField(name string) (interface{}, bool) {
	switch name {
	case "fd.name", "evt.arg.filename":
		return BytesToString(e.Filename[:]), true
	case "evt.arg.mode":
		return fmt.Sprintf("0%o", e.Mode), true
	case "evt.res":
		return int(e.Ret), true
	}
	return getCommonField(&e.Common, name)
}
