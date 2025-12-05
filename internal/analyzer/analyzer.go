package analyzer

import (
	"diploma/internal/events"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

var ptraceRequests = map[int64]string{
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
}

type Analyzer struct{}

func New() *Analyzer {
	return &Analyzer{}
}

// HandleOpenat - Обработка события открытия файла
func (a *Analyzer) HandleOpenat(event events.OpenatEvent) {
	// 1. Парсинг (используем безопасный BytesToString из events)
	rawFilename := events.BytesToString(event.Filename[:])
	comm := events.BytesToString(event.Common.Comm[:])
	pcomm := events.BytesToString(event.Common.Pcomm[:])

	// 2. Обогащение (бизнес-логика)
	absolutePath := a.resolvePath(event.Common.Pid, event.Ret, rawFilename)

	// 3. Логирование (или подготовка данных для дальнейшей работы)
	log.Printf(
		"[OPENAT] CgroupID:%d PID:%d PPID:%d UID:%d GID:%d COMM:%s PCOMM:%s FLAGS:%d DFD:%d RET:%d RAW:%q PATH:%q",
		event.Common.CgroupId, event.Common.Pid, event.Common.Ppid,
		event.Common.Uid, event.Common.Gid,
		comm, pcomm,
		event.Flags, event.Dfd, event.Ret,
		rawFilename, absolutePath,
	)
}

// HandleExecve - Обработка события запуска процесса
func (a *Analyzer) HandleExecve(event events.ExecveEvent) {
	// 1. Парсинг
	rawFilename := events.BytesToString(event.Filename[:])
	comm := events.BytesToString(event.Common.Comm[:])
	pcomm := events.BytesToString(event.Common.Pcomm[:])

	// Используем перенесенный в events хелпер
	argv := strings.Join(events.ExtractArgs(event.Argv), " ")
	envp := strings.Join(events.ExtractArgs(event.Envp), " ")

	// 2. Обогащение
	absolutePath := a.resolvePath(event.Common.Pid, -1, rawFilename)

	// 3. Логирование
	log.Printf(
		"[EXECVE] CgroupID:%d PID:%d PPID:%d UID:%d GID:%d COMM:%s PCOMM:%s RET:%d RAW:%q PATH:%q ARGS:%s ENV:%s",
		event.Common.CgroupId, event.Common.Pid, event.Common.Ppid,
		event.Common.Uid, event.Common.Gid,
		comm, pcomm, event.Ret,
		rawFilename, absolutePath,
		argv, envp,
	)
}

func (a *Analyzer) HandleConnect(event events.ConnectEvent) {
	// 1. Парсинг
	comm := events.BytesToString(event.Common.Comm[:])
	pcomm := events.BytesToString(event.Common.Pcomm[:])
	ipStr := events.IntToIP(event.Ip)
	port := events.Ntohs(event.Port)

	// 3. Логирование
	log.Printf(
		"[CONNECT] CgroupID:%d PID:%d PPID:%d UID:%d GID:%d COMM:%s PCOMM:%s RET:%d FD:%d IP:%s PORT:%d",
		event.Common.CgroupId, event.Common.Pid, event.Common.Ppid,
		event.Common.Uid, event.Common.Gid,
		comm, pcomm,
		event.Ret, event.Fd,
		ipStr, port,
	)
}

func (a *Analyzer) HandleAccept(event events.AcceptEvent) {
	// 1. Парсинг
	comm := events.BytesToString(event.Common.Comm[:])
	ipStr := events.IntToIP(event.Ip)
	port := events.Ntohs(event.Port)

	// 3. Логирование
	log.Printf(
		"[ACCEPT] INBOUND CONNECTION -> PID:%d COMM:%s REMOTE_IP:%s REMOTE_PORT:%d SOCKET_FD:%d",
		event.Common.Pid, comm, ipStr, port, event.Ret,
	)
}

func (a *Analyzer) HandlePtrace(event events.PtraceEvent) {
	comm := events.BytesToString(event.Common.Comm[:])
	pcomm := events.BytesToString(event.Common.Pcomm[:])

	// Расшифровка кода запроса
	reqName, ok := ptraceRequests[event.Request]
	if !ok {
		reqName = fmt.Sprintf("UNKNOWN(%d)", event.Request)
	}

	// Формируем сообщение
	// Важно: PID - это тот КТО вызывает ptrace (атакующий или отладчик)
	// TargetPid - это ТОТ, КОГО атакуют
	log.Printf(
		"[PTRACE] CgroupID:%d PID:%d PPID:%d UID:%d GID:%d COMM:%s PCOMM:%s RET:%d REQUEST:%s(code=%d) TARGET_PID:%d ADDR:0x%x",
		event.Common.CgroupId,  // ID контрольной группы
		event.Common.Pid,       // PID того, кто атакует (tracer)
		event.Common.Ppid,      // PPID атакующего
		event.Common.Uid,       // UID атакующего
		event.Common.Gid,       // GID атакующего
		comm,                   // Имя процесса атакующего
		pcomm,                  // Имя родительского процесса атакующего
		event.Ret,              // Результат вызова (0 - успешно, <0 - ошибка)
		reqName, event.Request, // Расшифрованное и сырое имя запроса
		event.TargetPid, // PID жертвы (tracee)
		event.Addr,      // Адрес памяти (если применимо)
	)
}

// resolvePath - Универсальная логика получения абсолютного пути
func (a *Analyzer) resolvePath(pid uint32, fd int32, filename string) string {
	// 1. Если есть успешный дескриптор - пробуем взять путь из /proc/PID/fd/FD
	if fd >= 0 {
		linkPath := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
		if realPath, err := os.Readlink(linkPath); err == nil {
			return realPath
		}
	}

	// 2. Если путь уже абсолютный
	if strings.HasPrefix(filename, "/") {
		return filename
	}

	// 3. Если путь относительный - склеиваем с CWD процесса
	cwdLink := fmt.Sprintf("/proc/%d/cwd", pid)
	if cwd, err := os.Readlink(cwdLink); err == nil {
		return filepath.Join(cwd, filename)
	}

	// 4. Fallback
	return fmt.Sprintf("UNKNOWN/%s", filename)
}
