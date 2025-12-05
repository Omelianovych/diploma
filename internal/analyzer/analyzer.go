package analyzer

import (
	"diploma/internal/events"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

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
