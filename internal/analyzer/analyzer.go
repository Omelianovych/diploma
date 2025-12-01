package analyzer

import (
	"bytes"
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

// HandleOpenat - Обработка события
func (a *Analyzer) HandleOpenat(event events.OpenatEvent) {
	// 1. Нормализация строк
	rawFilename := string(bytes.TrimRight(event.Filename[:], "\x00"))
	comm := string(bytes.TrimRight(event.Comm[:], "\x00"))

	// 2. Резолвинг пути (Обогащение)
	absolutePath := a.resolvePath(event, rawFilename)

	// 3. Простой лог со ВСЕЙ информацией в одну строку
	// Формат: КЛЮЧ:ЗНАЧЕНИЕ
	log.Printf("[OPENAT] PID:%d PPID:%d UID:%d GID:%d CGROUP:%d COMM:%s PCOMM:%s DFD:%d FLAGS:%d RET:%d RAW:%s PATH:%s",
		event.Pid,
		event.Ppid,
		event.Uid,
		event.Gid,
		event.CgroupId,
		comm,
		event.Pcomm,
		event.Dfd,
		event.Flags,
		event.Ret,
		rawFilename,
		absolutePath,
	)
}

// resolvePath - логика получения абсолютного пути
func (a *Analyzer) resolvePath(e events.OpenatEvent, filename string) string {
	// 1. Если есть успешный дескриптор - берем путь из ядра
	if e.Ret >= 0 {
		linkPath := fmt.Sprintf("/proc/%d/fd/%d", e.Pid, e.Ret)
		if realPath, err := os.Readlink(linkPath); err == nil {
			return realPath
		}
	}

	// 2. Если путь уже абсолютный
	if strings.HasPrefix(filename, "/") {
		return filename
	}

	// 3. Если путь относительный - склеиваем с CWD
	cwdLink := fmt.Sprintf("/proc/%d/cwd", e.Pid)
	if cwd, err := os.Readlink(cwdLink); err == nil {
		return filepath.Join(cwd, filename)
	}

	// 4. Не удалось определить
	return fmt.Sprintf("UNKNOWN/%s", filename)
}
