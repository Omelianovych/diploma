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

// HandleOpenat - Обработка события открытия файла
func (a *Analyzer) HandleOpenat(event events.OpenatEvent) {
	// 1. Нормализация строк
	rawFilename := string(bytes.TrimRight(event.Filename[:], "\x00"))
	comm := string(bytes.TrimRight(event.Common.Comm[:], "\x00"))
	pcomm := string(bytes.TrimRight(event.Common.Pcomm[:], "\x00"))

	// 2. Резолвинг пути (Обогащение)
	absolutePath := a.resolvePath(event.Common.Pid, event.Ret, rawFilename)

	// 3. Лог
	log.Printf(
		"[OPENAT] CgroupID:%d PID:%d PPID:%d UID:%d GID:%d COMM:%s PCOMM:%s FLAGS:%d DFD:%d RET:%d RAW:%q PATH:%q",
		event.Common.CgroupId,
		event.Common.Pid,
		event.Common.Ppid,
		event.Common.Uid,
		event.Common.Gid,
		comm,
		pcomm,
		event.Flags,
		event.Dfd,
		event.Ret,
		rawFilename,
		absolutePath,
	)
}

// HandleExecve - Обработка события запуска процесса
// func (a *Analyzer) HandleExecve(event events.ExecveEvent) {
// 	// 1. Нормализация строк
// 	// В execve Filename - это путь к исполняемому файлу
// 	rawFilename := string(bytes.TrimRight(event.Filename[:], "\x00"))
// 	comm := string(bytes.TrimRight(event.Common.Comm[:], "\x00"))   // Кто запускал (старое имя)
// 	pcomm := string(bytes.TrimRight(event.Common.Pcomm[:], "\x00")) // Родитель
//
// 	argsRaw := bytes.TrimRight(event.Args[:], "\x00")
// 	args := string(bytes.ReplaceAll(argsRaw, []byte{0}, []byte{' '}))
//
// 	// 2. Резолвинг пути
// 	// Для execve FD не возвращается как результат (там 0 при успехе),
// 	// поэтому передаем -1 вместо file descriptor, чтобы resolvePath использовал только CWD логику
// 	absolutePath := a.resolvePath(event.Common.Pid, -1, rawFilename)
//
// 	// 3. Лог
// 	log.Printf(
// 		"[EXECVE] CgroupID:%d PID:%d PPID:%d UID:%d GID:%d COMM:%s PCOMM:%s RET:%d RAW:%q PATH:%q ARGS:%s",
// 		event.Common.CgroupId,
// 		event.Common.Pid,
// 		event.Common.Ppid,
// 		event.Common.Uid,
// 		event.Common.Gid,
// 		comm,
// 		pcomm,
// 		event.Ret,
// 		rawFilename,
// 		absolutePath,
// 		args,
// 	)
// }

func (a *Analyzer) HandleExecve(event events.ExecveEvent) {
	// 1. Нормализация строк
	// В execve Filename - это путь к исполняемому файлу
	rawFilename := string(bytes.TrimRight(event.Filename[:], "\x00"))
	comm := string(bytes.TrimRight(event.Common.Comm[:], "\x00"))   // Кто запускал (старое имя)
	pcomm := string(bytes.TrimRight(event.Common.Pcomm[:], "\x00")) // Родитель

	// --- НОВАЯ ЛОГИКА ДЛЯ ARGS ---
	// Раньше: argsRaw := bytes.TrimRight(event.Args[:], "\x00") ...
	// Теперь: event.Args это массив [6][42]byte. Распаковываем его:
	var argsList []string
	for _, chunk := range event.Args {
		// Ищем конец строки (нулевой байт) внутри чанка
		n := bytes.IndexByte(chunk[:], 0)
		if n == -1 {
			n = len(chunk)
		}
		// Если чанк пустой (начинается с 0), значит аргументов больше нет
		if n == 0 {
			continue
		}
		argsList = append(argsList, string(chunk[:n]))
	}
	// Собираем в строку через пробел для лога
	args := strings.Join(argsList, " ")
	// -----------------------------

	// 2. Резолвинг пути
	// Для execve FD не возвращается как результат (там 0 при успехе),
	// поэтому передаем -1 вместо file descriptor.
	// (Предполагается, что метод resolvePath определен в rules.go или другом файле пакета analyzer)
	absolutePath := a.resolvePath(event.Common.Pid, -1, rawFilename)

	// 3. Лог
	log.Printf(
		"[EXECVE] CgroupID:%d PID:%d PPID:%d UID:%d GID:%d COMM:%s PCOMM:%s RET:%d RAW:%q PATH:%q ARGS:%s",
		event.Common.CgroupId,
		event.Common.Pid,
		event.Common.Ppid,
		event.Common.Uid,
		event.Common.Gid,
		comm,
		pcomm,
		event.Ret,
		rawFilename,
		absolutePath,
		args,
	)
}

// resolvePath - Универсальная логика получения абсолютного пути
// pid - ID процесса
// fd - файловый дескриптор (если есть, иначе -1)
// filename - исходное имя файла (может быть относительным)
func (a *Analyzer) resolvePath(pid uint32, fd int32, filename string) string {
	// 1. Если есть успешный дескриптор (для openat) - пробуем взять путь из /proc/PID/fd/FD
	if fd >= 0 {
		linkPath := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
		if realPath, err := os.Readlink(linkPath); err == nil {
			return realPath
		}
	}

	// 2. Если путь уже абсолютный, возвращаем как есть
	if strings.HasPrefix(filename, "/") {
		return filename
	}

	// 3. Если путь относительный - склеиваем с CWD процесса
	cwdLink := fmt.Sprintf("/proc/%d/cwd", pid)
	if cwd, err := os.Readlink(cwdLink); err == nil {
		return filepath.Join(cwd, filename)
	}

	// 4. Если не удалось определить контекст
	return fmt.Sprintf("UNKNOWN/%s", filename)
}
