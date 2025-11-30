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

type Analyzer struct {
	// В будущем здесь будут правила (rules)
}

func New() *Analyzer {
	return &Analyzer{}
}

// HandleOpenat - точка входа для обработки события
func (a *Analyzer) HandleOpenat(event events.OpenatEvent) {
	// 1. Нормализация: Очищаем имя файла и имя процесса от нуль-терминаторов
	rawFilename := string(bytes.TrimRight(event.Filename[:], "\x00"))
	comm := string(bytes.TrimRight(event.Comm[:], "\x00"))

	// 2. Обогащение: Пытаемся восстановить абсолютный путь
	absolutePath := a.resolvePath(event, rawFilename)

	// 3. Логирование результата
	// Выводим и сырой путь (как его видел процесс), и восстановленный (где он реально лежит)
	log.Printf("[Analyzer] PID:%d COMM:%s\n\tRaw Path:      %s\n\tResolved Path: %s\n\tStatus:        %s",
		event.Pid, comm, rawFilename, absolutePath, formatStatus(event.Ret))
}

// resolvePath превращает относительные пути в абсолютные, используя магию /proc
func (a *Analyzer) resolvePath(e events.OpenatEvent, filename string) string {
	// ВАРИАНТ А: Если операция прошла успешно (есть FD), спрашиваем у ядра
	// Ссылка /proc/PID/fd/FD всегда указывает на реальный файл
	if e.Ret >= 0 {
		linkPath := fmt.Sprintf("/proc/%d/fd/%d", e.Pid, e.Ret)
		if realPath, err := os.Readlink(linkPath); err == nil {
			return realPath
		}
	}

	// ВАРИАНТ Б: Если операция провалилась (Err) или файл уже закрыт
	// 1. Если путь уже абсолютный — возвращаем как есть
	if strings.HasPrefix(filename, "/") {
		return filename
	}

	// 2. Если путь относительный, читаем текущую директорию процесса (CWD)
	cwdLink := fmt.Sprintf("/proc/%d/cwd", e.Pid)
	if cwd, err := os.Readlink(cwdLink); err == nil {
		// Склеиваем CWD + Filename (например /etc + passwd)
		return filepath.Join(cwd, filename)
	}

	// 3. Если совсем ничего не помогло (процесс умер?)
	return fmt.Sprintf("UNKNOWN/%s", filename)
}

// Вспомогательная функция для красивого статуса
func formatStatus(ret int32) string {
	if ret < 0 {
		return fmt.Sprintf("BLOCKED (Err: %d)", ret)
	}
	return fmt.Sprintf("SUCCESS (FD: %d)", ret)
}
