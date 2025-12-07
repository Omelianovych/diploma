package analyzer

import (
	"diploma/internal/events"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

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

	// --- Расширенные опции (Linux extended ptrace) ---
	0x4200: "PTRACE_SETOPTIONS",  // 16896
	0x4201: "PTRACE_GETEVENTMSG", // 16897
	0x4202: "PTRACE_GETSIGINFO",  // 16898
	0x4203: "PTRACE_SETSIGINFO",
	0x4206: "PTRACE_SEIZE",     // 16902
	0x4207: "PTRACE_INTERRUPT", // 16903
	0x4208: "PTRACE_LISTEN",    // 16904
	0x420E: "PTRACE_GETREGSET", // 16910 (Чтение регистров)
	0x420F: "PTRACE_SETREGSET", // (Запись регистров)
}

type Analyzer struct {
	Rules []Rule
}

// EnrichedEvent - обертка над событием, добавляющая вычисленные данные (absolutePath)
type EnrichedEvent struct {
	events.EventGetter // Встраиваем интерфейс (оригинальное событие)
	ResolvedPath       string
}

// GetField перехватывает запросы к полям пути.
// Если просят путь файла - возвращаем ResolvedPath.
// Все остальное перенаправляем в оригинальное событие.
func (e *EnrichedEvent) GetField(name string) (interface{}, bool) {
	switch name {
	// Для Openat
	case "fd.name", "evt.arg.filename":
		return e.ResolvedPath, true
	// Для Execve
	case "proc.exepath":
		return e.ResolvedPath, true
	}
	// Делегируем оригинальному событию
	return e.EventGetter.GetField(name)
}

// GetType просто вызывает метод оригинального события
func (e *EnrichedEvent) GetType() string {
	return e.EventGetter.GetType()
}

func New(rulesCfg RulesConfig) *Analyzer {
	return &Analyzer{
		Rules: rulesCfg.Rules,
	}
}

func (a *Analyzer) checkRules(evt events.EventGetter) {
	for _, rule := range a.Rules {
		if rule.CheckEvent(evt) {
			log.Printf("[ALERT] RULE MATCH: %s | Severity: %s | Payload: %s",
				rule.Name, rule.Severity, rule.Message)
		}
	}
}

// HandleOpenat - Обработка события открытия файла
func (a *Analyzer) HandleOpenat(event events.OpenatEvent) {
	// 1. Парсинг
	rawFilename := events.BytesToString(event.Filename[:])

	// 2. Обогащение (бизнес-логика)
	absolutePath := a.resolvePath(event.Common.Pid, event.Ret, rawFilename)

	// 3. Создаем Обогащенное событие
	enrichedEvt := &EnrichedEvent{
		EventGetter:  &event, // передаем указатель на struct, так как методы реализованы на *OpenatEvent
		ResolvedPath: absolutePath,
	}

	// 4. Проверка правил (передаем уже enrichedEvt)
	a.checkRules(enrichedEvt)

	// 5. Логирование (опционально, для отладки)
	// log.Printf("[OPENAT] File: %s", absolutePath)
}

// HandleExecve - Обработка события запуска процесса
func (a *Analyzer) HandleExecve(event events.ExecveEvent) {
	// 1. Парсинг
	rawFilename := events.BytesToString(event.Filename[:])

	// 2. Обогащение
	absolutePath := a.resolvePath(event.Common.Pid, -1, rawFilename)

	// 3. Создаем Обогащенное событие
	enrichedEvt := &EnrichedEvent{
		EventGetter:  &event,
		ResolvedPath: absolutePath,
	}

	// 4. Проверка правил
	a.checkRules(enrichedEvt)
}

func (a *Analyzer) HandleConnect(event events.ConnectEvent) {
	// Connect пока не требует обогащения пути, передаем как есть
	// Но передаем указатель, чтобы сработал интерфейс
	a.checkRules(&event)
}

func (a *Analyzer) HandleAccept(event events.AcceptEvent) {
	a.checkRules(&event)
}

func (a *Analyzer) HandlePtrace(event events.PtraceEvent) {
	a.checkRules(&event)
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
