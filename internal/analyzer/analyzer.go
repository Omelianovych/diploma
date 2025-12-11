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

type EnrichedEvent struct {
	events.EventGetter // интерфейс (оригинальное событие)
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
	return e.EventGetter.GetField(name)
}

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

func (a *Analyzer) HandleOpenat(event events.OpenatEvent) {
	rawFilename := events.BytesToString(event.Filename[:])

	absolutePath := a.resolvePath(event.Common.Pid, event.Ret, rawFilename)

	enrichedEvt := &EnrichedEvent{
		EventGetter:  &event,
		ResolvedPath: absolutePath,
	}

	a.checkRules(enrichedEvt)

	// log.Printf("[OPENAT] File: %s", absolutePath)
}

func (a *Analyzer) HandleExecve(event events.ExecveEvent) {
	rawFilename := events.BytesToString(event.Filename[:])

	absolutePath := a.resolvePath(event.Common.Pid, -1, rawFilename)

	enrichedEvt := &EnrichedEvent{
		EventGetter:  &event,
		ResolvedPath: absolutePath,
	}

	a.checkRules(enrichedEvt)
}

func (a *Analyzer) HandleConnect(event events.ConnectEvent) {
	a.checkRules(&event)
}

func (a *Analyzer) HandleAccept(event events.AcceptEvent) {
	a.checkRules(&event)
}

func (a *Analyzer) HandlePtrace(event events.PtraceEvent) {
	a.checkRules(&event)
}

func (a *Analyzer) HandleMemfd(event events.MemfdEvent) {
	name := events.BytesToString(event.Name[:])
	log.Printf("[DEBUG] MEMFD_CREATE: Pid=%d Name='%s' Flags=%d RetFD=%d",
		event.Common.Pid, name, event.Flags, event.Ret)
	a.checkRules(&event)
}

func (a *Analyzer) HandleChmod(event events.ChmodEvent) {
	rawFilename := events.BytesToString(event.Filename[:])

	absolutePath := a.resolvePath(event.Common.Pid, -1, rawFilename)

	log.Printf("[DEBUG] CHMOD: Pid=%d File=%s Mode=0%o",
		event.Common.Pid, absolutePath, event.Mode)

	enrichedEvt := &EnrichedEvent{
		EventGetter:  &event,
		ResolvedPath: absolutePath,
	}
	a.checkRules(enrichedEvt)
}

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
