package analyzer

import (
	"diploma/internal/events"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type Analyzer struct {
	Rules []Rule
}

type EnrichedEvent struct {
	events.EventGetter
	ResolvedPath string
}

func (e *EnrichedEvent) GetField(name string) (interface{}, bool) {
	switch name {
	case "fd.name", "evt.arg.filename":
		return e.ResolvedPath, true
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
			procName, _ := evt.GetField("proc.name")
			pid, _ := evt.GetField("proc.pid")

			var target string

			switch evt.GetType() {
			case "openat", "chmod":
				if val, ok := evt.GetField("evt.arg.filename"); ok {
					target = fmt.Sprintf("File: %v", val)
				}
			case "execve":
				if val, ok := evt.GetField("proc.cmdline"); ok {
					cmd := fmt.Sprintf("%v", val)
					if len(cmd) > 50 {
						cmd = cmd[:47] + "..."
					}
					target = fmt.Sprintf("Cmd: %s", cmd)
				}
			case "connect", "accept":
				ip, _ := evt.GetField("fd.ip")
				port, _ := evt.GetField("fd.port")
				target = fmt.Sprintf("Net: %v:%v", ip, port)
			case "ptrace":
				req, _ := evt.GetField("evt.arg.request")
				tpid, _ := evt.GetField("proc.target_pid")
				target = fmt.Sprintf("Req: %v -> TargetPid: %v", req, tpid)
			case "memfd_create":
				name, _ := evt.GetField("evt.arg.name")
				target = fmt.Sprintf("MemfdName: %v", name)
			}

			log.Printf("[ALERT] %s [%s] | Msg: %s | Proc: %v(%v) | %s",
				rule.Name, rule.Severity, rule.Message, procName, pid, target)
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
	// name := events.BytesToString(event.Name[:])
	// log.Printf("[DEBUG] MEMFD_CREATE: Pid=%d Name='%s' Flags=%d RetFD=%d",
	// 	event.Common.Pid, name, event.Flags, event.Ret)
	a.checkRules(&event)
}

func (a *Analyzer) HandleChmod(event events.ChmodEvent) {
	rawFilename := events.BytesToString(event.Filename[:])

	absolutePath := a.resolvePath(event.Common.Pid, -1, rawFilename)

	// log.Printf("[DEBUG] CHMOD: Pid=%d File=%s Mode=0%o",
	// 	event.Common.Pid, absolutePath, event.Mode)

	enrichedEvt := &EnrichedEvent{
		EventGetter:  &event,
		ResolvedPath: absolutePath,
	}
	a.checkRules(enrichedEvt)
}

func (a *Analyzer) resolvePath(pid uint32, fd int32, filename string) string {
	if fd >= 0 {
		linkPath := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
		if realPath, err := os.Readlink(linkPath); err == nil {
			return realPath
		}
	}

	if strings.HasPrefix(filename, "/") {
		return filename
	}

	cwdLink := fmt.Sprintf("/proc/%d/cwd", pid)
	if cwd, err := os.Readlink(cwdLink); err == nil {
		return filepath.Join(cwd, filename)
	}

	return fmt.Sprintf("UNKNOWN/%s", filename)
}
