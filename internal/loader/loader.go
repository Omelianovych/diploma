package loader

import (
	"diploma/internal/bpf"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// LoaderResult хранит ридеры для разных типов событий
type LoaderResult struct {
	OpenatReader *ringbuf.Reader
	ExecveReader *ringbuf.Reader
}

func Setup() (*LoaderResult, func(), error) {
	// Обрати внимание: теперь загружаем TraceObjects, а не OpenatObjects
	objs := bpf.TraceObjects{}
	if err := bpf.LoadTraceObjects(&objs, nil); err != nil {
		return nil, nil, fmt.Errorf("loading objects: %v", err)
	}

	// Хранилище линков для очистки
	var links []link.Link

	// --- 1. OPENAT ---
	l1, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceEnterOpenat, nil)
	if err != nil {
		objs.Close()
		return nil, nil, err
	}
	links = append(links, l1)

	l2, err := link.Tracepoint("syscalls", "sys_exit_openat", objs.TraceExitOpenat, nil)
	if err != nil {
		// тут по-хорошему надо закрыть l1 и objs
		return nil, nil, err
	}
	links = append(links, l2)

	// --- 2. EXECVE ---
	l3, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceEnterExecve, nil)
	if err != nil {
		return nil, nil, err
	}
	links = append(links, l3)

	l4, err := link.Tracepoint("syscalls", "sys_exit_execve", objs.TraceExitExecve, nil)
	if err != nil {
		return nil, nil, err
	}
	links = append(links, l4)

	// --- READERS ---
	// Читаем из карты OpenatEvents
	rdOpenat, err := ringbuf.NewReader(objs.OpenatEvents)
	if err != nil {
		return nil, nil, err
	}
	// Читаем из карты ExecveEvents
	rdExecve, err := ringbuf.NewReader(objs.ExecveEvents)
	if err != nil {
		return nil, nil, err
	}

	cleanup := func() {
		rdOpenat.Close()
		rdExecve.Close()
		for _, l := range links {
			l.Close()
		}
		objs.Close()
	}

	return &LoaderResult{
		OpenatReader: rdOpenat,
		ExecveReader: rdExecve,
	}, cleanup, nil
}
