package loader

import (
	"diploma/internal/bpf"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type LoaderResult struct {
	OpenatReader  *ringbuf.Reader
	ExecveReader  *ringbuf.Reader
	ConnectReader *ringbuf.Reader
	AcceptReader  *ringbuf.Reader
	PtraceReader  *ringbuf.Reader
	MemfdReader   *ringbuf.Reader
	ChmodReader   *ringbuf.Reader
}

func Setup() (*LoaderResult, func(), error) {
	objs := bpf.TraceObjects{}
	if err := bpf.LoadTraceObjects(&objs, nil); err != nil {
		return nil, nil, fmt.Errorf("loading objects: %v", err)
	}

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

	l5, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceEnterConnect, nil)
	if err != nil {
		for _, l := range links {
			l.Close()
		}
		objs.Close()
		return nil, nil, fmt.Errorf("link connect enter: %v", err)
	}
	links = append(links, l5)

	l6, err := link.Tracepoint("syscalls", "sys_exit_connect", objs.TraceExitConnect, nil)
	if err != nil {
		for _, l := range links {
			l.Close()
		}
		objs.Close()
		return nil, nil, fmt.Errorf("link connect exit: %v", err)
	}
	links = append(links, l6)

	l7, err := link.Tracepoint("syscalls", "sys_enter_accept4", objs.TraceEnterAccept4, nil)
	if err != nil {
		for _, l := range links {
			l.Close()
		}
		objs.Close()
		return nil, nil, fmt.Errorf("link accept4 enter: %v", err)
	}
	links = append(links, l7)

	l8, err := link.Tracepoint("syscalls", "sys_exit_accept4", objs.TraceExitAccept4, nil)
	if err != nil {
		for _, l := range links {
			l.Close()
		}
		objs.Close()
		return nil, nil, fmt.Errorf("link accept4 exit: %v", err)
	}
	links = append(links, l8)

	// --- 5. PTRACE (NEW) ---
	l9, err := link.Tracepoint("syscalls", "sys_enter_ptrace", objs.TraceEnterPtrace, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("link ptrace enter: %v", err)
	}
	links = append(links, l9)

	l10, err := link.Tracepoint("syscalls", "sys_exit_ptrace", objs.TraceExitPtrace, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("link ptrace exit: %v", err)
	}
	links = append(links, l10)

	l11, err := link.Tracepoint("syscalls", "sys_enter_memfd_create", objs.TraceEnterMemfdCreate, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("link memfd enter: %v", err)
	}
	links = append(links, l11)

	l12, err := link.Tracepoint("syscalls", "sys_exit_memfd_create", objs.TraceExitMemfdCreate, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("link memfd exit: %v", err)
	}
	links = append(links, l12)

	l13, err := link.Tracepoint("syscalls", "sys_enter_fchmodat", objs.TraceEnterFchmodat, nil)
	if err != nil {
		return nil, nil, err
	}
	links = append(links, l13)

	l14, err := link.Tracepoint("syscalls", "sys_exit_fchmodat", objs.TraceExitFchmodat, nil)
	if err != nil {
		return nil, nil, err
	}
	links = append(links, l14)

	// --- READERS ---
	rdOpenat, err := ringbuf.NewReader(objs.OpenatEvents)
	if err != nil {
		return nil, nil, err
	}
	rdExecve, err := ringbuf.NewReader(objs.ExecveEvents)
	if err != nil {
		return nil, nil, err
	}
	rdConnect, err := ringbuf.NewReader(objs.ConnectEvents)
	if err != nil {
		return nil, nil, err
	}
	rdAccept, err := ringbuf.NewReader(objs.AcceptEvents)
	if err != nil {
		return nil, nil, err
	}
	// Ptrace Reader
	rdPtrace, err := ringbuf.NewReader(objs.PtraceEvents)
	if err != nil {
		return nil, nil, fmt.Errorf("reader ptrace: %v", err)
	}

	rdMemfd, err := ringbuf.NewReader(objs.MemfdEvents)
	if err != nil {
		return nil, nil, fmt.Errorf("reader memfd: %v", err)
	}

	rdChmod, err := ringbuf.NewReader(objs.ChmodEvents)
	if err != nil {
		return nil, nil, err
	}

	cleanup := func() {
		rdOpenat.Close()
		rdExecve.Close()
		rdConnect.Close()
		rdAccept.Close()
		rdPtrace.Close()
		rdMemfd.Close()
		rdChmod.Close()
		for _, l := range links {
			l.Close()
		}
		objs.Close()
	}

	return &LoaderResult{
		OpenatReader:  rdOpenat,
		ExecveReader:  rdExecve,
		ConnectReader: rdConnect,
		AcceptReader:  rdAccept,
		PtraceReader:  rdPtrace,
		MemfdReader:   rdMemfd,
		ChmodReader:   rdChmod,
	}, cleanup, nil
}
