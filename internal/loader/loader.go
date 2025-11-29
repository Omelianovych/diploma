package loader

import (
	"diploma/internal/bpf" // Импорт сгенерированного кода
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// Setup делает всю грязную работу по инициализации eBPF.
// Возвращает Reader для чтения событий и функцию очистки (cleanup).
func Setup() (*ringbuf.Reader, func(), error) {
	// 1. Загружаем объекты (тут всё как раньше, загружается ВЕСЬ C-код разом)
	objs := bpf.OpenatObjects{}
	if err := bpf.LoadOpenatObjects(&objs, nil); err != nil {
		return nil, nil, fmt.Errorf("loading objects: %v", err)
	}

	// 2. ЛИНК 1: sys_enter (Вход)
	// Цепляем функцию C "tracepoint__syscalls__sys_enter_openat" к событию ядра
	kpEnter, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TracepointSyscallsSysEnterOpenat, nil)
	if err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("linking enter tracepoint: %v", err)
	}

	// 3. ЛИНК 2: sys_exit (Выход) — ЭТО НОВОЕ!
	// Цепляем функцию C "tracepoint__syscalls__sys_exit_openat" к событию ядра
	kpExit, err := link.Tracepoint("syscalls", "sys_exit_openat", objs.TracepointSyscallsSysExitOpenat, nil)
	if err != nil {
		kpEnter.Close() // Не забываем закрыть первый линк при ошибке
		objs.Close()
		return nil, nil, fmt.Errorf("linking exit tracepoint: %v", err)
	}

	// 4. Создаем RingBuffer Reader
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		kpExit.Close()
		kpEnter.Close()
		objs.Close()
		return nil, nil, fmt.Errorf("opening ringbuf reader: %v", err)
	}

	// Функция очистки (вызывается при Ctrl+C)
	cleanup := func() {
		rd.Close()
		kpExit.Close()  // Закрываем второй линк
		kpEnter.Close() // Закрываем первый линк
		objs.Close()
	}

	return rd, cleanup, nil
}
