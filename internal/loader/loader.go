package loader

import (
	"diploma/internal/bpf" // Импорт сгенерированного кода
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Setup делает всю грязную работу по инициализации eBPF.
// Возвращает Reader для чтения событий и функцию очистки (cleanup).
func Setup() (*ringbuf.Reader, func(), error) {
	// 1. Снимаем лимиты памяти
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, fmt.Errorf("rlimit error: %w", err)
	}

	// 2. Загружаем байт-код в ядро
	var objs bpf.OpenatObjects
	if err := bpf.LoadOpenatObjects(&objs, nil); err != nil {
		return nil, nil, fmt.Errorf("load objects error: %w", err)
	}

	// Функция очистки (замыкание), которую мы будем дополнять
	cleanup := func() {
		objs.Close()
	}

	// 3. Прикрепляем Tracepoint
	// Используем объекты из пакета bpf
	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TracepointSyscallsSysEnterOpenat, nil)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("link error: %w", err)
	}

	// Добавляем закрытие линка в cleanup
	// (Это паттерн, чтобы гарантировать закрытие ресурсов в правильном порядке)
	baseCleanup := cleanup
	cleanup = func() {
		tp.Close()
		baseCleanup()
	}

	// 4. Открываем RingBuffer
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("ringbuf reader error: %w", err)
	}

	return rd, cleanup, nil
}
