package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// Event - это Go-структура, которая *точно* соответствует
// C-структуре 'event' в bpf_connect.c
// Важно следить за выравниванием полей!
type Event struct {
	PID   uint32
	Comm  [16]byte
	DAddr uint32
}

func main() {
	// Подписываемся на сигналы (Ctrl+C) для корректного выхода
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// eBPF программам нужны специальные лимиты на память
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Ошибка снятия rlimit: %v", err)
	}

	// Загружаем объекты eBPF (программу и map'у) из сгенерированного файла
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Ошибка загрузки eBPF объектов: %v", err)
	}
	defer objs.Close() // Закрываем все при выходе

	// Прикрепляем нашу eBPF программу к tracepoint'у
	// Имя 'syscalls' и 'sys_enter_connect' должны совпадать с C-кодом
	tp, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TracepointSyscallsSysEnterConnect, nil)
	if err != nil {
		log.Fatalf("Ошибка прикрепления к tracepoint: %v", err)
	}
	defer tp.Close() // Открепляем при выходе

	log.Println("eBPF программа загружена. Ожидание событий (Нажмите Ctrl+C для выхода)...")

	// Создаем PerfReader для чтения событий из map'ы 'events'
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("Ошибка создания perf reader: %v", err)
	}
	defer rd.Close()

	// Горутина для обработки сигналов (Ctrl+C)
	go func() {
		<-stopper
		log.Println("Получен сигнал, завершение...")
		rd.Close()
	}()

	var event Event
	for {
		// Читаем следующее событие из perf-буфера
		record, err := rd.Read()
		if err != nil {
			// Если rd.Close() был вызван, Read вернет ошибку
			if perf.IsClosed(err) {
				log.Println("Perf reader закрыт.")
				return
			}
			log.Printf("Ошибка чтения из perf buffer: %v", err)
			continue
		}

		// record.RawSample содержит сырые байты события
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("Ошибка парсинга события: %v", err)
			continue
		}

		// Форматируем и выводим данные
		pid := event.PID
		comm := string(event.Comm[:bytes.IndexByte(event.Comm[:], 0)])
		ip := intToIP(event.DAddr)

		log.Printf("PID: %d\t Process: %-16s\t Connect to: %s\n", pid, comm, ip.String())
	}
}

// Вспомогательная функция для конвертации uint32 (в сетевом порядке) в IP
func intToIP(ipNum uint32) net.IP {
	// IP приходит из ядра в Little Endian, конвертируем в Big Endian для net.IP
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}
