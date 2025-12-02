package main

import (
	"diploma/internal/analyzer"
	"diploma/internal/loader"
	"diploma/internal/poller"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	log.Println("Запуск Security Monitor...")

	loaded, cleanup, err := loader.Setup()
	if err != nil {
		log.Fatalf("Ошибка загрузки: %v", err)
	}
	defer cleanup()

	engine := analyzer.New()

	// 2. POLLER: Запускаем два независимых потока чтения
	// poller.Start теперь запускается дважды для разных типов
	poller.Start(loaded.OpenatReader, engine.HandleOpenat)
	poller.Start(loaded.ExecveReader, engine.HandleExecve) // Нужно добавить этот метод в Analyzer

	log.Println("Security Monitor запущен (Openat + Execve)...")

	// 4. Ожидание сигнала (блокируем main)
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper

	log.Println("\nЗавершение работы...")
	// cleanup() вызовется автоматически благодаря defer
}
