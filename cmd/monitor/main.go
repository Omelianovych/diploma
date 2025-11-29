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

	// 1. LOADER: Инициализируем eBPF
	// (Вся сложность с rlimit и link спрятана внутри)
	rd, cleanup, err := loader.Setup()
	if err != nil {
		log.Fatalf("Ошибка загрузки: %v", err)
	}
	defer cleanup() // Гарантированно выгрузим программу при выходе

	// 2. ANALYZER: Инициализируем мозг системы
	engine := analyzer.New()

	// 3. POLLER: Запускаем цикл прослушки в фоне
	// Мы говорим поллеру:
	// "Читай из rd, превращай байты в OpenatEvent, и отдавай их методу engine.HandleOpenat"
	poller.Start(rd, engine.HandleOpenat)

	log.Println("Система работает. Нажмите Ctrl+C для выхода.")

	// 4. Ожидание сигнала (блокируем main)
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper

	log.Println("\nЗавершение работы...")
	// cleanup() вызовется автоматически благодаря defer
}
