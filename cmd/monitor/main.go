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

	// 2. Подготовка правил (Заглушка или загрузка из YAML)
	// В будущем здесь будет: cfg, err := config.Load("rules.yaml")
	rulesCfg := analyzer.RulesConfig{
		Rules: []analyzer.Rule{
			{
				Name:       "Detect /etc/shadow access",
				Severity:   "CRITICAL",
				EventTypes: []string{"openat"},
				Message:    "Attempt to open shadow file detected",
				Conditions: []analyzer.Condition{
					{Field: "fd.name", Operator: "=", Value: "/etc/shadow"},
				},
			},
			{
				Name:       "Detect Netcat execution",
				Severity:   "WARNING",
				EventTypes: []string{"execve"},
				Message:    "Netcat binary executed",
				Conditions: []analyzer.Condition{
					{Field: "proc.name", Operator: "=", Value: "nc"},
				},
			},
		},
	}
	engine := analyzer.New(rulesCfg)

	// 2. POLLER: Запускаем два независимых потока чтения
	// poller.Start теперь запускается дважды для разных типов
	poller.Start(loaded.OpenatReader, engine.HandleOpenat)
	poller.Start(loaded.ExecveReader, engine.HandleExecve)   // Нужно добавить этот метод в Analyzer
	poller.Start(loaded.ConnectReader, engine.HandleConnect) // Нужно добавить этот метод в Analyzer
	poller.Start(loaded.AcceptReader, engine.HandleAccept)
	poller.Start(loaded.PtraceReader, engine.HandlePtrace)

	log.Println("Security Monitor запущен (Openat + Execve)...")

	// 4. Ожидание сигнала (блокируем main)
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper

	log.Println("\nЗавершение работы...")
	// cleanup() вызовется автоматически благодаря defer
}
