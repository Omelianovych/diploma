package main

import (
	"diploma/internal/analyzer"
	"diploma/internal/config"
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
	// rulesCfg := analyzer.RulesConfig{
	// 	Rules: []analyzer.Rule{
	// 		{
	// 			Name:       "Detect /etc/shadow access",
	// 			Severity:   "CRITICAL",
	// 			EventTypes: []string{"openat"},
	// 			Message:    "Attempt to open shadow file detected",
	// 			Conditions: []analyzer.Condition{
	// 				{Field: "fd.name", Operator: "=", Value: "/etc/shadow"},
	// 			},
	// 		},
	// 		{
	// 			Name:       "Suspicious Downloader (curl)",
	// 			Severity:   "INFO",
	// 			EventTypes: []string{"execve"},
	// 			Message:    "Curl utility executed",
	// 			Conditions: []analyzer.Condition{
	// 				{Field: "proc.name", Operator: "=", Value: "curl"},
	// 			},
	// 		},
	// 		{
	// 			Name:       "Detect ls -l command",
	// 			Severity:   "INFO", // Обычно это не угроза, поэтому INFO
	// 			EventTypes: []string{"execve"},
	// 			Message:    "Executed ls with list flag (-l)",
	// 			Conditions: []analyzer.Condition{
	// 				// 1. Убеждаемся, что это команда ls
	// 				{Field: "proc.name", Operator: "=", Value: "ls"},
	// 				// 2. Проверяем, что в аргументах есть флаг -l
	// 				// proc.cmdline содержит всю строку запуска, например "ls -l /tmp"
	// 				{Field: "proc.cmdline", Operator: "contains", Value: "-l"},
	// 			},
	// 		},
	// 	},
	// }
	rulesPath := "configs/security_rules.yaml"
	rulesCfg, err := config.LoadRules(rulesPath)
	if err != nil {
		log.Fatalf("Критическая ошибка: не удалось загрузить правила из %s: %v", rulesPath, err)
	}

	log.Printf("Загружено %d правил безопасности", len(rulesCfg.Rules))

	engine := analyzer.New(*rulesCfg)

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
