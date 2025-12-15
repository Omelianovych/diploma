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
		log.Fatalf("Помилка завантаження: %v", err)
	}
	defer cleanup()

	rulesPath := "configs/security_rules.yaml"
	rulesCfg, err := config.LoadRules(rulesPath)
	if err != nil {
		log.Fatalf("Критична помилка: не вдалося завантажити правила з %s: %v", rulesPath, err)
	}

	log.Printf("Завантажено %d правил безпеки", len(rulesCfg.Rules))

	engine := analyzer.New(*rulesCfg)

	poller.Start(loaded.OpenatReader, engine.HandleOpenat)
	poller.Start(loaded.ExecveReader, engine.HandleExecve)
	poller.Start(loaded.ConnectReader, engine.HandleConnect)
	poller.Start(loaded.AcceptReader, engine.HandleAccept)
	poller.Start(loaded.PtraceReader, engine.HandlePtrace)
	poller.Start(loaded.MemfdReader, engine.HandleMemfd)
	poller.Start(loaded.ChmodReader, engine.HandleChmod)
	log.Println("Security Monitor запущено")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper

	log.Println("\nЗавершення роботи...")
}
