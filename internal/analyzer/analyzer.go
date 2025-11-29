package analyzer

import (
	"diploma/internal/events"
	"log"
)

type Analyzer struct {
	// В будущем здесь будут правила (rules)
}

func New() *Analyzer {
	return &Analyzer{}
}

// HandleOpenat - это метод, который вызывается на каждое событие.
// Сейчас он просто печатает лог (как ваш printEvent раньше),
// но в будущем здесь будет проверка правил.
func (a *Analyzer) HandleOpenat(event events.OpenatEvent) {
	// Просто логируем (замена printEvent)
	log.Printf("[Analyzer] %s", event.String())
}
