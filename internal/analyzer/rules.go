package analyzer

import (
	"diploma/internal/events"
	"fmt"
	"strings"
)

// Condition - одно условие (например: proc.name = "nc")
type Condition struct {
	Field    string `yaml:"field"`    // proc.name
	Operator string `yaml:"operator"` // =, !=, startswith, contains
	Value    string `yaml:"value"`    // nc
}

// Rule - правило целиком
type Rule struct {
	Name       string      `yaml:"name"`
	EventTypes []string    `yaml:"event_types"` // ["openat", "open"]
	Conditions []Condition `yaml:"conditions"`  // Все условия должны выполниться (AND)
	Severity   string      `yaml:"severity"`
	Message    string      `yaml:"message"` // Шаблон сообщения
}

type RulesConfig struct {
	Rules []Rule `yaml:"rules"`
}

// CheckEvent проверяет, подходит ли событие под правило
func (r *Rule) CheckEvent(evt events.EventGetter) bool {
	// 1. Проверка типа события
	matchType := false
	for _, t := range r.EventTypes {
		if t == evt.GetType() {
			matchType = true
			break
		}
	}
	if !matchType {
		return false
	}

	// 2. Проверка всех условий
	for _, cond := range r.Conditions {
		val, ok := evt.GetField(cond.Field)
		if !ok {
			return false // Поле отсутствует в событии
		}

		if !checkCondition(val, cond.Operator, cond.Value) {
			return false
		}
	}
	return true
}

// checkCondition - логика операторов
func checkCondition(fieldVal interface{}, operator, ruleVal string) bool {
	strVal := fmt.Sprintf("%v", fieldVal) // Упрощение: работаем со строками

	switch operator {
	case "=":
		return strVal == ruleVal
	case "!=":
		return strVal != ruleVal
	case "startswith":
		return strings.HasPrefix(strVal, ruleVal)
	case "contains":
		return strings.Contains(strVal, ruleVal)
		// Добавить поддержку списков (in), регулярки и т.д.
	}
	return false
}
