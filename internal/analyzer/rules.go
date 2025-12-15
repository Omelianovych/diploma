package analyzer

import (
	"diploma/internal/events"
	"fmt"
	"strconv"
	"strings"
)

type Condition struct {
	Field    string `yaml:"field"`
	Operator string `yaml:"operator"`
	Value    string `yaml:"value"`
}

type Rule struct {
	Name       string      `yaml:"name"`
	EventTypes []string    `yaml:"event_types"`
	Conditions []Condition `yaml:"conditions"`
	Severity   string      `yaml:"severity"`
	Message    string      `yaml:"message"`
}

type RulesConfig struct {
	Rules []Rule `yaml:"rules"`
}

func (r *Rule) CheckEvent(evt events.EventGetter) bool {
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

	for _, cond := range r.Conditions {
		val, ok := evt.GetField(cond.Field)
		if !ok {
			return false
		}

		if !checkCondition(val, cond.Operator, cond.Value) {
			return false
		}
	}
	return true
}

func checkCondition(fieldVal interface{}, operator, ruleVal string) bool {
	strVal := fmt.Sprintf("%v", fieldVal)

	switch operator {
	case "=":
		return strVal == ruleVal
	case "!=":
		return strVal != ruleVal
	case "lt": // less than
		numVal, _ := strconv.Atoi(strVal)
		ruleNum, _ := strconv.Atoi(ruleVal)
		return numVal < ruleNum
	case "mt": // more than
		numVal, _ := strconv.Atoi(strVal)
		ruleNum, _ := strconv.Atoi(ruleVal)
		return numVal > ruleNum
	case "startswith":
		return strings.HasPrefix(strVal, ruleVal)
	case "contains":
		return strings.Contains(strVal, ruleVal)
	case "in":
		candidates := strings.Split(ruleVal, ",")
		for _, c := range candidates {
			if strVal == strings.TrimSpace(c) {
				return true
			}
		}
		return false
	case "not in":
		candidates := strings.Split(ruleVal, ",")
		for _, c := range candidates {
			if strVal == strings.TrimSpace(c) {
				return false
			}
		}
		return true
	}
	return false
}
