// заглушка
package analyzer

// Rule описує правило безпеки, яке ми будемо читати з YAML файлу.
// Поки що це заготовка, яку ми будемо використовувати пізніше.
type Rule struct {
	Name      string `yaml:"name"`
	EventType string `yaml:"event_type"` // наприклад "openat"
	Field     string `yaml:"field"`      // наприклад "filename"
	Operator  string `yaml:"operator"`   // наприклад "prefix", "suffix", "="
	Value     string `yaml:"value"`      // наприклад "/etc/shadow"
	Severity  string `yaml:"severity"`   // "INFO", "WARNING", "CRITICAL"
}

// RulesConfig - коренева структура для парсингу файлу правил
type RulesConfig struct {
	Rules []Rule `yaml:"rules"`
}
