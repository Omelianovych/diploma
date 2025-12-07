package config

import (
	"diploma/internal/analyzer"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadRules читает YAML файл и возвращает структуру RulesConfig
func LoadRules(path string) (*analyzer.RulesConfig, error) {
	// 1. Читаем файл с диска
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %w", err)
	}

	// 2. Создаем пустую структуру
	var cfg analyzer.RulesConfig

	// 3. Парсим YAML в структуру
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse yaml: %w", err)
	}

	return &cfg, nil
}
