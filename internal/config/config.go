package config

import (
	"diploma/internal/analyzer"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func LoadRules(path string) (*analyzer.RulesConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %w", err)
	}

	var cfg analyzer.RulesConfig

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse yaml: %w", err)
	}

	return &cfg, nil
}
