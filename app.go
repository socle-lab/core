package socle

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type appConfig struct {
	Version        string   `yaml:"version"`
	Name           string   `yaml:"name"`
	Description    string   `yaml:"description"`
	Arch           string   `yaml:"arch"`
	CompatibleWith []string `yaml:"compatible_with"`
	Server         server   `yaml:"server"`
	Defaults       struct {
		Router string `yaml:"router"`
		Render string `yaml:"render"`
	} `yaml:"defaults"`

	Modules map[string]module `yaml:"modules"`
}

type server struct {
	Name    string `yaml:"name"`
	Address string `yaml:"address"`
}

type store struct {
	Enabled bool `yaml:"enabled"`
}

type tlsConfig struct {
	Strategy       string `yaml:"strategy"` // self, root, le
	Mutual         bool   `yaml:"mutual"`
	CACertName     string `yaml:"ca_cert_name"`
	ServerCertName string `yaml:"server_cert_name"`
	ClientCertName string `yaml:"client_cert_name"`
}

type securityConfig struct {
	Enabled bool      `yaml:"enabled"`
	TLS     tlsConfig `yaml:"tls"`
}

type module struct {
	Name   string       `yaml:"name"`
	Type   string       `yaml:"type"` // web, api/rest, api/graphql, api/rpc, cli, worker
	Config moduleConfig `yaml:"config"`
}

type moduleConfig struct {
	Port            int            `yaml:"port"`
	MaintenancePort int            `yaml:"maintenance_port"`
	Router          string         `yaml:"router"`
	Render          string         `yaml:"render"`
	Store           store          `yaml:"store"`
	Middlewares     []string       `yaml:"middlewares"`
	Security        securityConfig `yaml:"security"`
}

func LoadAppConfig(rootPath string) (*appConfig, error) {
	path := rootPath + "/socle.yaml"
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read config file: %w", err)
	}

	expanded := expandEnv(string(data))

	var cfg appConfig
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("unable to unmarshal yaml: %w", err)
	}
	return &cfg, nil
}

func expandEnv(input string) string {
	return os.Expand(input, func(varName string) string {
		return os.Getenv(varName)
	})
}
