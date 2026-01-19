// Package core provides the core application configuration and initialization.
// It handles loading and parsing of YAML configuration files for the Socle framework.
package core

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// appConfig represents the root application configuration structure.
// It contains all top-level configuration including version, server settings,
// defaults, modules, and applications.
type appConfig struct {
	Version        string   `yaml:"version"`         // Application version
	Name           string   `yaml:"name"`            // Application name
	Description    string   `yaml:"description"`     // Application description
	Arch           string   `yaml:"arch"`            // Architecture type (e.g., "default")
	CompatibleWith []string `yaml:"compatible_with"` // List of compatible Socle versions
	Server         server   `yaml:"server"`          // Server configuration
	Defaults       struct {
		Router string `yaml:"router"` // Default router (e.g., "chi")
		Render string `yaml:"render"` // Default render engine (e.g., "templ")
	} `yaml:"defaults"` // Default configuration values
	Applications map[string]application `yaml:"applications"` // Application configurations (main, cli, etc.)
}

// server represents the server configuration.
// It defines the server name and address where the application will run.
type server struct {
	Name    string `yaml:"name"`    // Server name (can use environment variables)
	Address string `yaml:"address"` // Server address (can use environment variables)
}

// store represents the database store configuration.
// It indicates whether the store is enabled for a module or application.
type store struct {
	Enabled bool `yaml:"enabled"` // Whether the store is enabled
}

// tlsConfig represents TLS/SSL configuration for secure connections.
// It supports different certificate strategies and mutual TLS authentication.
type tlsConfig struct {
	Strategy       string `yaml:"strategy"`         // TLS strategy: "self" (self-signed), "root" (signed by root CA), or "le" (Let's Encrypt)
	Mutual         bool   `yaml:"mutual"`           // Whether mutual TLS (mTLS) is enabled
	CACertName     string `yaml:"ca_cert_name"`     // CA certificate file name (without extension)
	ServerCertName string `yaml:"server_cert_name"` // Server certificate file name (without extension)
	ClientCertName string `yaml:"client_cert_name"` // Client certificate file name (without extension)
}

// securityConfig represents the security configuration for a module or entrypoint.
// It includes TLS settings for encrypted connections.
type securityConfig struct {
	Enabled bool      `yaml:"enabled"` // Whether security/TLS is enabled
	TLS     tlsConfig `yaml:"tls"`     // TLS configuration
}

// module represents a module configuration.
// Modules are reusable components that can be configured independently (e.g., ui, api).
type module struct {
	Name   string       `yaml:"name"`   // Module name
	Type   string       `yaml:"type"`   // Module type: "web", "api/rest", "api/graphql", "api/rpc", "cli", "worker"
	Config moduleConfig `yaml:"config"` // Module-specific configuration
}

// moduleConfig contains the configuration for a module.
// It includes port settings, router/render engine, store, middlewares, and security.
type moduleConfig struct {
	Port            int            `yaml:"port"`             // HTTP port number (can use environment variables)
	RPCPort         int            `yaml:"rpc_port"`         // RPC port number (can use environment variables)
	MaintenancePort int            `yaml:"maintenance_port"` // Maintenance mode port number
	Router          string         `yaml:"router"`           // Router framework (e.g., "chi", "gin")
	Render          string         `yaml:"render"`           // Template render engine (e.g., "templ", "jet")
	Store           store          `yaml:"store"`            // Database store configuration
	Middlewares     []string       `yaml:"middlewares"`      // List of middleware names to apply
	Security        securityConfig `yaml:"security"`         // Security/TLS configuration
}

// application represents an application configuration.
// Applications are the main entry points of the system (e.g., main web app, CLI tool).
// They can have multiple entrypoints (HTTP, RPC) and share a common store configuration.
type application struct {
	Type        string                `yaml:"type"`                  // Application type: "web", "api", "ui", "cli"
	Description string                `yaml:"description,omitempty"` // Optional description of the application
	Store       store                 `yaml:"store,omitempty"`       // Shared store configuration for the application
	Entrypoints map[string]entrypoint `yaml:"entrypoints,omitempty"` // Map of entrypoint names to their configurations (e.g., "http", "rpc")
}

// entrypoint represents a network entrypoint configuration.
// Entrypoints define how the application accepts connections (HTTP or RPC).
// Each entrypoint can have its own port, protocol, router, middlewares, and security settings.
type entrypoint struct {
	Port        int            `yaml:"port"`                  // Port number for this entrypoint (can use environment variables)
	Protocol    string         `yaml:"protocol"`              // Protocol type: "http" or "rpc"
	Router      string         `yaml:"router,omitempty"`      // Router framework (typically for HTTP, e.g., "chi")
	Middlewares []string       `yaml:"middlewares,omitempty"` // List of middleware names to apply (typically for HTTP)
	Security    securityConfig `yaml:"security,omitempty"`    // Security/TLS configuration for this entrypoint
}

// LoadAppConfig loads and parses the application configuration from a YAML file.
// It reads the "socle.yaml" file from the specified root path, expands environment variables,
// and unmarshals the YAML content into an appConfig struct.
//
// Parameters:
//   - rootPath: The root directory path where the "socle.yaml" file is located
//
// Returns:
//   - *appConfig: Pointer to the parsed configuration struct
//   - error: Error if the file cannot be read or parsed
func LoadAppConfig(rootPath string) (*appConfig, error) {
	path := rootPath + "/socle.yaml"
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read config file: %w", err)
	}

	// Expand environment variables in the YAML content (e.g., ${HTTP_PORT} -> actual value)
	expanded := expandEnv(string(data))

	var cfg appConfig
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("unable to unmarshal yaml: %w", err)
	}
	return &cfg, nil
}

// expandEnv expands environment variables in a string.
// It replaces ${VAR_NAME} patterns with the corresponding environment variable values.
// This allows configuration files to reference environment variables dynamically.
//
// Parameters:
//   - input: The input string that may contain ${VAR_NAME} patterns
//
// Returns:
//   - string: The input string with all environment variables expanded
func expandEnv(input string) string {
	return os.Expand(input, func(varName string) string {
		return os.Getenv(varName)
	})
}
