package core

import (
	"database/sql"
	"fmt"

	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
	"github.com/robfig/cron/v3"
	"github.com/socle-lab/cache"
	"github.com/socle-lab/core/pkg/auth"
	"github.com/socle-lab/core/pkg/ratelimiter"
	"github.com/socle-lab/filesystems"
	"github.com/socle-lab/mailer"
	"github.com/socle-lab/render"
)

// Core is the overall type for the Core package. Members that are exported in this type
// are available to any application that uses it.
type Core struct {
	Version       string
	Debug         bool
	RootPath      string
	env           envConfig
	AppKey        string
	App           application
	Entrypoints   map[string]*EntrypointServer
	Log           Logger
	Session       *scs.SessionManager
	Render        render.Render
	EncryptionKey string
	Cache         cache.Cache
	DB            Database
	Authenticator auth.Authenticator
	Scheduler     *cron.Cron
	Mail          mailer.MailConfig
	FileSystems   map[string]filesystems.FS
	RateLimiter   ratelimiter.Limiter
}

type Database struct {
	DBType string
	Pool   *sql.DB
}

type HTTPServer struct {
	Name        string
	Address     string
	Port        int
	Secure      bool
	Security    HTTPServerSecurity
	Middlewares []string
}

type HTTPServerSecurity struct {
	Strategy       string
	DSN            string
	MutualTLS      bool
	CAName         string
	ServerCertName string
	ClientCertName string
}

func (s HTTPServer) GetURL() string {
	return fmt.Sprintf("%s:%d", s.Name, s.Port)
}

type RPCServer struct {
	Name     string
	Address  string
	Port     int
	Secure   bool
	Security RPCServerSecurity
	Enabled  bool
}

type RPCServerSecurity struct {
	Strategy       string
	DSN            string
	MutualTLS      bool
	CAName         string
	ServerCertName string
	ClientCertName string
}

func (s RPCServer) GetURL() string {
	return fmt.Sprintf("%s:%d", s.Name, s.Port)
}

// EntrypointServer represents a server instance for an entrypoint.
// It contains server configuration and can be used for either HTTP or RPC protocols.
type EntrypointServer struct {
	Name        string
	Address     string
	Port        int
	Protocol    string
	Enabled     bool
	Secure      bool
	Security    EntrypointSecurity
	Middlewares []string
	Routes      *chi.Mux
}

// EntrypointSecurity represents security configuration for an entrypoint server.
type EntrypointSecurity struct {
	Strategy       string
	DSN            string
	MutualTLS      bool
	CAName         string
	ServerCertName string
	ClientCertName string
}

func (s *EntrypointServer) GetURL() string {
	return fmt.Sprintf("%s:%d", s.Name, s.Port)
}
