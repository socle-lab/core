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
	appConfig     appConfig
	env           envConfig
	AppKey        string
	AppModule     module
	Version       string
	Debug         bool
	RootPath      string
	Log           Logger
	Routes        *chi.Mux
	Render        render.Render
	Session       *scs.SessionManager
	EncryptionKey string
	Cache         cache.Cache
	DB            Database
	Authenticator auth.Authenticator
	Server        Server
	Scheduler     *cron.Cron
	Mail          mailer.MailConfig
	FileSystems   map[string]filesystems.FS
	RateLimiter   ratelimiter.Limiter
}

type Database struct {
	DBType string
	Pool   *sql.DB
}

type Server struct {
	Name        string
	Address     string
	Port        int
	Secure      bool
	Security    ServerSecurity
	Middlewares []string
}

type ServerSecurity struct {
	Strategy       string
	DSN            string
	MutualTLS      bool
	CAName         string
	ServerCertName string
	ClientCertName string
}

func (s Server) GetURL() string {
	return fmt.Sprintf("%s:%d", s.Name, s.Port)
}
