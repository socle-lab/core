package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/justinas/nosurf"
)

func (c *Core) middlewareRegistry() map[string]func(http.Handler) http.Handler {
	return map[string]func(http.Handler) http.Handler{
		"request_id":             middleware.RequestID,
		"real_ip":                middleware.RealIP,
		"recovery":               middleware.Recoverer,
		"session":                c.SessionLoadMiddleware,
		"ratelimite":             c.RateLimiterMiddleware,
		"no_surf":                c.NoSurfMiddleware, // CSRF protection
		"maintenance_mode_check": c.MaintenanceModeCheckMiddleware,

		//"auth":       c.AuthMiddleware,
		//"healthcheck": c.HealthCheckMiddleware,
	}
}

func (c *Core) applyMiddlewares(r chi.Router, names []string) {
	registry := c.middlewareRegistry()

	for _, name := range names {
		if mw, ok := registry[name]; ok {
			r.Use(mw)
		} else {
			fmt.Printf("Middleware '%s' not found in registry\n", name)
		}
	}
}

func (c *Core) SessionLoadMiddleware(next http.Handler) http.Handler {
	c.Log.InfoLog.Println("SessionLoad callled")
	return c.Session.LoadAndSave(next)
}

func (c *Core) NoSurfMiddleware(next http.Handler) http.Handler {
	c.Log.InfoLog.Println("No surf middleware callled")
	csrfHandler := nosurf.New(next)
	secure, _ := strconv.ParseBool(c.env.cookie.secure)

	csrfHandler.ExemptGlob("/api/*")
	csrfHandler.SetBaseCookie(http.Cookie{
		HttpOnly: true,
		Path:     "/",
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		Domain:   c.env.cookie.domain,
	})

	return csrfHandler
}

func (c *Core) MaintenanceModeCheckMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if maintenanceMode {
			if !strings.Contains(r.URL.Path, "/public/maintenance.html") {
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Header().Set("Retry-After:", "300")
				w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, post-check=0, pre-check=0")
				http.ServeFile(w, r, fmt.Sprintf("%s/public/maintenance.html", c.RootPath))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (c *Core) RateLimiterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c.env.rateLimiter.Enabled {
			if allow, retryAfter := c.RateLimiter.Allow(r.RemoteAddr); !allow {
				w.WriteHeader(http.StatusTooManyRequests)
				w.Header().Set("Retry-After:", retryAfter.String())
				w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, post-check=0, pre-check=0")
				json.NewEncoder(w).Encode(&envelope{Error: fmt.Sprint("rate limit exceeded, retry after: ", retryAfter)})
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

type envelope struct {
	Error string `json:"error"`
}
