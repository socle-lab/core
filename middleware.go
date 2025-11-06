package socle

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

func (s *Socle) middlewareRegistry() map[string]func(http.Handler) http.Handler {
	return map[string]func(http.Handler) http.Handler{
		"request_id":             middleware.RequestID,
		"real_ip":                middleware.RealIP,
		"recovery":               middleware.Recoverer,
		"session":                s.SessionLoadMiddleware,
		"ratelimite":             s.RateLimiterMiddleware,
		"no_surf":                s.NoSurfMiddleware, // CSRF protection
		"maintenance_mode_check": s.MaintenanceModeCheckMiddleware,

		//"auth":       s.AuthMiddleware,
		//"healthcheck": s.HealthCheckMiddleware,
	}
}

func (s *Socle) applyMiddlewares(r chi.Router, names []string) {
	registry := s.middlewareRegistry()

	for _, name := range names {
		if mw, ok := registry[name]; ok {
			r.Use(mw)
		} else {
			fmt.Printf("Middleware '%s' not found in registry\n", name)
		}
	}
}

func (s *Socle) SessionLoadMiddleware(next http.Handler) http.Handler {
	s.Log.InfoLog.Println("SessionLoad callled")
	return s.Session.LoadAndSave(next)
}

func (s *Socle) NoSurfMiddleware(next http.Handler) http.Handler {
	s.Log.InfoLog.Println("No surf middleware callled")
	csrfHandler := nosurf.New(next)
	secure, _ := strconv.ParseBool(s.env.cookie.secure)

	csrfHandler.ExemptGlob("/api/*")
	csrfHandler.SetBaseCookie(http.Cookie{
		HttpOnly: true,
		Path:     "/",
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		Domain:   s.env.cookie.domain,
	})

	return csrfHandler
}

func (s *Socle) MaintenanceModeCheckMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if maintenanceMode {
			if !strings.Contains(r.URL.Path, "/public/maintenance.html") {
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Header().Set("Retry-After:", "300")
				w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, post-check=0, pre-check=0")
				http.ServeFile(w, r, fmt.Sprintf("%s/public/maintenance.html", s.RootPath))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Socle) RateLimiterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.env.rateLimiter.Enabled {
			if allow, retryAfter := s.RateLimiter.Allow(r.RemoteAddr); !allow {
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
