package core

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func (c *Core) routes(middlewares []string) http.Handler {
	mux := chi.NewRouter()
	c.applyMiddlewares(mux, middlewares)

	if c.Debug {
		mux.Use(middleware.Logger)
	}

	return mux
}

// Routes are core specific routes, which are mounted in the routes file
// in Core applications
func Routes() http.Handler {
	r := chi.NewRouter()
	r.Get("/test-c", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("it works!"))
	})
	return r
}
