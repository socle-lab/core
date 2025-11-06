package socle

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func (s *Socle) routes(middlewares []string) http.Handler {
	mux := chi.NewRouter()
	s.applyMiddlewares(mux, middlewares)

	if s.Debug {
		mux.Use(middleware.Logger)
	}

	return mux
}

// Routes are socle specific routes, which are mounted in the routes file
// in Socle applications
func Routes() http.Handler {
	r := chi.NewRouter()
	r.Get("/test-c", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("it works!"))
	})
	return r
}
