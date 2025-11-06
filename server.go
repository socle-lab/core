package socle

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

func (s *Socle) ListenAndServe() error {
	var err error

	srv := &http.Server{
		Addr:         s.Server.GetURL(),
		ErrorLog:     s.Log.ErrorLog,
		Handler:      s.Routes,
		IdleTimeout:  30 * time.Second,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 600 * time.Second,
	}

	if s.DB.Pool != nil {
		defer s.DB.Pool.Close()
	}

	if redisPool != nil {
		defer redisPool.Close()
	}

	if badgerConn != nil {
		defer badgerConn.Close()
	}

	go s.listenMaintenance()

	// start Gracefull server shutdown
	shutdown := make(chan error)

	go func() {
		quit := make(chan os.Signal, 1)

		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		q := <-quit

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		s.Log.InfoLog.Println("signal caught", "signal", q.String())

		shutdown <- srv.Shutdown(ctx)
	}()
	// end

	s.Log.InfoLog.Printf("Listening on  %s with security %v", s.Server.GetURL(), s.Server.Secure)
	if s.Server.Secure {
		s.Log.InfoLog.Println("Begin TLS  Security")

		switch s.Server.Security.Strategy {
		case "self":
			s.Log.InfoLog.Println("Begin SELF TLS  Security")
			srv.TLSConfig = &tls.Config{
				MinVersion: tls.VersionTLS13,
			}
			var caBytes []byte
			caBytes, err = os.ReadFile(s.Server.Security.CAName + ".crt")
			if err != nil {
				log.Fatal(err)
			}
			ca := x509.NewCertPool()
			if !ca.AppendCertsFromPEM(caBytes) {
				log.Fatal("CA cert not valid")
			}
			srv.TLSConfig.ClientCAs = ca

			if s.Server.Security.MutualTLS {
				srv.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert

			}

			err = srv.ListenAndServeTLS(s.Server.Security.ServerCertName+".crt", s.Server.Security.ServerCertName+".key")
		case "le":
			s.Log.InfoLog.Println("Begin Let's Encrypt Security")
			err = http.Serve(autocert.NewListener(s.Server.Security.DSN), nil)
		}

	} else {
		s.Log.InfoLog.Println("Skip TLS  Security")

		err = srv.ListenAndServe()
	}

	if !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	err = <-shutdown
	if err != nil {
		return err
	}

	s.Log.InfoLog.Println("server has stopped")

	return nil
}
