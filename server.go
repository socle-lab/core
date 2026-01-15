package core

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

func (c *Core) ListenAndServe() error {
	var err error

	srv := &http.Server{
		Addr:         c.HTTPServer.GetURL(),
		ErrorLog:     c.Log.ErrorLog,
		Handler:      c.Routes,
		IdleTimeout:  30 * time.Second,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 600 * time.Second,
	}

	if c.DB.Pool != nil {
		defer c.DB.Pool.Close()
	}

	if redisPool != nil {
		defer redisPool.Close()
	}

	if badgerConn != nil {
		defer badgerConn.Close()
	}

	go c.listenMaintenance()

	// start Gracefull server shutdown
	shutdown := make(chan error)

	go func() {
		quit := make(chan os.Signal, 1)

		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		q := <-quit

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		c.Log.InfoLog.Println("signal caught", "signal", q.String())

		shutdown <- srv.Shutdown(ctx)
	}()
	// end

	c.Log.InfoLog.Printf("Listening on  %s with security %v", c.HTTPServer.GetURL(), c.HTTPServer.Secure)
	if c.HTTPServer.Secure {
		c.Log.InfoLog.Println("Begin TLS  Security")

		switch c.HTTPServer.Security.Strategy {
		case "self":
			c.Log.InfoLog.Println("Begin SELF TLS  Security")
			srv.TLSConfig = &tls.Config{
				MinVersion: tls.VersionTLS13,
			}
			var caBytes []byte
			caBytes, err = os.ReadFile(c.HTTPServer.Security.CAName + ".crt")
			if err != nil {
				log.Fatal(err)
			}
			ca := x509.NewCertPool()
			if !ca.AppendCertsFromPEM(caBytes) {
				log.Fatal("CA cert not valid")
			}
			srv.TLSConfig.ClientCAs = ca

			if c.HTTPServer.Security.MutualTLS {
				srv.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert

			}

			err = srv.ListenAndServeTLS(c.HTTPServer.Security.ServerCertName+".crt", c.HTTPServer.Security.ServerCertName+".key")
		case "le":
			c.Log.InfoLog.Println("Begin Let's Encrypt Security")
			err = http.Serve(autocert.NewListener(c.HTTPServer.Security.DSN), nil)
		}

	} else {
		c.Log.InfoLog.Println("Skip TLS  Security")

		err = srv.ListenAndServe()
	}

	if !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	err = <-shutdown
	if err != nil {
		return err
	}

	c.Log.InfoLog.Println("server has stopped")

	return nil
}
