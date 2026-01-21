package core

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"os/signal"
	"syscall"
	"time"

	pkgErrors "github.com/pkg/errors"
	"golang.org/x/crypto/acme/autocert"
)

// ListenAndServe starts a server for the specified entrypoint.
// It checks the protocol of the entrypoint and routes to the appropriate server handler.
// The entrypoint parameter should match a key in the application's entrypoints configuration.
// Returns an error if the entrypoint doesn't exist or if the server fails to start.
func (c *Core) ListenAndServe(entrypoint string) error {
	// Look up the entrypoint in the application configuration
	ep, exists := c.App.Entrypoints[entrypoint]
	if !exists {
		return pkgErrors.Errorf("entrypoint %s does not exist", entrypoint)
	}

	// Route to the appropriate server based on protocol
	switch ep.Protocol {
	case "http":
		return c.ListenAndServeHTTP(entrypoint)
	case "rpc":
		return c.ListenAndServeRPC(entrypoint)
	default:
		return pkgErrors.Errorf("unsupported protocol %s for entrypoint %s", ep.Protocol, entrypoint)
	}
}

// ListenAndServeHTTP starts the HTTP server and handles incoming requests.
// It supports both secure (TLS) and non-secure connections, with graceful shutdown handling.
// The server will listen on the address and port configured in the entrypoint.
// Returns an error if the server fails to start or encounters a fatal error.
func (c *Core) ListenAndServeHTTP(entrypointName string) error {
	return c.ListenAndServeHTTPEntrypoint(entrypointName)
}

// ListenAndServeHTTPEntrypoint starts the HTTP server for a specific entrypoint.
func (c *Core) ListenAndServeHTTPEntrypoint(entrypointName string) error {
	ep, exists := c.Entrypoints[entrypointName]
	if !exists {
		return pkgErrors.Errorf("entrypoint %s does not exist", entrypointName)
	}
	if ep.Protocol != "http" {
		return pkgErrors.Errorf("entrypoint %s is not an HTTP entrypoint", entrypointName)
	}

	var err error

	// Create HTTP server with configured timeouts and handlers
	srv := &http.Server{
		Addr:         ep.GetURL(),
		ErrorLog:     c.Log.ErrorLog,
		Handler:      ep.Routes,
		IdleTimeout:  30 * time.Second,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 600 * time.Second,
	}

	// Ensure database connection is closed on exit
	if c.DB.Pool != nil {
		defer c.DB.Pool.Close()
	}

	// Ensure Redis connection pool is closed on exit
	if redisPool != nil {
		defer redisPool.Close()
	}

	// Ensure Badger connection is closed on exit
	if badgerConn != nil {
		defer badgerConn.Close()
	}

	// Start maintenance RPC server in background
	go c.listenMaintenance()

	// Setup graceful server shutdown handler
	shutdown := make(chan error)

	go func() {
		// Create a channel to receive OS signals
		quit := make(chan os.Signal, 1)

		// Register for interrupt and terminate signals
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		q := <-quit

		// Create context with timeout for graceful shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		c.Log.InfoLog.Println("signal caught", "signal", q.String())

		// Shutdown server gracefully and send result to shutdown channel
		shutdown <- srv.Shutdown(ctx)
	}()

	// Start server based on security configuration
	c.Log.InfoLog.Printf("Listening on  %s with security %v", ep.GetURL(), ep.Secure)
	if ep.Secure {
		c.Log.InfoLog.Println("Begin TLS  Security")

		switch ep.Security.Strategy {
		case "self":
			// Self-signed certificate strategy
			c.Log.InfoLog.Println("Begin SELF TLS  Security")
			srv.TLSConfig = &tls.Config{
				MinVersion: tls.VersionTLS13,
			}
			// Read CA certificate file
			var caBytes []byte
			caBytes, err = os.ReadFile(ep.Security.CAName + ".crt")
			if err != nil {
				log.Fatal(err)
			}
			// Create certificate pool and add CA certificate
			ca := x509.NewCertPool()
			if !ca.AppendCertsFromPEM(caBytes) {
				log.Fatal("CA cert not valid")
			}
			srv.TLSConfig.ClientCAs = ca

			// Enable mutual TLS if configured
			if ep.Security.MutualTLS {
				srv.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
			}

			// Start HTTPS server with TLS certificates
			err = srv.ListenAndServeTLS(ep.Security.ServerCertName+".crt", ep.Security.ServerCertName+".key")
		case "le":
			// Let's Encrypt automatic certificate strategy
			c.Log.InfoLog.Println("Begin Let's Encrypt Security")
			err = http.Serve(autocert.NewListener(ep.Security.DSN), nil)
		}

	} else {
		// Start HTTP server without TLS
		c.Log.InfoLog.Println("Skip TLS  Security")
		err = srv.ListenAndServe()
	}

	// Check if server was closed gracefully or encountered an error
	if !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	// Wait for shutdown signal and check for errors
	err = <-shutdown
	if err != nil {
		return err
	}

	c.Log.InfoLog.Println("server has stopped")

	return nil
}

// RegisterRPCService registers an RPC service that can be called remotely.
// Services must be registered before calling ListenAndServeRPC.
// The service parameter should be a pointer to a struct with exported methods
// that follow RPC method signature conventions.
// Example: c.RegisterRPCService(new(MyService))
func (c *Core) RegisterRPCService(service interface{}) error {
	return rpc.Register(service)
}

// ListenAndServeRPC starts the RPC server and handles incoming RPC connections.
// It supports both secure (TLS) and non-secure connections, with graceful shutdown handling.
// The server will only start if the entrypoint is enabled.
// Note: RPC services must be registered using RegisterRPCService() before calling this method.
// Returns an error if the server fails to start or encounters a fatal error.
func (c *Core) ListenAndServeRPC(entrypointName string) error {
	return c.ListenAndServeRPCEntrypoint(entrypointName)
}

// ListenAndServeRPCEntrypoint starts the RPC server for a specific entrypoint.
func (c *Core) ListenAndServeRPCEntrypoint(entrypointName string) error {
	ep, exists := c.Entrypoints[entrypointName]
	if !exists {
		return pkgErrors.Errorf("entrypoint %s does not exist", entrypointName)
	}
	if ep.Protocol != "rpc" {
		return pkgErrors.Errorf("entrypoint %s is not an RPC entrypoint", entrypointName)
	}

	// Exit early if RPC server is not enabled
	if !ep.Enabled {
		return nil
	}

	var err error
	var listener net.Listener

	// Get the server address from configuration
	address := ep.GetURL()

	// Setup graceful server shutdown handler
	shutdown := make(chan error)

	go func() {
		// Create a channel to receive OS signals
		quit := make(chan os.Signal, 1)

		// Register for interrupt and terminate signals
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		q := <-quit

		c.Log.InfoLog.Println("RPC signal caught", "signal", q.String())

		// Close listener and send result to shutdown channel
		if listener != nil {
			shutdown <- listener.Close()
		} else {
			shutdown <- nil
		}
	}()

	// Ensure database connection is closed on exit
	if c.DB.Pool != nil {
		defer c.DB.Pool.Close()
	}

	// Ensure Redis connection pool is closed on exit
	if redisPool != nil {
		defer redisPool.Close()
	}

	// Ensure Badger connection is closed on exit
	if badgerConn != nil {
		defer badgerConn.Close()
	}

	// Start RPC server based on security configuration
	c.Log.InfoLog.Printf("Starting RPC server on %s with security %v", address, ep.Secure)

	if ep.Secure {
		c.Log.InfoLog.Println("Begin TLS Security for RPC")

		switch ep.Security.Strategy {
		case "self":
			// Self-signed certificate strategy
			c.Log.InfoLog.Println("Begin SELF TLS Security for RPC")
			// Load server certificate and private key
			var cert tls.Certificate
			cert, err = tls.LoadX509KeyPair(
				ep.Security.ServerCertName+".crt",
				ep.Security.ServerCertName+".key",
			)
			if err != nil {
				return err
			}

			// Read CA certificate file
			var caBytes []byte
			caBytes, err = os.ReadFile(ep.Security.CAName + ".crt")
			if err != nil {
				return err
			}
			// Create certificate pool and add CA certificate
			ca := x509.NewCertPool()
			if !ca.AppendCertsFromPEM(caBytes) {
				return errors.New("CA cert not valid")
			}

			// Configure TLS with certificates and minimum version
			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{cert},
				ClientCAs:    ca,
				MinVersion:   tls.VersionTLS13,
			}

			// Enable mutual TLS if configured
			if ep.Security.MutualTLS {
				tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			}

			// Create TLS listener
			listener, err = tls.Listen("tcp", address, tlsConfig)
			if err != nil {
				return err
			}
		default:
			return errors.New("unsupported TLS strategy for RPC server")
		}
	} else {
		// Start RPC server without TLS
		c.Log.InfoLog.Println("Skip TLS Security for RPC")
		listener, err = net.Listen("tcp", address)
		if err != nil {
			return err
		}
	}

	// Ensure listener is closed on exit
	defer listener.Close()

	// Accept and handle RPC connections in a separate goroutine
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				// Check if shutdown was requested
				select {
				case <-shutdown:
					return
				default:
					// Log error and continue accepting connections
					c.Log.ErrorLog.Println("RPC accept error:", err)
					continue
				}
			}
			// Serve each connection in its own goroutine
			go rpc.ServeConn(conn)
		}
	}()

	c.Log.InfoLog.Printf("RPC server listening on %s", address)

	// Wait for shutdown signal and check for errors
	err = <-shutdown
	if err != nil {
		return err
	}

	c.Log.InfoLog.Println("RPC server has stopped")

	return nil
}
