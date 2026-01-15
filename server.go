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

	"golang.org/x/crypto/acme/autocert"
)

// ListenAndServe starts the HTTP server and handles incoming requests.
// It supports both secure (TLS) and non-secure connections, with graceful shutdown handling.
// The server will listen on the address and port configured in HTTPServer.
// Returns an error if the server fails to start or encounters a fatal error.
func (c *Core) ListenAndServe() error {
	var err error

	// Create HTTP server with configured timeouts and handlers
	srv := &http.Server{
		Addr:         c.HTTPServer.GetURL(),
		ErrorLog:     c.Log.ErrorLog,
		Handler:      c.Routes,
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
	c.Log.InfoLog.Printf("Listening on  %s with security %v", c.HTTPServer.GetURL(), c.HTTPServer.Secure)
	if c.HTTPServer.Secure {
		c.Log.InfoLog.Println("Begin TLS  Security")

		switch c.HTTPServer.Security.Strategy {
		case "self":
			// Self-signed certificate strategy
			c.Log.InfoLog.Println("Begin SELF TLS  Security")
			srv.TLSConfig = &tls.Config{
				MinVersion: tls.VersionTLS13,
			}
			// Read CA certificate file
			var caBytes []byte
			caBytes, err = os.ReadFile(c.HTTPServer.Security.CAName + ".crt")
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
			if c.HTTPServer.Security.MutualTLS {
				srv.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
			}

			// Start HTTPS server with TLS certificates
			err = srv.ListenAndServeTLS(c.HTTPServer.Security.ServerCertName+".crt", c.HTTPServer.Security.ServerCertName+".key")
		case "le":
			// Let's Encrypt automatic certificate strategy
			c.Log.InfoLog.Println("Begin Let's Encrypt Security")
			err = http.Serve(autocert.NewListener(c.HTTPServer.Security.DSN), nil)
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
// The server will only start if RPCServer.Enabled is true.
// Note: RPC services must be registered using RegisterRPCService() before calling this method.
// Returns an error if the server fails to start or encounters a fatal error.
func (c *Core) ListenAndServeRPC() error {
	// Exit early if RPC server is not enabled
	if !c.RPCServer.Enabled {
		return nil
	}

	var err error
	var listener net.Listener

	// Get the server address from configuration
	address := c.RPCServer.GetURL()

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
	c.Log.InfoLog.Printf("Starting RPC server on %s with security %v", address, c.RPCServer.Secure)

	if c.RPCServer.Secure {
		c.Log.InfoLog.Println("Begin TLS Security for RPC")

		switch c.RPCServer.Security.Strategy {
		case "self":
			// Self-signed certificate strategy
			c.Log.InfoLog.Println("Begin SELF TLS Security for RPC")
			// Load server certificate and private key
			var cert tls.Certificate
			cert, err = tls.LoadX509KeyPair(
				c.RPCServer.Security.ServerCertName+".crt",
				c.RPCServer.Security.ServerCertName+".key",
			)
			if err != nil {
				return err
			}

			// Read CA certificate file
			var caBytes []byte
			caBytes, err = os.ReadFile(c.RPCServer.Security.CAName + ".crt")
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
			if c.RPCServer.Security.MutualTLS {
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
