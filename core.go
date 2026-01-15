package core

import (
	"expvar"
	"log"
	"net"
	"net/rpc"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/dgraph-io/badger/v3"
	"github.com/go-chi/chi/v5"
	"github.com/gomodule/redigo/redis"
	"github.com/pkg/errors"
	"github.com/robfig/cron/v3"
	"github.com/socle-lab/cache"
	"github.com/socle-lab/core/pkg/auth"
	"github.com/socle-lab/core/pkg/env"
	"github.com/socle-lab/core/pkg/ratelimiter"
	"github.com/socle-lab/filesystems"
	"github.com/socle-lab/filesystems/miniofilesystem"
	"github.com/socle-lab/filesystems/s3filesystem"
	"github.com/socle-lab/filesystems/sftpfilesystem"
	"github.com/socle-lab/filesystems/webdavfilesystem"
	"github.com/socle-lab/mailer"
	"github.com/socle-lab/render"
	"github.com/socle-lab/session"
)

var redisCache *cache.RedisCache
var badgerCache *cache.BadgerCache
var redisPool *redis.Pool
var badgerConn *badger.DB
var maintenanceMode bool

// New reads the .env file, creates our application config, populates the Core type with settings
// based on .env values, and creates necessary folders and files if they don't exist
func (c *Core) New(rootPath, moduleKey string) error {
	// Load .env
	err := env.Load(rootPath)
	if err != nil {
		return err
	}
	c.env = initEnvConfig()

	//load socle.yaml
	appConfig, err := LoadAppConfig(rootPath)
	if err != nil {
		return err
	}
	c.appConfig = *appConfig

	module, exists := appConfig.Modules[moduleKey]
	if !exists {
		return errors.Errorf("Module with key %s does't exist", moduleKey)
	}

	c.AppKey = moduleKey
	c.AppModule = module
	c.Debug = c.env.debug
	c.EncryptionKey = c.env.encryptionKey
	c.Version = c.appConfig.Version
	c.RootPath = rootPath
	// create loggers
	err = c.initLoggers()
	if err != nil {
		return err
	}

	// init router
	err = c.initRouter()
	if err != nil {
		return err
	}

	// connect to database
	if c.AppModule.Config.Store.Enabled {
		err = c.initDB()
		if err != nil {
			return err
		}
	}

	// config scheduler
	err = c.initScheduler()
	if err != nil {
		return err
	}

	// cache setting
	err = c.initCache()
	if err != nil {
		return err
	}

	// init server
	err = c.initServer()
	if err != nil {
		return err
	}

	// init RPC server
	err = c.initRPCServer()
	if err != nil {
		return err
	}

	// create session
	err = c.InitSession()
	if err != nil {
		return err
	}

	//init render
	err = c.initRenderer()
	if err != nil {
		return err
	}

	// init Mailer
	err = c.initMailer()
	if err != nil {
		return err
	}

	//init auth
	err = c.initAuthentificator()
	if err != nil {
		return err
	}

	//init auth
	err = c.initRateLimiter()
	if err != nil {
		return err
	}

	//init filesystem
	err = c.initFileSystems()
	if err != nil {
		return err
	}

	//metric
	err = c.initMetrics()
	if err != nil {
		return err
	}

	return nil
}

func (c *Core) initLoggers() error {
	c.Log.InfoLog = log.New(os.Stdout, c.AppKey+" INFO\t", log.Ldate|log.Ltime)
	c.Log.ErrorLog = log.New(os.Stdout, c.AppKey+" ERROR\t", log.Ldate|log.Ltime|log.Lshortfile)
	return nil
}

func (c *Core) initRouter() error {
	if !InArrayStr(c.AppModule.Type, []string{"web", "api/rest"}) {
		return nil
	}
	var middlewares []string = c.AppModule.Config.Middlewares
	c.HTTPServer.Middlewares = middlewares
	c.Routes = c.routes(middlewares).(*chi.Mux)
	return nil
}

func (c *Core) initDB() error {
	if c.env.db.dbType != "" {
		db, err := c.OpenDB(c.env.db.dbType, c.BuildDSN())
		if err != nil {
			c.Log.ErrorLog.Println(err)
			return err
		}
		c.DB = Database{
			DBType: c.env.db.dbType,
			Pool:   db,
		}
	}

	return nil
}

func (c *Core) initScheduler() error {
	c.Scheduler = cron.New()
	return nil
}

func (c *Core) initCache() error {
	if c.env.cache == "redis" || c.env.sessionType == "redis" {
		redisCache = c.createClientRedisCache()
		c.Cache = redisCache
		redisPool = redisCache.Conn
	}

	if c.env.cache == "badger" {
		badgerCache = c.createClientBadgerCache()
		c.Cache = badgerCache
		badgerConn = badgerCache.Conn

		_, err := c.Scheduler.AddFunc("@daily", func() {
			_ = badgerCache.Conn.RunValueLogGC(0.7)
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Core) createClientRedisCache() *cache.RedisCache {
	cacheClient := cache.RedisCache{
		Conn:   c.createRedisPool(),
		Prefix: c.env.redis.prefix,
	}
	return &cacheClient
}

func (c *Core) createClientBadgerCache() *cache.BadgerCache {
	cacheClient := cache.BadgerCache{
		Conn: c.createBadgerConn(),
	}
	return &cacheClient
}

func (c *Core) createRedisPool() *redis.Pool {
	return &redis.Pool{
		MaxIdle:     50,
		MaxActive:   10000,
		IdleTimeout: 240 * time.Second,
		Dial: func() (redis.Conn, error) {
			return redis.Dial("tcp",
				c.env.redis.host,
				redis.DialPassword(c.env.redis.password))
		},

		TestOnBorrow: func(conn redis.Conn, t time.Time) error {
			_, err := conn.Do("PING")
			return err
		},
	}
}

func (c *Core) createBadgerConn() *badger.DB {
	db, err := badger.Open(badger.DefaultOptions(c.RootPath + "/tmp/badger"))
	if err != nil {
		return nil
	}
	return db
}

func (c *Core) initMailer() error {
	c.Mail = mailer.MailConfig{
		Domain:      c.env.mail.domain,
		Templates:   c.RootPath + "/internal/mail",
		Host:        c.env.mail.smtp.host,
		Port:        c.env.mail.smtp.port,
		Username:    c.env.mail.smtp.username,
		Password:    c.env.mail.smtp.password,
		Encryption:  c.env.mail.smtp.encryptionKey,
		FromName:    c.env.mail.fromName,
		FromAddress: c.env.mail.FromAddress,
		API:         c.env.mail.mailerService.api,
		APIKey:      c.env.mail.mailerService.key,
		APIUrl:      c.env.mail.mailerService.url,
		IsSandbox:   c.env.mail.isSandbox,
		MaxRetires:  c.env.mail.maxRetires,
	}
	var client mailer.Mailer
	switch c.env.mail.client {
	case "smtp":
		client = &mailer.SMTPClient{
			MailConfig: c.Mail,
		}
	default:
		client = &mailer.SMTPClient{
			MailConfig: c.Mail,
		}
	}
	client.InitServer()

	var d mailer.Distributor
	switch c.env.mail.distributor {
	case "channel":
		d = &mailer.ChannelDistributor{
			Jobs:    make(chan mailer.Message, 20),
			Results: make(chan mailer.Result, 20),
		}
	default:
		d = &mailer.ChannelDistributor{
			Jobs:    make(chan mailer.Message, 20),
			Results: make(chan mailer.Result, 20),
		}
	}

	c.Mail.Distributor = d

	go d.ListenForMail(client, c.Mail.IsSandbox)
	return nil
}

func (c *Core) initServer() error {
	if !InArrayStr(c.AppModule.Type, []string{"web", "api/rest"}) {
		return nil
	}

	c.HTTPServer = HTTPServer{
		Name:    c.env.serverName,
		Address: c.env.serverAddress,
	}

	c.HTTPServer.Port = c.AppModule.Config.Port
	c.HTTPServer.Secure = c.AppModule.Config.Security.Enabled
	c.HTTPServer.Security.Strategy = c.AppModule.Config.Security.TLS.Strategy
	c.HTTPServer.Security.MutualTLS = c.AppModule.Config.Security.TLS.Mutual
	c.HTTPServer.Security.CAName = c.AppModule.Config.Security.TLS.CACertName
	c.HTTPServer.Security.ServerCertName = c.AppModule.Config.Security.TLS.ServerCertName
	c.HTTPServer.Security.ClientCertName = c.AppModule.Config.Security.TLS.ClientCertName
	return nil

}

func (c *Core) initRPCServer() error {
	if !InArrayStr(c.AppModule.Type, []string{"api/rpc"}) {
		return nil
	}

	c.RPCServer = RPCServer{
		Name:    c.env.serverName,
		Address: c.env.serverAddress,
		Enabled: c.AppModule.Config.RPCPort > 0,
	}

	c.RPCServer.Port = c.AppModule.Config.RPCPort
	c.RPCServer.Secure = c.AppModule.Config.Security.Enabled
	c.RPCServer.Security.Strategy = c.AppModule.Config.Security.TLS.Strategy
	c.RPCServer.Security.MutualTLS = c.AppModule.Config.Security.TLS.Mutual
	c.RPCServer.Security.CAName = c.AppModule.Config.Security.TLS.CACertName
	c.RPCServer.Security.ServerCertName = c.AppModule.Config.Security.TLS.ServerCertName
	c.RPCServer.Security.ClientCertName = c.AppModule.Config.Security.TLS.ClientCertName
	return nil

}

func (c *Core) InitSession() error {
	// if c.entry != "web" {
	// 	return nil
	// }

	sess := session.Session{
		CookieLifetime: c.env.cookie.lifetime,
		CookiePersist:  c.env.cookie.persist,
		CookieName:     c.env.cookie.name,
		SessionType:    c.env.sessionType,
	}

	if c.env.cookie.domain != "" {
		sess.CookieDomain = c.env.cookie.domain
	}
	switch c.env.sessionType {
	case "redis":
		sess.RedisPool = redisCache.Conn
	case "mysql", "postgres", "mariadb", "postgresql":
		sess.DBPool = c.DB.Pool
	}

	c.Session = sess.InitSession()
	return nil
}

func (c *Core) initRenderer() error {
	if c.AppModule.Type != "web" {
		return nil
	}

	switch c.AppModule.Config.Render {
	case "templ":
		rd := &render.TemplRender{}
		rd.RootPath = c.RootPath
		rd.Session = c.Session
		c.Render = rd

	// 		c.Render = &render.Render{
	// 	Renderer: c.appConfig.Entries.Web.Render,
	// 	RootPath: c.RootPath,
	// 	Session:  c.Session,
	// }
	case "jet":
		rd := &render.JetRender{}
		rd.RootPath = c.RootPath
		rd.Session = c.Session
		c.Render = rd
	default:

	}
	return nil
}

func (c *Core) initAuthentificator() error {
	if c.AppModule.Type != "api/rest" {
		return nil
	}

	c.Authenticator = auth.NewJWTAuthenticator(
		c.env.auth.token.secret,
		c.env.auth.token.iss,
		c.env.auth.token.iss,
	)

	return nil
}

func (c *Core) initRateLimiter() error {
	c.RateLimiter = ratelimiter.NewFixedWindowLimiter(
		c.env.rateLimiter.RequestsPerTimeFrame,
		c.env.rateLimiter.TimeFrame,
	)

	return nil
}

func (c *Core) initFileSystems() error {
	c.FileSystems = make(map[string]filesystems.FS)
	if c.env.filesystems.s3.key != "" {
		s3 := s3filesystem.S3{
			Key:      c.env.filesystems.s3.key,
			Secret:   c.env.filesystems.s3.secret,
			Region:   c.env.filesystems.s3.region,
			Endpoint: c.env.filesystems.s3.endpoint,
			Bucket:   c.env.filesystems.s3.bucket,
		}
		c.FileSystems["S3"] = &s3
	}

	if c.env.filesystems.minio.secret != "" {
		useSSL := false
		if c.env.filesystems.minio.useSSL {
			useSSL = true
		}

		minio := miniofilesystem.Minio{
			Endpoint: c.env.filesystems.minio.endpoint,
			Key:      c.env.filesystems.minio.key,
			Secret:   c.env.filesystems.minio.secret,
			UseSSL:   useSSL,
			Region:   c.env.filesystems.minio.region,
			Bucket:   c.env.filesystems.minio.bucket,
		}
		c.FileSystems["MINIO"] = &minio
	}

	if c.env.filesystems.sftp.host != "" {
		sftp := sftpfilesystem.SFTP{
			Host: c.env.filesystems.sftp.host,
			User: c.env.filesystems.sftp.user,
			Pass: c.env.filesystems.sftp.pass,
			Port: c.env.filesystems.sftp.port,
		}
		c.FileSystems["SFTP"] = &sftp
	}

	if c.env.filesystems.webDAV.host != "" {
		webDav := webdavfilesystem.WebDAV{
			Host: c.env.filesystems.webDAV.host,
			User: c.env.filesystems.webDAV.user,
			Pass: c.env.filesystems.webDAV.pass,
		}
		c.FileSystems["WEBDAV"] = &webDav
	}

	return nil
}

func (c *Core) initMetrics() error {
	expvar.NewString("version").Set(c.Version)
	expvar.Publish("database", expvar.Func(func() any {
		return c.DB.Pool.Stats()
	}))
	expvar.Publish("goroutines", expvar.Func(func() any {
		return runtime.NumGoroutine()
	}))

	return nil
}

type MaintenanceServer struct{}

func (r *MaintenanceServer) MaintenanceMode(inMaintenanceMode bool, resp *string) error {
	if inMaintenanceMode {
		maintenanceMode = true
		*resp = "Server in maintenance mode"
	} else {
		maintenanceMode = false
		*resp = "Server live!"
	}
	return nil
}

func (c *Core) listenMaintenance() {
	// if nothing specified for rpc port, don't start
	port := c.AppModule.Config.MaintenancePort
	if port != 0 {
		c.Log.InfoLog.Println("Starting RPC server on port", port)
		err := rpc.Register(new(MaintenanceServer))
		if err != nil {
			c.Log.ErrorLog.Println(err)
			return
		}
		listen, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			c.Log.ErrorLog.Println(err)
			return
		}
		for {
			rpcConn, err := listen.Accept()
			if err != nil {
				continue
			}
			go rpc.ServeConn(rpcConn)
		}

	}
}
