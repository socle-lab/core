package socle

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

// New reads the .env file, creates our application config, populates the Socle type with settings
// based on .env values, and creates necessary folders and files if they don't exist
func (s *Socle) New(rootPath, moduleKey string) error {
	// Load .env
	err := env.Load(rootPath)
	if err != nil {
		return err
	}
	s.env = initEnvConfig()

	//load socle.yaml
	appConfig, err := LoadAppConfig(rootPath)
	if err != nil {
		return err
	}
	s.appConfig = *appConfig

	module, exists := appConfig.Modules[moduleKey]
	if !exists {
		return errors.Errorf("Module with key %s does't exist", moduleKey)
	}

	s.AppKey = moduleKey
	s.AppModule = module
	s.Debug = s.env.debug
	s.EncryptionKey = s.env.encryptionKey
	s.Version = s.appConfig.Version
	s.RootPath = rootPath
	// create loggers
	err = s.initLoggers()
	if err != nil {
		return err
	}

	// init router
	err = s.initRouter()
	if err != nil {
		return err
	}

	// connect to database
	if s.AppModule.Config.Store.Enabled {
		err = s.initDB()
		if err != nil {
			return err
		}
	}

	// config scheduler
	err = s.initScheduler()
	if err != nil {
		return err
	}

	// cache setting
	err = s.initCache()
	if err != nil {
		return err
	}

	// init server
	err = s.initServer()
	if err != nil {
		return err
	}

	// create session
	err = s.InitSession()
	if err != nil {
		return err
	}

	//init render
	err = s.initRenderer()
	if err != nil {
		return err
	}

	// init Mailer
	err = s.initMailer()
	if err != nil {
		return err
	}

	//init auth
	err = s.initAuthentificator()
	if err != nil {
		return err
	}

	//init auth
	err = s.initRateLimiter()
	if err != nil {
		return err
	}

	//init filesystem
	err = s.initFileSystems()
	if err != nil {
		return err
	}

	//metric
	err = s.initMetrics()
	if err != nil {
		return err
	}

	return nil
}

func (s *Socle) initLoggers() error {
	s.Log.InfoLog = log.New(os.Stdout, s.AppKey+" INFO\t", log.Ldate|log.Ltime)
	s.Log.ErrorLog = log.New(os.Stdout, s.AppKey+" ERROR\t", log.Ldate|log.Ltime|log.Lshortfile)
	return nil
}

func (s *Socle) initRouter() error {
	if !InArrayStr(s.AppModule.Type, []string{"web", "api/rest"}) {
		return nil
	}
	var middlewares []string = s.AppModule.Config.Middlewares
	s.Server.Middlewares = middlewares
	s.Routes = s.routes(middlewares).(*chi.Mux)
	return nil
}

func (s *Socle) initDB() error {
	if s.env.db.dbType != "" {
		db, err := s.OpenDB(s.env.db.dbType, s.BuildDSN())
		if err != nil {
			s.Log.ErrorLog.Println(err)
			return err
		}
		s.DB = Database{
			DBType: s.env.db.dbType,
			Pool:   db,
		}
	}

	return nil
}

func (s *Socle) initScheduler() error {
	s.Scheduler = cron.New()
	return nil
}

func (s *Socle) initCache() error {
	if s.env.cache == "redis" || s.env.sessionType == "redis" {
		redisCache = s.createClientRedisCache()
		s.Cache = redisCache
		redisPool = redisCache.Conn
	}

	if s.env.cache == "badger" {
		badgerCache = s.createClientBadgerCache()
		s.Cache = badgerCache
		badgerConn = badgerCache.Conn

		_, err := s.Scheduler.AddFunc("@daily", func() {
			_ = badgerCache.Conn.RunValueLogGC(0.7)
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Socle) createClientRedisCache() *cache.RedisCache {
	cacheClient := cache.RedisCache{
		Conn:   s.createRedisPool(),
		Prefix: s.env.redis.prefix,
	}
	return &cacheClient
}

func (s *Socle) createClientBadgerCache() *cache.BadgerCache {
	cacheClient := cache.BadgerCache{
		Conn: s.createBadgerConn(),
	}
	return &cacheClient
}

func (s *Socle) createRedisPool() *redis.Pool {
	return &redis.Pool{
		MaxIdle:     50,
		MaxActive:   10000,
		IdleTimeout: 240 * time.Second,
		Dial: func() (redis.Conn, error) {
			return redis.Dial("tcp",
				s.env.redis.host,
				redis.DialPassword(s.env.redis.password))
		},

		TestOnBorrow: func(conn redis.Conn, t time.Time) error {
			_, err := conn.Do("PING")
			return err
		},
	}
}

func (s *Socle) createBadgerConn() *badger.DB {
	db, err := badger.Open(badger.DefaultOptions(s.RootPath + "/tmp/badger"))
	if err != nil {
		return nil
	}
	return db
}

func (s *Socle) initMailer() error {
	s.Mail = mailer.MailConfig{
		Domain:      s.env.mail.domain,
		Templates:   s.RootPath + "/internal/mail",
		Host:        s.env.mail.smtp.host,
		Port:        s.env.mail.smtp.port,
		Username:    s.env.mail.smtp.username,
		Password:    s.env.mail.smtp.password,
		Encryption:  s.env.mail.smtp.encryptionKey,
		FromName:    s.env.mail.fromName,
		FromAddress: s.env.mail.FromAddress,
		API:         s.env.mail.mailerService.api,
		APIKey:      s.env.mail.mailerService.key,
		APIUrl:      s.env.mail.mailerService.url,
		IsSandbox:   s.env.mail.isSandbox,
		MaxRetires:  s.env.mail.maxRetires,
	}
	var client mailer.Mailer
	switch s.env.mail.client {
	case "smtp":
		client = &mailer.SMTPClient{
			MailConfig: s.Mail,
		}
	default:
		client = &mailer.SMTPClient{
			MailConfig: s.Mail,
		}
	}
	client.InitServer()

	var d mailer.Distributor
	switch s.env.mail.distributor {
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

	s.Mail.Distributor = d

	go d.ListenForMail(client, s.Mail.IsSandbox)
	return nil
}

func (s *Socle) initServer() error {
	if !InArrayStr(s.AppModule.Type, []string{"web", "api/rest"}) {
		return nil
	}

	s.Server = Server{
		Name:    s.env.serverName,
		Address: s.env.serverAddress,
	}

	s.Server.Port = s.AppModule.Config.Port
	s.Server.Secure = s.AppModule.Config.Security.Enabled
	s.Server.Security.Strategy = s.AppModule.Config.Security.TLS.Strategy
	s.Server.Security.MutualTLS = s.AppModule.Config.Security.TLS.Mutual
	s.Server.Security.CAName = s.AppModule.Config.Security.TLS.CACertName
	s.Server.Security.ServerCertName = s.AppModule.Config.Security.TLS.ServerCertName
	s.Server.Security.ClientCertName = s.AppModule.Config.Security.TLS.ClientCertName
	return nil

}

func (s *Socle) InitSession() error {
	// if s.entry != "web" {
	// 	return nil
	// }

	sess := session.Session{
		CookieLifetime: s.env.cookie.lifetime,
		CookiePersist:  s.env.cookie.persist,
		CookieName:     s.env.cookie.name,
		SessionType:    s.env.sessionType,
	}

	if s.env.cookie.domain != "" {
		sess.CookieDomain = s.env.cookie.domain
	}
	switch s.env.sessionType {
	case "redis":
		sess.RedisPool = redisCache.Conn
	case "mysql", "postgres", "mariadb", "postgresql":
		sess.DBPool = s.DB.Pool
	}

	s.Session = sess.InitSession()
	return nil
}

func (s *Socle) initRenderer() error {
	if s.AppModule.Type != "web" {
		return nil
	}

	switch s.AppModule.Config.Render {
	case "templ":
		rd := &render.TemplRender{}
		rd.RootPath = s.RootPath
		rd.Session = s.Session
		s.Render = rd

	// 		s.Render = &render.Render{
	// 	Renderer: s.appConfig.Entries.Web.Render,
	// 	RootPath: s.RootPath,
	// 	Session:  s.Session,
	// }
	case "jet":
		rd := &render.JetRender{}
		rd.RootPath = s.RootPath
		rd.Session = s.Session
		s.Render = rd
	default:

	}
	return nil
}

func (s *Socle) initAuthentificator() error {
	if s.AppModule.Type != "api/rest" {
		return nil
	}

	s.Authenticator = auth.NewJWTAuthenticator(
		s.env.auth.token.secret,
		s.env.auth.token.iss,
		s.env.auth.token.iss,
	)

	return nil
}

func (s *Socle) initRateLimiter() error {
	s.RateLimiter = ratelimiter.NewFixedWindowLimiter(
		s.env.rateLimiter.RequestsPerTimeFrame,
		s.env.rateLimiter.TimeFrame,
	)

	return nil
}

func (s *Socle) initFileSystems() error {
	s.FileSystems = make(map[string]filesystems.FS)
	if s.env.filesystems.s3.key != "" {
		s3 := s3filesystem.S3{
			Key:      s.env.filesystems.s3.key,
			Secret:   s.env.filesystems.s3.secret,
			Region:   s.env.filesystems.s3.region,
			Endpoint: s.env.filesystems.s3.endpoint,
			Bucket:   s.env.filesystems.s3.bucket,
		}
		s.FileSystems["S3"] = &s3
	}

	if s.env.filesystems.minio.secret != "" {
		useSSL := false
		if s.env.filesystems.minio.useSSL {
			useSSL = true
		}

		minio := miniofilesystem.Minio{
			Endpoint: s.env.filesystems.minio.endpoint,
			Key:      s.env.filesystems.minio.key,
			Secret:   s.env.filesystems.minio.secret,
			UseSSL:   useSSL,
			Region:   s.env.filesystems.minio.region,
			Bucket:   s.env.filesystems.minio.bucket,
		}
		s.FileSystems["MINIO"] = &minio
	}

	if s.env.filesystems.sftp.host != "" {
		sftp := sftpfilesystem.SFTP{
			Host: s.env.filesystems.sftp.host,
			User: s.env.filesystems.sftp.user,
			Pass: s.env.filesystems.sftp.pass,
			Port: s.env.filesystems.sftp.port,
		}
		s.FileSystems["SFTP"] = &sftp
	}

	if s.env.filesystems.webDAV.host != "" {
		webDav := webdavfilesystem.WebDAV{
			Host: s.env.filesystems.webDAV.host,
			User: s.env.filesystems.webDAV.user,
			Pass: s.env.filesystems.webDAV.pass,
		}
		s.FileSystems["WEBDAV"] = &webDav
	}

	return nil
}

func (s *Socle) initMetrics() error {
	expvar.NewString("version").Set(s.Version)
	expvar.Publish("database", expvar.Func(func() any {
		return s.DB.Pool.Stats()
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

func (s *Socle) listenMaintenance() {
	// if nothing specified for rpc port, don't start
	port := s.AppModule.Config.MaintenancePort
	if port != 0 {
		s.Log.InfoLog.Println("Starting RPC server on port", port)
		err := rpc.Register(new(MaintenanceServer))
		if err != nil {
			s.Log.ErrorLog.Println(err)
			return
		}
		listen, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			s.Log.ErrorLog.Println(err)
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
