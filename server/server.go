package server

import (
	"encoding/gob"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"github.com/racirx/mob/authentication"
	"github.com/racirx/mob/config"
	"go.uber.org/zap"
	"log"
	"net/http"
	"time"
)

type Application struct {
	engine                 *gin.Engine
	Config                 *config.Config
	Logger                 *zap.Logger
	AuthenticationProvider authentication.Provider
}

func (a *Application) Initialize(conf *config.Config) {
	r := gin.New()

	logConf := zap.NewProductionConfig()
	logConf.Level.SetLevel(conf.ServerConfig.Logger.Level)
	logConf.Encoding = conf.ServerConfig.Logger.Encoding
	logger, err := logConf.Build()
	if err != nil {
		log.Fatalf("server: error initializing logger: %v\n", err)
	}

	//defer func() {
	//	if err := logger.Sync(); err != nil {
	//		log.Fatalf("server: logger error: %v\n", err)
	//	}
	//}()

	r.Use(ginzap.Ginzap(logger, time.RFC3339, false))
	r.Use(ginzap.RecoveryWithZap(logger, true))

	r.LoadHTMLGlob("templates/*")

	gob.Register(map[string]interface{}{})
	r.Use(sessions.Sessions("session", cookie.NewStore([]byte(conf.ServerConfig.Key))))

	r.GET("/", func(c *gin.Context) {
		logger.Debug("route: loading template: index")
		sess := sessions.Default(c)
		if sess.Get("profile") == nil {
			c.Redirect(http.StatusTemporaryRedirect, "/login")
			return
		}

		c.HTML(http.StatusOK, "index.tmpl", gin.H{
			"title": "MOB",
		})
		return
	})

	auth, err := conf.Authenticator.Config.Open(logger)
	if err != nil {
		logger.Sugar().Fatalf("server: %v", err)
		return
	}

	r.GET("/login", func(c *gin.Context) {
		auth.Login(c)
	})
	r.GET("/callback", func(c *gin.Context) {
		auth.Callback(c)
	})

	*a = Application{
		engine:                 r,
		Config:                 conf,
		Logger:                 logger,
		AuthenticationProvider: auth,
	}
}

func (a *Application) Run() {
	if err := a.engine.Run(fmt.Sprintf(":%s", a.Config.ServerConfig.Port)); err != nil {
		a.Logger.Fatal(fmt.Sprintf("server: %v\n", err))
	}
}
