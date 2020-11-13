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
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

type Application struct {
	engine                 *gin.Engine
	Config                 *config.Config
	Logger                 *zap.Logger
	AuthenticationProvider authentication.Provider
}

type Form struct {
	Letter string `form:"letter" binding:"required"`
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
		profile := sess.Get("profile")
		if profile == nil {
			c.Redirect(http.StatusTemporaryRedirect, "/login")
			return
		}

		c.HTML(http.StatusOK, "index.tmpl", profile)
		return
	})

	r.POST("/submit", func(c *gin.Context) {
		form := new(Form)

		version := "final"
		if c.PostForm("submit") == "Save Draft" {
			version = "draft"
		}

		if err := c.ShouldBind(form); err != nil {
			logger.Sugar().Infof("post route: %v\n", err)
			c.Redirect(http.StatusMovedPermanently, "/")
			return
		}

		err = ioutil.WriteFile(fmt.Sprintf("letters/%s/mob_%d.txt", version, time.Now().Unix()), []byte(form.Letter), os.ModePerm)
		if err != nil {
			logger.Sugar().Errorf("post route: %v\n", err)
			c.Redirect(http.StatusMovedPermanently, "/")
			return
		}

		c.Redirect(http.StatusMovedPermanently, "/")
	})

	auth, err := conf.Authenticator.Config.Open(logger)
	if err != nil {
		logger.Sugar().Fatalf("server: %v", err)
		return
	}

	r.GET("/login", func(c *gin.Context) {
		auth.Login(c)
	})
	r.GET("/logout", func(c *gin.Context) {
		auth.Logout(c)
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
