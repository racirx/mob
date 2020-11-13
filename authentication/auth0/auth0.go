package auth0

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/racirx/mob/authentication"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"strings"
)

type Config struct {
	Issuer       string `json:"issuer"`
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	RedirectURL  string `json:"redirectUrl"`
	Scopes       string `json:"scopes"`
	LogoutUri    string `json:"logoutUri"`
}

func (c *Config) Open(logger *zap.Logger) (authentication.Provider, error) {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		logger.Sugar().Errorf("auth0: error opening authenticator: %v", err)
		return nil, err
	}

	conf := oauth2.Config{
		ClientID:     c.ClientId,
		ClientSecret: c.ClientSecret,
		RedirectURL:  c.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       strings.Split(c.Scopes, " "),
	}

	return &Auth0{
		IdentityProvider: provider,
		OauthConfig:      conf,
		Ctx:              ctx,
		Logger:           logger,
		config:           c,
	}, nil

}

type Auth0 struct {
	IdentityProvider *oidc.Provider
	OauthConfig      oauth2.Config
	Ctx              context.Context
	Logger           *zap.Logger
	config           *Config
}

func (a *Auth0) Login(ctx *gin.Context) {
	// Generate random state
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		a.Logger.Sugar().Errorf("auth0: %v", err)
		ctx.HTML(http.StatusInternalServerError, "index.tmpl", gin.H{
			"error": "Error logging in",
		})
		return
	}

	state := base64.StdEncoding.EncodeToString(b)
	sess := sessions.Default(ctx)
	sess.Set("state", state)
	if err := sess.Save(); err != nil {
		a.Logger.Sugar().Errorf("auth0: %v", err)
		ctx.HTML(http.StatusInternalServerError, "index.tmpl", gin.H{
			"error": "Error logging in",
		})
		return
	}

	ctx.Redirect(http.StatusTemporaryRedirect, a.OauthConfig.AuthCodeURL(state))
}

func (a *Auth0) Logout(ctx *gin.Context) {
	var scheme string
	if ctx.Request.TLS == nil {
		scheme = "http"
	} else {
		scheme = "https"
	}

	returnTo, err := url.Parse(fmt.Sprintf("%s://%s", scheme, ctx.Request.Host))
	if err != nil {
		a.Logger.Sugar().Errorf("auth0: %v", err)
		ctx.HTML(http.StatusInternalServerError, "index.tmpl", gin.H{
			"error": "Error Logging out",
		})
		return
	}

	logoutUrl, err := url.Parse(a.config.Issuer + a.config.LogoutUri)
	if err != nil {
		a.Logger.Sugar().Errorf("auth0: %v", err)
		ctx.HTML(http.StatusInternalServerError, "index.tmpl", gin.H{
			"error": "Error Logging out",
		})
		return
	}

	q := logoutUrl.Query()
	q.Add("returnTo", returnTo.String())
	q.Add("client_id", a.OauthConfig.ClientID)
	logoutUrl.RawQuery = q.Encode()

	ctx.Redirect(http.StatusTemporaryRedirect, logoutUrl.String())
}

func (a *Auth0) Callback(ctx *gin.Context) {
	sess := sessions.Default(ctx)
	state := sess.Get("state")

	if state != nil {
		if ctx.Query("state") != state {
			a.Logger.Sugar().Error("auth0: state mismatch")
			ctx.HTML(http.StatusInternalServerError, "index.tmpl", gin.H{
				"error": "Error logging in",
			})
			return
		}
	}

	code := ctx.Query("code")
	if code == "" {
		a.Logger.Sugar().Error("auth0: no code")
		ctx.HTML(http.StatusInternalServerError, "index.tmpl", gin.H{
			"error": "Error logging in",
		})
		return
	}

	token, err := a.OauthConfig.Exchange(context.TODO(), code)
	if err != nil {
		a.Logger.Sugar().Errorf("auth0: %v", err)
		ctx.HTML(http.StatusUnauthorized, "index.tmpl", gin.H{
			"error": "Error logging in",
		})
		return
	}

	rawIdToken, ok := token.Extra("id_token").(string)
	if !ok {
		a.Logger.Sugar().Error("auth0: no id token in response")
		ctx.HTML(http.StatusUnauthorized, "index.tmpl", gin.H{
			"error": "Error logging in",
		})
		return
	}

	oidcConfig := &oidc.Config{ClientID: a.OauthConfig.ClientID}

	idToken, err := a.IdentityProvider.Verifier(oidcConfig).Verify(context.TODO(), rawIdToken)
	if err != nil {
		a.Logger.Sugar().Errorf("auth0: %v", err)
		ctx.HTML(http.StatusUnauthorized, "index.tmpl", gin.H{
			"error": "Error logging in",
		})
		return
	}

	var profile map[string]interface{}
	if err = idToken.Claims(&profile); err != nil {
		a.Logger.Sugar().Errorf("auth0: %v", err)
		ctx.HTML(http.StatusUnauthorized, "index.tmpl", gin.H{
			"error": "Error logging in",
		})
		return
	}

	sess.Set("id_token", rawIdToken)
	sess.Set("access_token", token.AccessToken)
	sess.Set("profile", profile)

	if err = sess.Save(); err != nil {
		a.Logger.Sugar().Errorf("auth0: %v", err)
		ctx.HTML(http.StatusUnauthorized, "index.tmpl", gin.H{
			"error": "Error logging in",
		})
		return
	}

	ctx.Redirect(http.StatusSeeOther, "/")
}
