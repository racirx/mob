package authentication

import "github.com/gin-gonic/gin"

type Provider interface {
	Login(ctx *gin.Context)
	Logout(ctx *gin.Context)
	Callback(ctx *gin.Context)
}
