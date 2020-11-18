package gins

import (
	"github.com/gin-gonic/gin"
	"github.com/storyicon/grbac"
	"net/http"
	"time"
)

func Authorization(rulesLoader  func()(grbac.Rules, error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		rbac, err := grbac.New(grbac.WithLoader(rulesLoader, time.Minute))
		if err != nil {
			_ = c.AbortWithError(http.StatusInternalServerError, err)
			log.Error(err.Error())
			return
		}
		g := Gin{Ctx: c}
		roles := []string{g.Trace().UserRole}
		state, _ := rbac.IsRequestGranted(c.Request, roles)
		if !state.IsGranted() {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}