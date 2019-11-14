package sso

import (
	"encoding/json"
	"fmt"
	"github.com/devopsfaith/krakend/config"
	"github.com/devopsfaith/krakend/proxy"
	krakendgin "github.com/devopsfaith/krakend/router/gin"
	"github.com/gin-gonic/gin"
	logger "github.com/sirupsen/logrus"
)

var HandlerFactory = NewSSOHttpProxy(krakendgin.EndpointHandler)

// NewRateLimiterMw builds a rate limiting wrapper over the received handler factory.
func NewSSOHttpProxy(next krakendgin.HandlerFactory) krakendgin.HandlerFactory {
	return func(remote *config.EndpointConfig, p proxy.Proxy) gin.HandlerFunc {
		handlerFunc := next(remote, p)
		handlerFunc = NewEndpointRateLimiterMw(remote)(handlerFunc)
		return handlerFunc
	}
}

// EndpointMw is a function that decorates the received handlerFunc with some rateliming logic
type EndpointMw func(gin.HandlerFunc) gin.HandlerFunc

// NewEndpointRateLimiterMw creates a simple ratelimiter for a given handlerFunc
func NewEndpointRateLimiterMw(remote *config.EndpointConfig) EndpointMw {
	return func(next gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			err := checkRequest(c.Request, remote)
			if err != nil{
				rsp := Response{
					ErrorId: 4001,
					Reason:  fmt.Sprintf("认证失败%s",err.Error()),
					Desc:    fmt.Sprintf("认证失败%s", err.Error()),
				}
				response, jsonErr := json.Marshal(rsp)
				if jsonErr != nil {
					logger.Error("序列化失败")
				}
				c.Data(200, "json", response)
				return
			}
			next(c)
		}
	}
}