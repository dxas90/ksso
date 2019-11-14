package sso

import (
	"encoding/json"
	"fmt"
	"github.com/devopsfaith/krakend/config"
	"github.com/devopsfaith/krakend/proxy"
	krakendgin "github.com/devopsfaith/krakend/router/gin"
	"github.com/gin-gonic/gin"
)

var HandlerFactory = NewSSOHttpProxy(krakendgin.EndpointHandler)

// NewRateLimiterMw builds a rate limiting wrapper over the received handler factory.
func NewSSOHttpProxy(next krakendgin.HandlerFactory) krakendgin.HandlerFactory {
	return func(remote *config.EndpointConfig, p proxy.Proxy) gin.HandlerFunc {
		handlerFunc := next(remote, p)

		ok, _ := ConfigGetter(remote.ExtraConfig)
		if !ok{
			fmt.Println("没有sso的插件")
			return handlerFunc
		}
		fmt.Println("加载插件...")
		handlerFunc = NewEndpointRateLimiterMw()(handlerFunc)
		return handlerFunc
	}
}

// EndpointMw is a function that decorates the received handlerFunc with some rateliming logic
type EndpointMw func(gin.HandlerFunc) gin.HandlerFunc

// NewEndpointRateLimiterMw creates a simple ratelimiter for a given handlerFunc
func NewEndpointRateLimiterMw() EndpointMw {
	return func(next gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			err := modifyRequest(c.Request)
			if err != nil{
				rsp := Response{
					ErrorId: 4001,
					Reason:  fmt.Sprintf("认证失败%s",err.Error()),
					Desc:    fmt.Sprintf("认证失败%s", err.Error()),
				}
				response, jsonErr := json.Marshal(rsp)
				if jsonErr != nil {
					fmt.Println("反序列化失败...")
				}
				c.Data(200, "json", response)
				return
			}
			next(c)
		}
	}
}