package sso

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/devopsfaith/krakend/config"
	"github.com/devopsfaith/krakend/logging"
	"github.com/devopsfaith/krakend/proxy"
	"github.com/devopsfaith/krakend/transport/http/client"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

const Namespace = "github.com/gs012345/sso"

func SsoNewBackendFactory(logger logging.Logger, re client.HTTPRequestExecutor) proxy.BackendFactory {
	return NewConfiguredBackendFactory(logger, func(_ *config.Backend) client.HTTPRequestExecutor { return re })
}

func NewConfiguredBackendFactory(logger logging.Logger, ref func(*config.Backend) client.HTTPRequestExecutor) proxy.BackendFactory {
	//parse.Register("static.Modifier", staticModifierFromJSON)
	return func(remote *config.Backend) proxy.Proxy {
		//logger.Error(result, remote.ExtraConfig)
		re := ref(remote) // 这个是可以获取到配置参数的
		ok, err := ConfigGetter(remote.ExtraConfig)
		if err != nil { // 不能存在或者不生效的话, 都不能, 都返回默认的
			fmt.Println("不使用插件...")
			return proxy.NewHTTPProxyWithHTTPExecutor(remote, re, remote.Decoder)
		}
		if !ok {
			fmt.Println("不使用插件...")
			return proxy.NewHTTPProxyWithHTTPExecutor(remote, re, remote.Decoder)
		} // 如果存在的话, 走插件处理...
		fmt.Println("使用插件...")
		return proxy.NewHTTPProxyWithHTTPExecutor(remote, HTTPRequestExecutor(re), remote.Decoder)
	}

}

func HTTPRequestExecutor(re client.HTTPRequestExecutor) client.HTTPRequestExecutor {
	return func(ctx context.Context, req *http.Request) (resp *http.Response, err error) {
		if err = modifyRequest(req); err != nil {
			if resp == nil {
				resp = &http.Response{
					Request:    req,
					Header:     http.Header{},
					StatusCode: http.StatusOK,
				}
			}
			respErr := modifyResponse(resp, err)
			if respErr != nil {
				return
			}
			return resp, nil
		}
		mctx, ok := req.Context().(*Context)
		if !ok || !mctx.SkippingRoundTrip() {
			resp, err = re(ctx, req)
			if err != nil {
				return
			}
			if resp == nil {
				err = ErrEmptyResponse
				return
			}
		} else if resp == nil {
			resp = &http.Response{
				Request:    req,
				Header:     http.Header{},
				StatusCode: http.StatusOK,
				Body:       ioutil.NopCloser(bytes.NewBufferString("")),
			}
		}
		err = modifyResponse(resp, nil)
		return
	}
}

func modifyRequest(req *http.Request) error {
	if _, ok := req.Header["X-Sso-Fullticketid"]; !ok {
		return errors.New("缺少认证header信息")
	}
	ticket := req.Header["X-Sso-Fullticketid"][0]
	//fmt.Printf("获取到的请求头是:%s", ticket)
	//fmt.Println("获取到的值是:")
	//fmt.Println(req.Header["X-Sso-Fullticketid"][0])
	userInfo, err := ssoGetUserModel(ticket)
	if err != nil {
		return fmt.Errorf("请求校验sso失败:%s", err.Error())
	}
	if userInfo.ErrorCode == 4012 {
		return fmt.Errorf("非法的ticket:%s", userInfo.Message)
	}
	if userInfo.Data == nil {
		return fmt.Errorf("当前用户不存在:%s", userInfo.Message)
	}
	fmt.Println(userInfo.Data.LoginEmail)
	req.Header["UserEmail"] = []string{userInfo.Data.LoginEmail}
	req.Header["AccountGuid"] = []string{userInfo.Data.AccountGuid}
	return nil
}

func modifyResponse(resp *http.Response, err error) error {
	if resp.Header == nil {
		resp.Header = http.Header{}
	}
	if resp.StatusCode == 0 {
		resp.StatusCode = http.StatusOK
	}
	if err != nil {
		rsp := Response{
			ErrorId: 4001,
			Reason:  fmt.Sprintf("认证失败:%s", err.Error()),
			Desc:    fmt.Sprintf("认证失败:%s", err.Error()),
		}
		response, jsonErr := json.Marshal(rsp)
		if jsonErr != nil {
			resp.Body = ioutil.NopCloser(bytes.NewBufferString(fmt.Sprintf("数据反序列化失败:%s", jsonErr.Error())))
		}
		resp.Body = ioutil.NopCloser(bytes.NewBuffer(response))
	}
	return nil
}

var (
	// ErrEmptyValue is the error returned when there is no config under the namespace
	//ErrEmptyValue = errors.New("getting the extra config for the martian module")
	//// ErrBadValue is the error returned when the config is not a map
	//ErrBadValue = errors.New("casting the extra config for the martian module")
	//// ErrMarshallingValue is the error returned when the config map can not be marshalled again
	//ErrMarshallingValue = errors.New("marshalling the extra config for the martian module")
	// ErrEmptyResponse is the error returned when the modifier receives a nil response
	ErrEmptyResponse = errors.New("getting the http response from the request executor")
)

type Context struct {
	context.Context
	skipRoundTrip bool
}

// SkipRoundTrip flags the context to skip the round trip
func (c *Context) SkipRoundTrip() {
	c.skipRoundTrip = true
}

// SkippingRoundTrip returns the flag for skipping the round trip
func (c *Context) SkippingRoundTrip() bool {
	return c.skipRoundTrip
}

var _ context.Context = &Context{Context: context.Background()}

func ssoGetUserModel(ticket string) (*SsoTicketUserInfoResponse, error) {
	token_url := ""
	reqClient := &http.Client{}
	v := url.Values{}
	req, err := http.NewRequest("GET", token_url, strings.NewReader(v.Encode()))
	req.Header.Set("ticket", ticket)
	resp, err := reqClient.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var token_response SsoTicketUserInfoResponse
	err = json.Unmarshal(body, &token_response)
	return &token_response, nil

}

type SsoTicketUserInfoResponse struct {
	ErrorCode int      `json:"errorCode"`
	Data      *SsoData `json:"data"`
	Message   string   `json:"message"`
}

type SsoData struct {
	LoginEmail  string `json:"LoginEmail"`
	AccountGuid string `json:"AccountGuid"`
	DisplayName string `json:"DisplayName"`
}

type Response struct {
	ErrorId int    `json:"error_id"`
	Reason  string `json:"reason"`
	Desc    string `json:"desc"`
}

func ConfigGetter(e config.ExtraConfig) (bool, error) {
	_, ok := e[Namespace]
	if !ok {
		return false, nil
	}
	fmt.Println("进入判断插件...")
	return true, nil
	//data, ok := cfg.(map[string]interface{})
	//if !ok {
	//	return false, ErrEmptyResponse
	//}

	//raw, err := json.Marshal(data)
	//if err != nil {
	//	return false, ErrEmptyResponse
	//}
	//
	//r, err := parse.FromJSON(raw)
	//
	//return true, nil
}
