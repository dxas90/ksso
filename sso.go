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
	logger "github.com/sirupsen/logrus"
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
		//if err != nil { // 不能存在或者不生效的话, 都不能, 都返回默认的
		//	return proxy.NewHTTPProxyWithHTTPExecutor(remote, re, remote.Decoder)
		//}
		//if !ok {
		//	return proxy.NewHTTPProxyWithHTTPExecutor(remote, re, remote.Decoder)
		//} // 如果存在的话, 走插件处理...
		logger.Info("use sso plugin")
		return proxy.NewHTTPProxyWithHTTPExecutor(remote, HTTPRequestExecutor(re, remote), remote.Decoder)
	}

}

func HTTPRequestExecutor(re client.HTTPRequestExecutor, remote *config.Backend) client.HTTPRequestExecutor {
	return func(ctx context.Context, req *http.Request) (resp *http.Response, err error) {
		if err = checkRequest(req, remote); err != nil {
			resp = &http.Response{Request:req}
			verifyResponse(resp, err)
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
		verifyResponse(resp, nil)
		return
	}
}

func checkRequest(req *http.Request, remote *config.Backend) error {
	configMap, anonymous, err := ConfigGetter(remote.ExtraConfig)
	if err != nil{
		return err
	}
	if !anonymous{
		req.Header[configMap["user-email"]] = []string{configMap["anonymous"]}
		//req.Header["Account-Guid"] = []string{userInfo.Data.AccountGuid}
		return nil
	}
	ssoHeader := configMap["sso-header"]
	if _, ok := req.Header[ssoHeader]; !ok {
		logger.Error("缺少认证header信息")
		return errors.New("缺少认证header信息")
	}
	ticket := req.Header[ssoHeader][0]
	ssoUrl := configMap["sso-addr"]
	userInfo, err := ssoGetUserModel(ticket, ssoUrl)
	if err != nil {
		return fmt.Errorf("请求校验sso失败:%s", err.Error())
	}
	if userInfo.ErrorCode == 4012 {
		logger.Errorf("非法的ticket:%s", userInfo.Message)
		return fmt.Errorf("非法的ticket:%s", userInfo.Message)
	}
	if userInfo.Data == nil {
		logger.Errorf("当前用户不存在:%s", userInfo.Message)
		return fmt.Errorf("当前用户不存在:%s", userInfo.Message)
	}
	req.Header[configMap["user-email"]] = []string{userInfo.Data.LoginEmail}
	req.Header[configMap["account-guid"]] = []string{userInfo.Data.AccountGuid}
	return nil
}

func verifyResponse(resp *http.Response, err error) {
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

//// SkippingRoundTrip returns the flag for skipping the round trip
func (c *Context) SkippingRoundTrip() bool {
	return c.skipRoundTrip
}

func ssoGetUserModel(ticket, ssoUrl string) (*SsoTicketUserInfoResponse, error) {
	if ssoUrl == ""{
		return nil, errors.New("sso的地址不能为空")
	}
	logger.Info("request sso ")
	reqClient := &http.Client{}
	v := url.Values{}
	req, err := http.NewRequest("GET", ssoUrl, strings.NewReader(v.Encode()))
	if err != nil{
		return nil, err
	}
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

func ConfigGetter(e config.ExtraConfig) (map[string]string, bool, error) {
	var(
		value map[string]string
		ok bool
	)
	logger.Info("get sso plugin args")
	if value, ok = e[Namespace];!ok{
		return value, false, errors.New("请配置sso插件")
	}
	if _, ok = value["sso-addr"]; !ok{
		return value, false, errors.New("缺少访问sso的请求url")
	}
	if _, ok = value["user-email"]; !ok{
		return value, false, errors.New("缺少后端使用的header信息user-email")
	}
	if _, ok = value["account-guid"]; !ok{
		return value, false, errors.New("缺少后端使用的header信息account-guid")
	}
	if _, ok = value["anonymous"]; ok{
		return value, false, nil
	}
	if _, ok = value["sso-header"]; !ok{
		return value, false, errors.New("缺少认证的header信息sso-header")
	}
	logger.Info("调用sso backend proxy")
	return value, true, nil
}
