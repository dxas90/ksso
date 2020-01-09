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

const Namespace string = "github.com/gs012345/sso"

func SsoNewBackendFactory(logger logging.Logger, re client.HTTPRequestExecutor) proxy.BackendFactory {
	return NewConfiguredBackendFactory(logger, func(_ *config.Backend) client.HTTPRequestExecutor { return re })
}

func NewConfiguredBackendFactory(logger logging.Logger, ref func(*config.Backend) client.HTTPRequestExecutor) proxy.BackendFactory {
	//parse.Register("static.Modifier", staticModifierFromJSON)
	return func(remote *config.Backend) proxy.Proxy {
		//logger.Error(result, remote.ExtraConfig)
		re := ref(remote)
		_, ok := remote.ExtraConfig[Namespace]
		if !ok {
			return proxy.NewHTTPProxyWithHTTPExecutor(remote, re, remote.Decoder)
		} // 如果存在的话, 走插件处理...
		fmt.Println("use sso plugin...")
		return proxy.NewHTTPProxyWithHTTPExecutor(remote, HTTPRequestExecutor(re, remote), remote.Decoder)
	}

}

func HTTPRequestExecutor(re client.HTTPRequestExecutor, remote *config.Backend) client.HTTPRequestExecutor {
	return func(ctx context.Context, req *http.Request) (resp *http.Response, err error) {
		if err = checkRequest(req, remote.ExtraConfig); err != nil {
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

func checkRequest(req *http.Request, remote config.ExtraConfig) error {
	configMap, anonymous, err := ConfigGetter(remote)
	if err != nil{
		return err
	}
	if !anonymous{
		req.Header[configMap["user-email"].(string)] = []string{configMap["anonymous"].(string)}
		//req.Header["Account-Guid"] = []string{userInfo.Data.AccountGuid}
		return nil
	}
	ssoHeader := configMap["sso-header"]
	if _, ok := req.Header[ssoHeader.(string)]; !ok {
		logger.Error("缺少认证header信息")
		return errors.New("缺少认证header信息")
	}
	ticket := req.Header[ssoHeader.(string)][0]
	ssoUrl := configMap["sso-addr"]
	userInfo, err := ssoGetUserModel(ticket, ssoUrl.(string))
	if err != nil {
		return fmt.Errorf("请求校验鉴权失败:%s", err.Error())
	}
	if userInfo.ErrorCode == 4012 {
		logger.Errorf("原因非法的用户认证信息:%s", userInfo.Message)
		return fmt.Errorf("原因非法的用户认证信息:%s", userInfo.Message)
	}
	if userInfo.Data == nil {
		logger.Errorf("当前用户不存在:%s", userInfo.Message)
		return fmt.Errorf("当前用户不存在:%s", userInfo.Message)
	}

	req.Header[configMap["user-email"].(string)] = []string{userInfo.Data.LoginEmail}
	req.Header[configMap["account-guid"].(string)] = []string{userInfo.Data.AccountGuid}
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
			ErrorId: 4004,
			Reason:  fmt.Sprintf("鉴权失败:%s", err.Error()),
			Desc:    fmt.Sprintf("鉴权失败:%s", err.Error()),
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

func ConfigGetter(e config.ExtraConfig) (map[string]interface{}, bool, error) {
	var(
		ssoConfig interface{}
		ok bool
	)
	logger.Info("get sso plugin args")
	if ssoConfig,ok = e[Namespace];!ok{
		return nil, false, errors.New("请配置sso插件")
	}
	value := ssoConfig.(map[string]interface{})
	if _, ok = value["user-email"]; !ok{
		return value, false, errors.New("缺少后端使用的header信息user-email")
	}
	if _, ok = value["account-guid"]; !ok{
		return value, false, errors.New("缺少后端使用的header信息account-guid")
	}
	if _, ok = value["anonymous"]; ok{
		return value, false, nil
	}
	if _, ok = value["sso-addr"]; !ok{
		return value, false, errors.New("缺少访问sso的请求url")
	}
	if _, ok = value["sso-header"]; !ok{
		return value, false, errors.New("缺少认证的header信息sso-header")
	}
	logger.Info("调用sso backend proxy")
	return value, true, nil
}
