package ksso

import "context"

type Context struct {
	context.Context
	skipRoundTrip bool
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