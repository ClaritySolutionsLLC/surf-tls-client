package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sync"
	"unsafe"

	surf_tls_cffi_src "github.com/ClaritySolutionsLLC/surf-tls-client/cffi_src"
	"github.com/enetx/http"
	"github.com/google/uuid"
)

var (
	unsafePointers    = make(map[string]*C.char)
	unsafePointersLck = sync.Mutex{}
)

//export freeMemory
func freeMemory(responseId *C.char) {
	responseIdString := C.GoString(responseId)

	unsafePointersLck.Lock()
	defer unsafePointersLck.Unlock()

	ptr, ok := unsafePointers[responseIdString]

	if !ok {
		return
	}

	C.free(unsafe.Pointer(ptr))

	delete(unsafePointers, responseIdString)
}

//export destroyAll
func destroyAll() *C.char {
	surf_tls_cffi_src.ClearSessionCache()

	out := surf_tls_cffi_src.DestroyOutput{
		Id:      uuid.New().String(),
		Success: true,
	}

	jsonResponse, marshallError := json.Marshal(out)

	if marshallError != nil {
		clientErr := surf_tls_cffi_src.NewSurfTLSClientError(marshallError)

		return handleErrorResponse("", false, clientErr)
	}

	responseString := C.CString(string(jsonResponse))

	unsafePointersLck.Lock()
	unsafePointers[out.Id] = responseString
	unsafePointersLck.Unlock()

	return responseString
}

//export destroySession
func destroySession(destroySessionParams *C.char) *C.char {
	destroySessionParamsJson := C.GoString(destroySessionParams)

	destroySessionInput := surf_tls_cffi_src.DestroySessionInput{}
	marshallError := json.Unmarshal([]byte(destroySessionParamsJson), &destroySessionInput)

	if marshallError != nil {
		clientErr := surf_tls_cffi_src.NewSurfTLSClientError(marshallError)

		return handleErrorResponse("", false, clientErr)
	}

	surf_tls_cffi_src.RemoveSession(destroySessionInput.SessionId)

	out := surf_tls_cffi_src.DestroyOutput{
		Id:      uuid.New().String(),
		Success: true,
	}

	jsonResponse, marshallError := json.Marshal(out)

	if marshallError != nil {
		clientErr := surf_tls_cffi_src.NewSurfTLSClientError(marshallError)

		return handleErrorResponse(destroySessionInput.SessionId, true, clientErr)
	}

	responseString := C.CString(string(jsonResponse))

	unsafePointersLck.Lock()
	unsafePointers[out.Id] = responseString
	unsafePointersLck.Unlock()

	return responseString
}

//export getCookiesFromSession
func getCookiesFromSession(getCookiesParams *C.char) *C.char {
	getCookiesParamsJson := C.GoString(getCookiesParams)

	cookiesInput := surf_tls_cffi_src.GetCookiesFromSessionInput{}
	marshallError := json.Unmarshal([]byte(getCookiesParamsJson), &cookiesInput)

	if marshallError != nil {
		clientErr := surf_tls_cffi_src.NewSurfTLSClientError(marshallError)

		return handleErrorResponse("", false, clientErr)
	}

	surfClient, err := surf_tls_cffi_src.GetClient(cookiesInput.SessionId)
	if err != nil {
		clientErr := surf_tls_cffi_src.NewSurfTLSClientError(err)

		return handleErrorResponse(cookiesInput.SessionId, true, clientErr)
	}

	u, parsErr := url.Parse(cookiesInput.Url)
	if parsErr != nil {
		clientErr := surf_tls_cffi_src.NewSurfTLSClientError(parsErr)

		return handleErrorResponse(cookiesInput.SessionId, true, clientErr)
	}

	// Get cookies from surf client
	// Note: surf uses http.Client which has a cookie jar
	cookies := surfClient.GetClient().Jar.Cookies(u)

	out := surf_tls_cffi_src.CookiesFromSessionOutput{
		Id:      uuid.New().String(),
		Cookies: transformCookies(cookies),
	}

	jsonResponse, marshallError := json.Marshal(out)

	if marshallError != nil {
		clientErr := surf_tls_cffi_src.NewSurfTLSClientError(marshallError)

		return handleErrorResponse(cookiesInput.SessionId, true, clientErr)
	}

	responseString := C.CString(string(jsonResponse))

	unsafePointersLck.Lock()
	unsafePointers[out.Id] = responseString
	unsafePointersLck.Unlock()

	return responseString
}

//export addCookiesToSession
func addCookiesToSession(addCookiesParams *C.char) *C.char {
	addCookiesParamsJson := C.GoString(addCookiesParams)

	cookiesInput := surf_tls_cffi_src.AddCookiesToSessionInput{}
	marshallError := json.Unmarshal([]byte(addCookiesParamsJson), &cookiesInput)

	if marshallError != nil {
		clientErr := surf_tls_cffi_src.NewSurfTLSClientError(marshallError)

		return handleErrorResponse("", false, clientErr)
	}

	surfClient, err := surf_tls_cffi_src.GetClient(cookiesInput.SessionId)
	if err != nil {
		clientErr := surf_tls_cffi_src.NewSurfTLSClientError(err)

		return handleErrorResponse(cookiesInput.SessionId, true, clientErr)
	}

	u, parsErr := url.Parse(cookiesInput.Url)
	if parsErr != nil {
		clientErr := surf_tls_cffi_src.NewSurfTLSClientError(parsErr)

		return handleErrorResponse(cookiesInput.SessionId, true, clientErr)
	}

	// Set cookies in surf client's cookie jar
	cookies := buildCookies(cookiesInput.Cookies)
	if surfClient.GetClient().Jar != nil {
		surfClient.GetClient().Jar.SetCookies(u, cookies)
	}

	allCookies := surfClient.GetClient().Jar.Cookies(u)

	out := surf_tls_cffi_src.CookiesFromSessionOutput{
		Id:      uuid.New().String(),
		Cookies: transformCookies(allCookies),
	}

	jsonResponse, marshallError := json.Marshal(out)

	if marshallError != nil {
		clientErr := surf_tls_cffi_src.NewSurfTLSClientError(marshallError)

		return handleErrorResponse(cookiesInput.SessionId, true, clientErr)
	}

	responseString := C.CString(string(jsonResponse))

	unsafePointersLck.Lock()
	unsafePointers[out.Id] = responseString
	unsafePointersLck.Unlock()

	return responseString
}

//export request
func request(requestParams *C.char) *C.char {
	requestParamsJson := C.GoString(requestParams)

	requestInput := surf_tls_cffi_src.RequestInput{}
	marshallError := json.Unmarshal([]byte(requestParamsJson), &requestInput)

	if marshallError != nil {
		clientErr := surf_tls_cffi_src.NewSurfTLSClientError(marshallError)

		return handleErrorResponse("", false, clientErr)
	}

	surfClient, sessionId, withSession, err := surf_tls_cffi_src.CreateClient(requestInput)
	if err != nil {
		return handleErrorResponse(sessionId, withSession, err)
	}

	req, err := surf_tls_cffi_src.BuildRequest(surfClient, requestInput)
	if err != nil {
		clientErr := surf_tls_cffi_src.NewSurfTLSClientError(err)

		return handleErrorResponse(sessionId, withSession, clientErr)
	}

	// Set cookies
	cookies := buildCookies(requestInput.RequestCookies)
	if len(cookies) > 0 {
		req.AddCookies(cookies...)
	}

	// Execute the request
	result := req.Do()
	if result.IsErr() {
		clientErr := surf_tls_cffi_src.NewSurfTLSClientError(result.Err())
		return handleErrorResponse(sessionId, withSession, clientErr)
	}

	resp := result.Unwrap()

	if resp == nil {
		clientErr := surf_tls_cffi_src.NewSurfTLSClientError(fmt.Errorf("response is nil"))
		return handleErrorResponse(sessionId, withSession, clientErr)
	}

	response, err := surf_tls_cffi_src.BuildResponse(sessionId, withSession, resp, requestInput)
	if err != nil {
		return handleErrorResponse(sessionId, withSession, err)
	}

	jsonResponse, marshallError := json.Marshal(response)

	if marshallError != nil {
		clientErr := surf_tls_cffi_src.NewSurfTLSClientError(marshallError)

		return handleErrorResponse(sessionId, withSession, clientErr)
	}

	responseString := C.CString(string(jsonResponse))

	unsafePointersLck.Lock()
	unsafePointers[response.Id] = responseString
	unsafePointersLck.Unlock()

	return responseString
}

func handleErrorResponse(sessionId string, withSession bool, err *surf_tls_cffi_src.SurfTLSClientError) *C.char {
	response := surf_tls_cffi_src.Response{
		Id:      uuid.New().String(),
		Status:  0,
		Body:    err.Error(),
		Headers: nil,
		Cookies: nil,
	}

	if withSession {
		response.SessionId = sessionId
	}

	jsonResponse, marshallError := json.Marshal(response)

	if marshallError != nil {
		errStr := C.CString(marshallError.Error())

		return errStr
	}

	responseString := C.CString(string(jsonResponse))

	unsafePointersLck.Lock()
	unsafePointers[response.Id] = responseString
	unsafePointersLck.Unlock()

	return responseString
}

func buildCookies(cookies []surf_tls_cffi_src.Cookie) []*http.Cookie {
	var ret []*http.Cookie

	for _, cookie := range cookies {
		ret = append(ret, &http.Cookie{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Path:     cookie.Path,
			Domain:   cookie.Domain,
			Expires:  cookie.Expires.Time,
			MaxAge:   cookie.MaxAge,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HttpOnly,
		})
	}

	return ret
}

func transformCookies(cookies []*http.Cookie) []surf_tls_cffi_src.Cookie {
	var ret []surf_tls_cffi_src.Cookie

	for _, cookie := range cookies {
		ret = append(ret, surf_tls_cffi_src.Cookie{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Path:     cookie.Path,
			Domain:   cookie.Domain,
			MaxAge:   cookie.MaxAge,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HttpOnly,
			Expires: surf_tls_cffi_src.Timestamp{
				Time: cookie.Expires,
			},
		})
	}

	return ret
}

func main() {
}
