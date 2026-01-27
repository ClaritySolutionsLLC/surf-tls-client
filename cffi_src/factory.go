package surf_tls_cffi_src

import (
	"encoding/base64"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/surf"
	"github.com/google/uuid"
	utls "github.com/enetx/utls"
)

var clientsLock = sync.Mutex{}

// clients contains all registered clients, mapped by their individual IDs
var clients = make(map[string]*surf.Client)

// RemoveSession deletes the client with the given sessionId from the client session storage.
func RemoveSession(sessionId string) {
	clientsLock.Lock()
	defer clientsLock.Unlock()
	client, ok := clients[sessionId]
	if !ok {
		return
	}
	client.CloseIdleConnections()
	delete(clients, sessionId)
}

// ClearSessionCache empties the client session storage.
func ClearSessionCache() {
	clientsLock.Lock()
	defer clientsLock.Unlock()
	clients = make(map[string]*surf.Client)
}

// GetClient returns the client with the given sessionId from the client session storage.
// If there is no client with the given sessionId, it returns an error.
func GetClient(sessionId string) (*surf.Client, error) {
	clientsLock.Lock()
	defer clientsLock.Unlock()

	client, ok := clients[sessionId]

	if !ok {
		return nil, fmt.Errorf("no client found for sessionId: %s", sessionId)
	}

	return client, nil
}

// CreateClient creates a new client from a given RequestInput.
func CreateClient(requestInput RequestInput) (client *surf.Client, sessionID string, withSession bool, clientErr *SurfTLSClientError) {
	useSession := true
	sessionId := requestInput.SessionId

	newSessionId := uuid.New().String()
	if sessionId != nil && *sessionId != "" {
		newSessionId = *sessionId
	} else {
		useSession = false
	}

	clientsLock.Lock()
	defer clientsLock.Unlock()

	// Check if client already exists
	if existingClient, ok := clients[newSessionId]; ok && useSession {
		// Modify existing client if needed (proxy changes, etc.)
		modifiedClient, changed, err := handleModification(existingClient, requestInput.ProxyUrl, requestInput.IsRotatingProxy)
		if err != nil {
			clientErr := NewSurfTLSClientError(fmt.Errorf("failed to modify existing client: %w", err))
			return nil, newSessionId, useSession, clientErr
		}

		if changed {
			clients[newSessionId] = modifiedClient
		}

		return modifiedClient, newSessionId, useSession, nil
	}

	// Create new client
	cli := surf.NewClient()
	builder := cli.Builder()

	// Configure timeout
	timeout := time.Duration(30) * time.Second
	if requestInput.TimeoutSeconds != 0 {
		timeout = time.Duration(requestInput.TimeoutSeconds) * time.Second
	} else if requestInput.TimeoutMilliseconds != 0 {
		timeout = time.Duration(requestInput.TimeoutMilliseconds) * time.Millisecond
	}
	builder.Timeout(timeout)

	// Configure proxy
	if requestInput.ProxyUrl != nil && *requestInput.ProxyUrl != "" {
		builder.Proxy(g.String(*requestInput.ProxyUrl))
	}

	// Configure redirects
	if !requestInput.FollowRedirects {
		builder.NotFollowRedirects()
	}

	// Configure HTTP version
	if requestInput.ForceHttp1 {
		builder.ForceHTTP1()
	} else if requestInput.ForceHttp2 {
		builder.ForceHTTP2()
	} else if requestInput.ForceHttp3 {
		builder.ForceHTTP3()
	} else if requestInput.DisableHttp3 {
		// HTTP3 is disabled by default, so we don't need to do anything
	}

	// Configure JA3/4 TLS fingerprinting
	if requestInput.JA3String != "" {
		// Parse JA3 string and create custom spec
		// This would require parsing the JA3 string format
		// For now, we'll use a default Chrome fingerprint
		builder.JA().Chrome144()
	} else if requestInput.JA3HelloID != "" {
		// Map JA3HelloID to utls ClientHelloID
		helloID := mapJA3HelloID(requestInput.JA3HelloID)
		if helloID.IsSet() {
			builder.JA().SetHelloID(helloID)
		} else {
			builder.JA().Chrome144() // Default
		}
	} else {
		// Default to Chrome fingerprint
		builder.JA().Chrome144()
	}

	// Configure HTTP/2 settings if provided
	if len(requestInput.H2Settings) > 0 {
		h2Builder := builder.HTTP2Settings()
		for key, value := range requestInput.H2Settings {
			switch key {
			case "HEADER_TABLE_SIZE":
				h2Builder.HeaderTableSize(value)
			case "MAX_CONCURRENT_STREAMS":
				h2Builder.MaxConcurrentStreams(value)
			case "INITIAL_WINDOW_SIZE":
				h2Builder.InitialWindowSize(value)
			case "MAX_FRAME_SIZE":
				h2Builder.MaxFrameSize(value)
			case "MAX_HEADER_LIST_SIZE":
				h2Builder.MaxHeaderListSize(value)
			case "SETTINGS_ENABLE_PUSH":
				h2Builder.EnablePush(value)
			}
		}
		h2Builder.Set()
	}

	// Configure header order (headers are set per-request, not on the client)
	// This will be handled in BuildRequest

	// Configure insecure skip verify (default is true, so we only need to set if false)
	if !requestInput.InsecureSkipVerify {
		builder.With(func(client *surf.Client) error {
			client.GetTLSConfig().InsecureSkipVerify = false
			return nil
		}, 0)
	}

	// Build the client
	result := builder.Build()
	if result.IsErr() {
		clientErr := NewSurfTLSClientError(fmt.Errorf("failed to build client: %w", result.Err()))
		return nil, newSessionId, useSession, clientErr
	}

	builtClient := result.Unwrap()

	if useSession {
		clients[newSessionId] = builtClient
	}

	return builtClient, newSessionId, useSession, nil
}

// BuildRequest constructs a HTTP request from a given RequestInput using the provided client.
func BuildRequest(client *surf.Client, input RequestInput) (*surf.Request, *SurfTLSClientError) {
	if input.RequestMethod == "" || input.RequestUrl == "" {
		return nil, NewSurfTLSClientError(fmt.Errorf("no request url or request method provided"))
	}

	var req *surf.Request
	var requestBody interface{}

	// Handle request body
	if input.RequestBody != nil && *input.RequestBody != "" {
		if input.IsByteRequest {
			// Decode base64 if it's a byte request
			decoded, err := base64.StdEncoding.DecodeString(*input.RequestBody)
			if err != nil {
				return nil, NewSurfTLSClientError(fmt.Errorf("failed to base64 decode request body: %w", err))
			}
			requestBody = decoded
		} else {
			requestBody = *input.RequestBody
		}
	}

	switch input.RequestMethod {
	case "GET":
		req = client.Get(g.String(input.RequestUrl))
	case "POST":
		req = client.Post(g.String(input.RequestUrl), requestBody)
	case "PUT":
		req = client.Put(g.String(input.RequestUrl), requestBody)
	case "PATCH":
		req = client.Patch(g.String(input.RequestUrl), requestBody)
	case "DELETE":
		if requestBody != nil {
			req = client.Delete(g.String(input.RequestUrl), requestBody)
		} else {
			req = client.Delete(g.String(input.RequestUrl))
		}
	case "HEAD":
		req = client.Head(g.String(input.RequestUrl))
	case "OPTIONS":
		req = client.Get(g.String(input.RequestUrl)) // surf doesn't have Options, use Get
	default:
		return nil, NewSurfTLSClientError(fmt.Errorf("unsupported request method: %s", input.RequestMethod))
	}

	// Set headers
	if len(input.Headers) > 0 {
		headerMap := g.NewMapOrd[g.String, g.String]()
		for key, value := range input.Headers {
			headerMap.Insert(g.String(key), g.String(value))
		}
		req.SetHeaders(headerMap)
	}

	// Set request host override
	if input.RequestHostOverride != nil && *input.RequestHostOverride != "" {
		req.GetRequest().Host = *input.RequestHostOverride
	}

	return req, nil
}

// BuildResponse constructs a client response from a given surf Response.
func BuildResponse(sessionId string, withSession bool, resp *surf.Response, input RequestInput) (Response, *SurfTLSClientError) {
	isByteResponse := input.IsByteResponse

	var respBodyBytes []byte
	var err error

	if resp.Body != nil {
		respBodyBytes, err = io.ReadAll(resp.Body.Reader)
		if err != nil {
			clientErr := NewSurfTLSClientError(err)
			return Response{}, clientErr
		}
	}

	finalResponse := string(respBodyBytes)

	if isByteResponse {
		mimeType := http.DetectContentType(respBodyBytes)
		base64Encoding := fmt.Sprintf("data:%s;base64,", mimeType)
		base64Encoding += base64.StdEncoding.EncodeToString(respBodyBytes)
		finalResponse = base64Encoding
	}

	// Convert cookies
	cookiesMap := make(map[string]string)
	if resp.Cookies != nil {
		for _, cookie := range resp.Cookies {
			cookiesMap[cookie.Name] = cookie.Value
		}
	}

	// Convert headers
	headersMap := make(map[string][]string)
	if resp.Headers != nil {
		// Headers is http.Header which is map[string][]string
		for key, values := range http.Header(resp.Headers) {
			headersMap[key] = values
		}
	}

	response := Response{
		Id:           uuid.New().String(),
		Status:       int(resp.StatusCode),
		UsedProtocol: resp.Proto.Std(),
		Body:         finalResponse,
		Headers:      headersMap,
		Target:       "",
		Cookies:      cookiesMap,
	}

	if resp.URL != nil {
		response.Target = resp.URL.String()
	}

	if withSession {
		response.SessionId = sessionId
	}

	return response, nil
}

func handleModification(client *surf.Client, proxyUrl *string, isRotatingProxy bool) (*surf.Client, bool, error) {
	changed := false

	if client == nil {
		return client, false, fmt.Errorf("no surf client for modification check")
	}

	if proxyUrl != nil && *proxyUrl != "" {
		// Rebuild client with new proxy
		newClient := surf.NewClient()
		builder := newClient.Builder()
		builder.Proxy(g.String(*proxyUrl))
		result := builder.Build()
		if result.IsErr() {
			return nil, false, fmt.Errorf("failed to rebuild client with new proxy: %w", result.Err())
		}
		return result.Unwrap(), true, nil
	}

	return client, changed, nil
}

func mapJA3HelloID(helloID string) utls.ClientHelloID {
	switch helloID {
	case "chrome_auto":
		return utls.HelloChrome_Auto
	case "chrome_144":
		return utls.HelloChrome_120 // Use closest available
	case "firefox_auto":
		return utls.HelloFirefox_Auto
	case "firefox_147":
		return utls.HelloFirefox_120 // Use closest available
	default:
		return utls.ClientHelloID{} // Empty/not set
	}
}

func buildCookies(cookies []Cookie) []*http.Cookie {
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

func transformCookies(cookies []*http.Cookie) []Cookie {
	var ret []Cookie

	for _, cookie := range cookies {
		ret = append(ret, Cookie{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Path:     cookie.Path,
			Domain:   cookie.Domain,
			MaxAge:   cookie.MaxAge,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HttpOnly,
			Expires: Timestamp{
				Time: cookie.Expires,
			},
		})
	}

	return ret
}
