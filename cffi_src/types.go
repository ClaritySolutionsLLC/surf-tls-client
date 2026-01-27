package surf_tls_cffi_src

import (
	"encoding/json"
	"fmt"
	"time"
)

type SurfTLSClientError struct {
	err error
}

func NewSurfTLSClientError(err error) *SurfTLSClientError {
	return &SurfTLSClientError{
		err: err,
	}
}

func (e *SurfTLSClientError) Error() string {
	return e.err.Error()
}

type DestroySessionInput struct {
	SessionId string `json:"sessionId"`
}

type DestroyOutput struct {
	Id      string `json:"id"`
	Success bool   `json:"success"`
}

type AddCookiesToSessionInput struct {
	SessionId string   `json:"sessionId"`
	Url       string   `json:"url"`
	Cookies   []Cookie `json:"cookies"`
}

type GetCookiesFromSessionInput struct {
	SessionId string `json:"sessionId"`
	Url       string `json:"url"`
}

type CookiesFromSessionOutput struct {
	Id      string   `json:"id"`
	Cookies []Cookie `json:"cookies"`
}

// RequestInput is the data a Python client can construct a client and request from.
type RequestInput struct {
	Headers                     map[string]string   `json:"headers"`
	DefaultHeaders              map[string][]string `json:"defaultHeaders"`
	ConnectHeaders              map[string][]string `json:"connectHeaders"`
	ProxyUrl                    *string             `json:"proxyUrl"`
	RequestBody                 *string             `json:"requestBody"`
	RequestHostOverride         *string             `json:"requestHostOverride"`
	SessionId                   *string             `json:"sessionId"`
	RequestMethod               string              `json:"requestMethod"`
	RequestUrl                  string              `json:"requestUrl"`
	RequestCookies              []Cookie            `json:"requestCookies"`
	TimeoutMilliseconds         int                 `json:"timeoutMilliseconds"`
	TimeoutSeconds              int                 `json:"timeoutSeconds"`
	FollowRedirects             bool                `json:"followRedirects"`
	ForceHttp1                  bool                `json:"forceHttp1"`
	ForceHttp2                  bool                `json:"forceHttp2"`
	ForceHttp3                  bool                `json:"forceHttp3"`
	DisableHttp3                bool                `json:"disableHttp3"`
	InsecureSkipVerify          bool                `json:"insecureSkipVerify"`
	IsByteRequest               bool                `json:"isByteRequest"`
	IsByteResponse              bool                `json:"isByteResponse"`
	IsRotatingProxy             bool                `json:"isRotatingProxy"`
	WithDebug                   bool                `json:"withDebug"`
	WithRandomTLSExtensionOrder bool                `json:"withRandomTLSExtensionOrder"`
	// JA3/4 TLS fingerprinting
	JA3String                   string                `json:"ja3String"`
	JA3HelloID                  string                `json:"ja3HelloID"`
	// HTTP/2 settings
	H2Settings                  map[string]uint32     `json:"h2Settings"`
	H2SettingsOrder             []string              `json:"h2SettingsOrder"`
	PseudoHeaderOrder           []string              `json:"pseudoHeaderOrder"`
	HeaderOrder                 []string              `json:"headerOrder"`
	// Transport options
	TransportOptions            *TransportOptions   `json:"transportOptions"`
}

// TransportOptions contains settings for the underlying http transport
type TransportOptions struct {
	DisableKeepAlives      bool           `json:"disableKeepAlives"`
	DisableCompression     bool           `json:"disableCompression"`
	MaxIdleConns           int            `json:"maxIdleConns"`
	MaxIdleConnsPerHost    int            `json:"maxIdleConnsPerHost"`
	MaxConnsPerHost        int            `json:"maxConnsPerHost"`
	MaxResponseHeaderBytes int64          `json:"maxResponseHeaderBytes"`
	WriteBufferSize        int            `json:"writeBufferSize"`
	ReadBufferSize         int            `json:"readBufferSize"`
	IdleConnTimeout        *time.Duration `json:"idleConnTimeout"`
}

type Cookie struct {
	Expires  Timestamp `json:"expires"`
	Domain   string    `json:"domain"`
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	Value    string    `json:"value"`
	MaxAge   int       `json:"maxAge"`
	Secure   bool      `json:"secure"`
	HttpOnly bool      `json:"httpOnly"`
}

type Timestamp struct {
	time.Time
}

func (p *Timestamp) UnmarshalJSON(bytes []byte) error {
	var raw int64
	err := json.Unmarshal(bytes, &raw)
	if err != nil {
		return fmt.Errorf("error decoding timestamp: %w", err)
	}

	p.Time = time.Unix(raw, 0)

	return nil
}

func (p *Timestamp) MarshalJSON() ([]byte, error) {
	stamp := fmt.Sprintf("%d", p.Unix())
	return []byte(stamp), nil
}

// Response is the response that is sent back to the Python client.
type Response struct {
	Cookies      map[string]string   `json:"cookies"`
	Headers      map[string][]string `json:"headers"`
	Id           string              `json:"id"`
	Body         string              `json:"body"`
	SessionId    string              `json:"sessionId,omitempty"`
	Target       string              `json:"target"`
	UsedProtocol string              `json:"usedProtocol"`
	Status       int                 `json:"status"`
}
