package globalsign

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"
)

const (
	clientVersion  = "0.0.1"
	apiVersion     = "v1"
	defaultBaseURL = "https://emea.api.dss.globalsign.com:8443" // TODO (galihrivanto): update when have confirmation
	baseAPI        = "/v2"
	userAgent      = "globalSign/" + clientVersion
	contentType    = "application/json;charset=utf-8"
)

// Client manage communication with wdms ap
type Client struct {
	sync.Mutex
	// HTTP client used to communicate with the DO API.
	client *http.Client

	// Base URL for API requests.
	baseURL *url.URL

	// User agent for client
	userAgent string

	// Auth token for authorization
	authToken string

	// Optional function called after every successful request made to APIs
	onRequestCompleted RequestCompletionCallback

	// login / authentication service
	LoginService LoginService

	// digital signing service (dss)
	DigitalSigningService DigitalSigningService
}

// Do sends an API request and returns the API response. The API response is JSON decoded and stored in the value
// pointed to by v, or returned as an error if an API error has occurred. If v implements the io.Writer interface,
// the raw response will be written to v, without attempting to decode it.
func (c *Client) Do(ctx context.Context, req *http.Request, v interface{}) (*Response, error) {
	resp, err := DoRequestWithClient(ctx, c.client, req)
	if err != nil {
		return nil, err
	}
	if c.onRequestCompleted != nil {
		c.onRequestCompleted(req, resp)
	}

	defer func() {
		if rerr := resp.Body.Close(); err == nil {
			err = rerr
		}
	}()

	// wrap response
	response := newResponse(resp)

	err = CheckResponse(resp)
	if err != nil {
		return response, err
	}

	if v != nil {
		// if v is io.Writer then simply copy response body
		if w, ok := v.(io.Writer); ok {
			_, err = io.Copy(w, resp.Body)
			if err != nil {
				return nil, err
			}
		} else {
			err = json.NewDecoder(resp.Body).Decode(v)
			if err != nil {
				return nil, err
			}
		}
	}

	return response, err
}

// NewClient returns a new API client.
func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	baseURL, _ := url.Parse(defaultBaseURL)

	c := &Client{client: httpClient, baseURL: baseURL, userAgent: userAgent}

	c.LoginService = &loginService{client: c}
	c.DigitalSigningService = &digitalSigningService{client: c}

	return c
}

// ClientOpt are options for New.
type ClientOpt func(*Client) error

// New returns a new Globalsign API client instance.
func New(httpClient *http.Client, opts ...ClientOpt) (*Client, error) {
	c := NewClient(httpClient)
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}

	return c, nil
}

// SetBaseURL is a client option for setting the base URL.
func SetBaseURL(bu string) ClientOpt {
	return func(c *Client) error {
		u, err := url.Parse(bu)
		if err != nil {
			return err
		}

		c.baseURL = u
		return nil
	}
}

// SetUserAgent is a client option for setting the user agent.
func SetUserAgent(ua string) ClientOpt {
	return func(c *Client) error {
		c.userAgent = fmt.Sprintf("%s %s", ua, c.userAgent)
		return nil
	}
}

// SetAuthToken set authorization token which used request authorization
func (c *Client) SetAuthToken(token string) {
	c.Lock()
	defer c.Unlock()

	c.authToken = token
}

// AuthToken get authorization token which used request authorization
func (c *Client) AuthToken() string {
	c.Lock()
	defer c.Unlock()

	return c.authToken
}

// NewRequest creates an API request. A relative URL can be provided in urlStr, which will be resolved to the
// BaseURL of the Client. Relative URLS should always be specified without a preceding slash. If specified, the
// value pointed to by body is JSON encoded and included in as the request body.
func (c *Client) NewRequest(ctx context.Context, method, urlStr string, body interface{}) (*http.Request, error) {
	c.Lock()
	defer c.Unlock()
	u, err := c.baseURL.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	if body != nil {
		err = json.NewEncoder(buf).Encode(body)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, u.String(), buf)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)
	req.Header.Add("Accept", contentType)
	req.Header.Add("User-Agent", c.userAgent)

	// if auth token is set
	// then put token as Authorization header
	if c.authToken != "" {
		req.Header.Add("Authorization", "Bearer "+c.authToken)
	}

	return req, nil
}

// OnRequestCompleted sets the DO API request completion callback
func (c *Client) OnRequestCompleted(rc RequestCompletionCallback) {
	c.onRequestCompleted = rc
}

// RequestCompletionCallback defines the type of the request callback function
type RequestCompletionCallback func(*http.Request, *http.Response)

// Response wraps standard http Response with default response fields
// which returned from wdms api
type Response struct {
	*http.Response
}

// ErrorResponse wrap standard http Response along with error code
// and message which returned from wdms api
type ErrorResponse struct {
	// original response
	Response *http.Response

	// Error code
	Code int `json:"code"`

	// Description of error
	Message string `json:"detail"`
}

func (r *ErrorResponse) Error() string {
	return fmt.Sprintf("%d. message: %v", r.Response.StatusCode, r.Message)
}

// ValidationError contains field to field validation error message
type ValidationError map[string]string

func (e ValidationError) Error() string {
	s := ""
	for k, v := range e {
		s += fmt.Sprintf("%s: %v\n", k, v)
	}

	return s
}

// ListRequest contains common parameter for list request
type ListRequest struct {
	Page int `json:"page,omitempty"`

	// Number of results to return per page.
	Limit int `json:"limit,omitempty"`

	// search	A search term.
	Search string `json:"search,omitempty"`

	// ordering
	Ordering int `json:"ordering,omitempty"`
}

// ListResult contains common field from api result
type ListResult struct {
	Count int `json:"count"`

	// next page link
	Next     string `json:"next"`
	Previous string `json:"previous"`
}

// newResponse creates a new Response for the provided http.Response
func newResponse(r *http.Response) *Response {
	response := Response{Response: r}

	return &response
}

// DoRequest submits an HTTP request.
func DoRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	return DoRequestWithClient(ctx, http.DefaultClient, req)
}

// DoRequestWithClient submits an HTTP request using the specified client.
func DoRequestWithClient(
	ctx context.Context,
	client *http.Client,
	req *http.Request) (*http.Response, error) {
	req = req.WithContext(ctx)
	return client.Do(req)
}

// CheckResponse checks the API response for errors, and returns them if present. A response is considered an
// error if it has a status code outside the 200 range. API error responses are expected to have either no response
// body, or a JSON response body that maps to ErrorResponse. Any other response body will be silently ignored.
func CheckResponse(r *http.Response) error {
	if c := r.StatusCode; c >= 200 && c < 300 {
		return nil
	}

	errorResponse := &ErrorResponse{Response: r}
	data, err := ioutil.ReadAll(r.Body)
	if err != nil || len(data) == 0 {
		return errorResponse
	}

	// if error code is > 400 then unmarshal to validation error
	// otherwise unmarshal to response error
	if r.StatusCode > 400 {
		validationResponse := &ValidationError{}
		err := json.Unmarshal(data, validationResponse)
		if err == nil {
			return validationResponse
		}

	}

	err = json.Unmarshal(data, errorResponse)
	if err != nil {
		errorResponse.Message = string(data)
	}

	// set code
	errorResponse.Code = r.StatusCode

	return errorResponse
}

// String is a helper routine that allocates a new string value
// to store v and returns a pointer to it.
func String(v string) *string {
	p := new(string)
	*p = v
	return p
}

// Int is a helper routine that allocates a new int32 value
// to store v and returns a pointer to it, but unlike Int32
// its argument value is an int.
func Int(v int) *int {
	p := new(int)
	*p = v
	return p
}

// Bool is a helper routine that allocates a new bool value
// to store v and returns a pointer to it.
func Bool(v bool) *bool {
	p := new(bool)
	*p = v
	return p
}

// StreamToString converts a reader to a string
func StreamToString(stream io.Reader) string {
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(stream)
	return buf.String()
}

// URLQueryEncoder .
type URLQueryEncoder interface {
	MarshalURLQuery() string
}

// MarshalURLQuery encode struct into url queries
// using `json` tag as query name reference
func MarshalURLQuery(v interface{}) (queries url.Values) {
	// init
	queries = url.Values{}

	t := reflect.TypeOf(v)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	// input must be type of `struct`
	if t.Kind() != reflect.Struct {
		return
	}

	value := reflect.ValueOf(v)
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}

	// enumerate the field to get the tag
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.PkgPath != "" {
			continue
		}

		var query string
		var omitEmpty bool

		parts := strings.Split(strings.TrimSpace(field.Tag.Get("json")), ",")
		if len(parts) == 0 {
			query = field.Name
		} else {
			query = strings.TrimSpace(parts[0])
			if len(query) == 0 {
				query = field.Name
			}

			if len(parts) > 1 {
				for _, part := range parts[0:] {
					if strings.TrimSpace(part) == "omitempty" {
						omitEmpty = true
						break
					}
				}
			}
		}

		vv := value.Field(i)

		// if field implement Query encoder interface
		if encoder, ok := vv.Interface().(URLQueryEncoder); ok {
			queries.Add(query, encoder.MarshalURLQuery())

			// go to next field
			continue
		}

		switch vv.Interface().(type) {
		case string:
			if vv.String() == "" && omitEmpty {
				break
			}

			queries.Add(query, vv.String())

		case float32, float64:
			if vv.Float() == 0.0 && omitEmpty {
				break
			}

			queries.Add(query, fmt.Sprintf("%f", vv.Float()))

		case int, int64:
			if vv.Int() == 0 && omitEmpty {
				break
			}

			queries.Add(query, fmt.Sprintf("%d", vv.Int()))

		case uint, uint64:
			if vv.Uint() == 0 && omitEmpty {
				break
			}

			queries.Add(query, fmt.Sprintf("%d", vv.Uint()))

		case bool:
			queries.Add(query, fmt.Sprintf("%v", vv.Bool()))

		case time.Time:
			if vv.String() == "" && omitEmpty {
				break
			}

			queries.Add(query, vv.Interface().(time.Time).Format(time.RFC3339Nano))

		default:
			vqueries := MarshalURLQuery(vv.Interface())
			if len(vqueries) > 0 {
				queries = mergeQueries(queries, vqueries)
			}
		}
	}

	return
}

func mergeQueries(queries ...url.Values) url.Values {
	if len(queries) == 0 {
		return url.Values{}
	}

	if len(queries) == 1 {
		return queries[0]
	}

	base := queries[0]
	for _, query := range queries[0:] {
		for k, v := range query {
			if len(v) > 0 {
				base[k] = v
			}
		}
	}

	return base
}

// NewHTTPClientWithCertificate .
func NewHTTPClientWithCertificate(certPath, keyPath string) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		InsecureSkipVerify:       true,
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		Certificates: []tls.Certificate{cert},
	}
	tr := &http.Transport{TLSClientConfig: config}

	return &http.Client{Transport: tr}, nil
}
