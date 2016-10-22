package http_client_cluster

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"crypto/tls"
	"golang.org/x/net/http2"
)

const errWeight uint64 = 10
const minHeapSize = 8
const DefaultRequestTimeout = 5 * time.Second
const DefaultRetry = 3

var (
	ErrNoEndpoints           = errors.New("client: no endpoints available")
	ErrTooManyRedirects      = errors.New("client: too many redirects")
	ErrClusterUnavailable    = errors.New("client: cluster is unavailable or misconfigured")
	ErrNoLeaderEndpoint      = errors.New("client: no leader endpoint available")
	errTooManyRedirectChecks = errors.New("client: too many redirect checks")
)

// per host to a client
var ClientMap map[string]ConfigClient = make(map[string]ConfigClient, 1)
var ClientRWLock *sync.RWMutex = new(sync.RWMutex)

// CancelableTransport mimics net/http.Transport, but requires that
// the object also support request cancellation.
type CancelableTransport interface {
	http.RoundTripper
	CancelRequest(req *http.Request)
}

type CheckRedirectFunc func(via int) error

// DefaultCheckRedirect follows up to 10 redirects, but no more.
var DefaultCheckRedirect CheckRedirectFunc = func(via int) error {
	if via > 10 {
		return ErrTooManyRedirects
	}
	return nil
}

type Config struct {
	// CheckRedirect specifies the policy for handling HTTP redirects.
	// If CheckRedirect is not nil, the Client calls it before
	// following an HTTP redirect. The sole argument is the number of
	// requests that have alrady been made. If CheckRedirect returns
	// an error, Client.Do will not make any further requests and return
	// the error back it to the caller.
	//
	// If CheckRedirect is nil, the Client uses its default policy,
	// which is to stop after 10 consecutive requests.
	CheckRedirect CheckRedirectFunc

	// Username specifies the user credential to add as an authorization header
	Username string

	// Password is the password for the specified user to add as an authorization header
	// to the request.
	Password string

	// HeaderTimeoutPerRequest specifies the time limit to wait for response
	// header in a single request made by the Client. The timeout includes
	// connection time, any redirects, and header wait time.
	//
	// For non-watch GET request, server returns the response body immediately.
	// For PUT/POST/DELETE request, server will attempt to commit request
	// before responding, which is expected to take `100ms + 2 * RTT`.
	// For watch request, server returns the header immediately to notify Client
	// watch start. But if server is behind some kind of proxy, the response
	// header may be cached at proxy, and Client cannot rely on this behavior.
	//
	// One API call may send multiple requests to different etcd servers until it
	// succeeds. Use context of the API to specify the overall timeout.
	//
	// A HeaderTimeoutPerRequest of zero means no timeout.
	HeaderTimeoutPerRequest time.Duration

	// retry times when request err
	Retry int

	// cert for request https
	Cert tls.Certificate
}

func (cfg *Config) checkRedirect() CheckRedirectFunc {
	if cfg.CheckRedirect == nil {
		return DefaultCheckRedirect
	}
	return cfg.CheckRedirect
}

func (cfg *Config) headerTimeoutPerRequest() time.Duration {
	if cfg.HeaderTimeoutPerRequest == 0 {
		return DefaultRequestTimeout
	}
	return cfg.HeaderTimeoutPerRequest
}

func (cfg *Config) retry() int {
	if cfg.Retry == 0 {
		return DefaultRetry
	}
	return cfg.Retry
}

type Client interface {
	// recieve user's request, then do the request through cluster_client transport
	Do(request *http.Request) (*http.Response, []byte, error)

	httpClient
}

type ConfigClient struct {
	client Client
	config Config
}

func formatSchemeHost(scheme, host string) string {
	return fmt.Sprintf("%s://%s", scheme, host)
}

//
func ConfigClientTls(request *http.Request, cert_dir, pwd string) error {
	ClientRWLock.RLock()
	config_client, ok := ClientMap[formatSchemeHost(request.URL.Scheme, request.URL.Host)]
	ClientRWLock.RUnlock()
	if ok {
		return nil
	}

	cert, err := GetCertificate(cert_dir, pwd)
	if nil != err {
		log.Println("get certificate err: ", err)
		return err
	}
	config_client.config.Cert = cert
	_, err = New(request.URL.Scheme, request.URL.Host, config_client.config)
	return err
}

func GetClient(scheme, host string) (Client, error) {
	ClientRWLock.RLock()
	config_client, ok := ClientMap[formatSchemeHost(scheme, host)]
	ClientRWLock.RUnlock()
	if ok {
		return config_client.client, nil
	}

	// if cfg == nil {
	// 	cfg = &Config{}
	// }
	c, err := New(scheme, host, config_client.config)
	return c, err
}

// the Response.Body has closed after reading into body.
func HttpClientClusterDo(request *http.Request) (resp *http.Response, body []byte, err error) {
	client, err := GetClient(request.URL.Scheme, request.URL.Host)
	if nil != err || client == nil {
		log.Println("new http cluster client err: %v", err)
		return nil, nil, err
	}

	resp, body, err = client.Do(request)
	return
}

func New(scheme, host string, cfg Config) (Client, error) {

	c := &httpClusterClient{
		rand:   rand.New(rand.NewSource(int64(time.Now().Nanosecond()))),
		cfg:    &cfg,
		scheme: scheme,
		host:   host,
	}
	if cfg.Username != "" {
		c.credentials = &credentials{
			username: cfg.Username,
			password: cfg.Password,
		}
	}
	c.updateClientAddr()
	go func(c *httpClusterClient) {
		timer := time.NewTimer(30 * time.Second)
		for {
			select {
			case <-timer.C:
				c.updateClientAddr()
			}
		}
	}(c)

	ClientRWLock.Lock()
	defer ClientRWLock.Unlock()
	cofig_client := ConfigClient{
		client: c,
		config: cfg,
	}
	ClientMap[formatSchemeHost(scheme, host)] = cofig_client
	return c, nil
}

type httpClient interface {
	DoRequest(context.Context, httpAction) (*http.Response, []byte, error)
}

type credentials struct {
	username string
	password string
}

type httpClientFactory func(url.URL) httpClient

// return the request, which could be a source rquest,
// or with authenticated info,
// or wrapped with redirect url.
type httpAction interface {
	HTTPRequest(ip string, port int) *http.Request
}

type basicAction struct {
	req *http.Request
}

func (b *basicAction) HTTPRequest(ip string, port int) *http.Request {
	// Don't replace the host of request, the host may use to nginx forward.
	// Should specifc the transport's dial func to load balancing.
	// Check newHTTPClient() func for more detail.

	// addr := fmt.Sprintf("%s:%d", ip, port)
	// b.req.URL.Host = addr

	return b.req
}

type authedAction struct {
	act         httpAction
	credentials credentials
}

func (a *authedAction) HTTPRequest(ip string, port int) *http.Request {
	r := a.act.HTTPRequest(ip, port)
	r.SetBasicAuth(a.credentials.username, a.credentials.password)
	return r
}

type redirectHTTPAction struct {
	action   httpAction
	location url.URL
}

func (r *redirectHTTPAction) HTTPRequest(ip string, port int) *http.Request {
	origin := r.action.HTTPRequest(ip, port)
	origin.URL = &r.location
	return origin
}

func newHTTPClient(ip string, port int, cr CheckRedirectFunc, headerTimeout time.Duration,
	cert tls.Certificate) httpClient {
	dial := func(network, address string) (net.Conn, error) {
		d := net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		return d.Dial(network, fmt.Sprintf("%s:%d", ip, port))
	}
	// proxy := func(_ *http.Request) (*url.URL, error) {
	// 	return url.Parse("http://127.0.0.1:8888")
	// }
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{cert},
	}
	if len(cert.Certificate) > 0 {
		tlsConfig.BuildNameToCertificate()
	}

	var tr = &http.Transport{
		// Proxy: proxy,
		Dial:                dial,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     tlsConfig,
	}
	// log.Println(fmt.Sprintf("transport: %+v", tr))

	err := http2.ConfigureTransport(tr)
	if err != nil {
		log.Println("http2 ConfigureTransport err: ", err)
	}

	client := &redirectFollowingHTTPClient{
		checkRedirect: cr,
		client: &simpleHTTPClient{
			transport:     *tr,
			ip:            ip,
			port:          port,
			headerTimeout: headerTimeout,
		},
	}

	return client
}

/*********************************************************************************
 带优先级的httpClient，weight越低优先级越高
 封装redirectFollowingHTTPClient

 The httpWeightClient with priority has encapsulate redirectFollowingHTTPClient,
 the lower the weight, the higher the priority.
**********************************************************************************/
type httpWeightClient struct {
	client   httpClient
	endpoint string // "127.0.0.1"
	index    int
	weight   uint64
	errcnt   int
}

/************************************************************************
 带集群功能的client，封装httpWeightClient

 The client with cluster functionality has encapsulate httpWeightClient
************************************************************************/
type httpClusterClient struct {
	credentials *credentials
	sync.RWMutex
	endpoints []string
	rand      *rand.Rand
	cfg       *Config
	scheme    string
	host      string
	clients   []*httpWeightClient
}

func (c *httpClusterClient) Len() int {
	return len(c.clients)
}

func (c *httpClusterClient) Swap(i, j int) {
	c.clients[i], c.clients[j] = c.clients[j], c.clients[i]
	c.clients[i].index = i
	c.clients[j].index = j
}

func (c *httpClusterClient) Less(i, j int) bool {
	return c.clients[i].weight < c.clients[j].weight
}

func (c *httpClusterClient) Pop() (client interface{}) {
	c.clients, client = c.clients[:c.Len()-1], c.clients[c.Len()-1]
	return
}

func (c *httpClusterClient) Push(client interface{}) {
	weightClient := client.(*httpWeightClient)
	weightClient.index = c.Len()
	c.clients = append(c.clients, weightClient)
}

func (c *httpClusterClient) exist(addr string) bool {
	c.RLock()
	for _, cli := range c.clients {
		if cli.endpoint == addr {
			c.RUnlock()
			return true
		}
	}
	c.RUnlock()
	return false
}

func (c *httpClusterClient) add(addr string, client httpClient) {
	c.Lock()
	defer c.Unlock()

	for _, cli := range c.clients {
		if cli.endpoint == addr {
			return
		}
	}
	heap.Push(c, &httpWeightClient{client: client, endpoint: addr})

	if c.Len() == minHeapSize {
		heap.Init(c)
	}
}

// update clients with new addrs, remove the no use client
func (c *httpClusterClient) clear(addrs []string) {
	c.Lock()
	for _, cli := range c.clients {
		var has_cli bool
		for _, addr := range addrs {
			if cli.endpoint == addr {
				has_cli = true
				break
			}
		}
		if !has_cli {
			heap.Remove(c, cli.index)
		}
	}
	c.Unlock()
}

func (c *httpClusterClient) get() *httpWeightClient {
	c.Lock()
	defer c.Unlock()

	size := c.Len()
	if size == 0 {
		return nil
	}

	if size < minHeapSize {
		var index int = 0
		for i := 1; i < size; i++ {
			if c.Less(i, index) {
				index = i
			}
		}

		return c.clients[index]
	}

	client := heap.Pop(c).(*httpWeightClient)
	heap.Push(c, client)
	return client
}

func (c *httpClusterClient) use(client *httpWeightClient) {
	c.Lock()
	client.weight++
	if c.Len() >= minHeapSize {
		heap.Fix(c, client.index)
	}
	c.Unlock()
}

func (c *httpClusterClient) done(client *httpWeightClient) {
	c.Lock()
	client.weight--
	if c.Len() >= minHeapSize {
		heap.Fix(c, client.index)
	}
	c.Unlock()
}

func (c *httpClusterClient) occurErr(client *httpWeightClient, err error) {
	c.Lock()
	if nil != err {
		client.weight += errWeight
		client.errcnt++
		if c.Len() >= minHeapSize {
			heap.Fix(c, client.index)
		}
	} else {
		if client.errcnt > 0 {
			client.weight -= errWeight
			client.errcnt--
			if c.Len() >= minHeapSize {
				heap.Fix(c, client.index)
			}
		}
	}
	c.Unlock()
}

func (c *httpClusterClient) updateClientAddr() {
	addr := strings.Split(c.host, ":")
	addrs, err := net.LookupHost(addr[0])
	if nil != err {
		log.Println("lookup host err: ", err)
		return
	}
	// only ipv4
	var ips []string
	for _, s := range addrs {
		ip := net.ParseIP(s)
		if ip != nil && len(ip.To4()) == net.IPv4len {
			ips = append(ips, s)
		}
	}

	c.endpoints = ips

	var port int
	if len(addr) > 1 {
		port, err = strconv.Atoi(addr[1])
		if nil != err {
			log.Println("parse port err: ", err)
			return
		}
	} else {
		switch c.scheme {
		case "http", "HTTP":
			port = 80
		case "https", "HTTPS":
			port = 443
		}
	}

	c.clear(ips)

	for i := range ips {
		if !c.exist(ips[i]) {
			c.add(ips[i], newHTTPClient(ips[i], port, c.cfg.checkRedirect(), c.cfg.HeaderTimeoutPerRequest, c.cfg.Cert))
		}
	}

	if c.Len() == 0 {
		log.Println("cluster has no client to use")
	}

}

func (c *httpClusterClient) Do(request *http.Request) (*http.Response, []byte, error) {
	act := &basicAction{
		req: request,
	}

	resp, body, err := c.DoRequest(context.Background(), act)
	if nil != err {
		return nil, nil, err
	}

	return resp, body, nil
}

func (c *httpClusterClient) DoRequest(ctx context.Context, act httpAction) (*http.Response, []byte, error) {
	var err error
	var retry int
	cerr := &ClusterError{}

	if c.Len() == 0 {
		err = fmt.Errorf("cluster do not have client to use")
		return nil, nil, err
	}

	// action
	action := act
	if c.credentials != nil {
		action = &authedAction{
			act:         act,
			credentials: *c.credentials,
		}
	}

	for retry = 0; retry < c.cfg.retry(); retry++ {
		client := c.get()
		if client == nil {
			continue
		}

		c.use(client)
		resp, body, err := client.client.DoRequest(ctx, action)

		c.Push(client)
		c.done(client)
		c.occurErr(client, err)

		if nil != err {
			cerr.Errors = append(cerr.Errors, err)
			// mask previous errors with context error, which is controlled by user
			if err == context.Canceled || err == context.DeadlineExceeded {
				// return nil, nil, err
				log.Println("context err, retry")
			}

			// c.occurErr(client, err)
			log.Printf("cluster: put client back %v err: %v", client.endpoint, err)
			continue
		}

		// 500 internal err, not retry
		// if resp.StatusCode/100 == 5 {
		// 	switch resp.StatusCode {
		// 	case http.StatusInternalServerError, http.StatusServiceUnavailable:
		// 		// TODO: make sure this is a no leader response
		// 		cerr.Errors = append(cerr.Errors, fmt.Errorf("client: "))
		// 	default:
		// 		cerr.Errors = append(cerr.Errors, fmt.Errorf("client: member %s returns server error [%s]", client.endpoint, http.StatusText(resp.StatusCode)))
		// 	}
		// 	continue
		// }
		return resp, body, nil
	}
	if retry >= c.cfg.retry() && cerr.Errors != nil {
		log.Println("cluster call failed after %v times", c.cfg.retry())
	}

	return nil, nil, cerr
}

/***********************************************************************
 带重定向功能的client，封装了simpleHTTPClient

 The client with redirect functionality has encapsulate simpleHTTPClient
***********************************************************************/
type redirectFollowingHTTPClient struct {
	client        httpClient
	checkRedirect CheckRedirectFunc
}

func (r *redirectFollowingHTTPClient) DoRequest(ctx context.Context, act httpAction) (*http.Response, []byte, error) {
	next := act
	for i := 0; i < 100; i++ {
		if i > 0 {
			if err := r.checkRedirect(i); nil != err {
				return nil, nil, err
			}
		}

		resp, body, err := r.client.DoRequest(ctx, next)
		if nil != err {
			return nil, nil, err
		}
		if resp.StatusCode/100 == 3 { // redirect to new url
			hdr := resp.Header.Get("Location")
			if hdr == "" {
				return nil, nil, fmt.Errorf("Location header not set")
			}
			loc, err := url.Parse(hdr)
			if nil != err {
				return nil, nil, fmt.Errorf("Location header not valid URL: %s", hdr)
			}
			next = &redirectHTTPAction{
				action:   act,
				location: *loc,
			}
			continue
		}
		return resp, body, nil
	}

	return nil, nil, errTooManyRedirectChecks
}

/***************************************************
 the base http client
***************************************************/
type simpleHTTPClient struct {
	transport     http.Transport
	ip            string
	port          int
	headerTimeout time.Duration
}

type roundTripResponse struct {
	resp *http.Response
	err  error
}

func (sc *simpleHTTPClient) DoRequest(ctx context.Context, act httpAction) (*http.Response, []byte, error) {
	req := act.HTTPRequest(sc.ip, sc.port)

	if err := printcURL(req); nil != err {
		return nil, nil, err
	}

	var hctx context.Context
	var hcancel context.CancelFunc
	if sc.headerTimeout > 0 {
		hctx, hcancel = context.WithTimeout(ctx, sc.headerTimeout)
	} else {
		hctx, hcancel = context.WithCancel(ctx)
	}
	defer hcancel()

	reqcancel := requestCanceler(sc.transport, req)
	rtchan := make(chan roundTripResponse, 1)
	go func() {
		resp, err := sc.transport.RoundTrip(req)
		rtchan <- roundTripResponse{resp: resp, err: err}
	}()

	var resp *http.Response
	var err error
	select {
	case rtresp := <-rtchan:
		resp, err = rtresp.resp, rtresp.err
	case <-hctx.Done():
		// cancel and wait for request to actually exit before continuing
		reqcancel()
		rtresp := <-rtchan
		resp = rtresp.resp
		switch {
		case ctx.Err() != nil:
			err = ctx.Err()
		case hctx.Err() != nil:
			err = fmt.Errorf("client: ip %s exceeded header timeout", sc.ip)
		default:
			panic("failed to get error from context")
		}
	}

	// always check for resp nil-ness to deal with possible
	// race conditions between channels above
	defer func() {
		if resp != nil {
			resp.Body.Close()
		}
	}()

	if nil != err {
		return nil, nil, err
	}

	var body []byte
	done := make(chan struct{})
	go func() {
		body, err = ioutil.ReadAll(resp.Body)
		done <- struct{}{}
	}()

	select {
	case <-ctx.Done():
		resp.Body.Close()
		<-done
		return nil, nil, ctx.Err()
	case <-done:
	}

	return resp, body, err
}

func requestCanceler(tr http.Transport, req *http.Request) func() {
	ch := make(chan struct{})
	req.Cancel = ch

	return func() {
		close(ch)
	}
}
