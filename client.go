package http_client_cluster

import (
	"container/heap"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
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

// per host to a client
var ClientMap map[string]*httpClusterClient = make(map[string]*httpClusterClient, 1)
var ClientRWLock *sync.RWMutex = new(sync.RWMutex)

type Config struct {
	// Username specifies the user credential to add as an authorization header
	Username string

	// Password is the password for the specified user to add as an authorization header
	// to the request.
	Password string

	// TimeoutPerRequest specifies the time limit to wait for response
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
	// A TimeoutPerRequest of zero means no timeout.
	TimeoutPerRequest time.Duration

	// retry times when request err
	Retry int

	// cert for request https
	Cert tls.Certificate
}

func (cfg *Config) timeoutPerRequest() time.Duration {
	if cfg.TimeoutPerRequest == 0 {
		return DefaultRequestTimeout
	}
	return cfg.TimeoutPerRequest
}

func (cfg *Config) retry() int {
	if cfg.Retry == 0 {
		return DefaultRetry
	}
	return cfg.Retry
}

func formatSchemeHost(scheme, host string) string {
	return fmt.Sprintf("%s://%s", scheme, host)
}

//
func ConfigClientTls(request *http.Request, cert_dir, pwd string) error {
	ClientRWLock.RLock()
	_, ok := ClientMap[formatSchemeHost(request.URL.Scheme, request.URL.Host)]
	ClientRWLock.RUnlock()
	if ok {
		return nil
	}

	cert, err := GetCertificate(cert_dir, pwd)
	if nil != err {
		log.Println("get certificate err: ", err)
		return err
	}

	cfg := Config{}
	cfg.Cert = cert
	_, err = New(request.URL.Scheme, request.URL.Host, cfg)
	return err
}

func GetClient(scheme, host string) (*httpClusterClient, error) {
	ClientRWLock.RLock()
	cluster_client, ok := ClientMap[formatSchemeHost(scheme, host)]
	ClientRWLock.RUnlock()
	if ok {
		return cluster_client, nil
	}

	cfg := Config{}
	cluster_client, err := New(scheme, host, cfg)
	return cluster_client, err
}

func New(scheme, host string, cfg Config) (*httpClusterClient, error) {
	c := &httpClusterClient{
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
	ClientMap[formatSchemeHost(scheme, host)] = c
	return c, nil
}

func newHTTPClient(ip string, port int, timeout time.Duration, cert tls.Certificate) http.Client {
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

	// consult the https request conn which is http1 to http2 conn.
	err := http2.ConfigureTransport(tr)
	if err != nil {
		log.Println("http2 ConfigureTransport err: ", err)
	}

	client := http.Client{
		Transport: tr,
		Timeout:   timeout,
	}

	return client
}

// the Response.Body has closed after reading into body.
func HttpClientClusterDo(ctx context.Context, request *http.Request) (resp *http.Response, err error) {
	cluster_client, err := GetClient(request.URL.Scheme, request.URL.Host)
	if nil != err || cluster_client == nil {
		log.Println("new http cluster_client err: %v", err)
		return nil, err
	}

	if ctx == nil {
		ctx = context.Background()
	}
	resp, err = cluster_client.Do(ctx, request)
	return
}

type credentials struct {
	username string
	password string
}

// return the request, which could be a source rquest,
// or with authenticated info,
// or wrapped with redirect url.
type httpAction interface {
	HTTPRequest() *http.Request
}

type basicAction struct {
	req *http.Request
}

func (b *basicAction) HTTPRequest() *http.Request {
	return b.req
}

type authedAction struct {
	act         httpAction
	credentials credentials
}

func (a *authedAction) HTTPRequest() *http.Request {
	r := a.act.HTTPRequest()
	r.SetBasicAuth(a.credentials.username, a.credentials.password)
	return r
}

/*********************************************************************************
 带优先级的httpClient，weight越低优先级越高
 封装redirectFollowingHTTPClient

 The httpWeightClient with priority has encapsulate redirectFollowingHTTPClient,
 the lower the weight, the higher the priority.
**********************************************************************************/
type httpWeightClient struct {
	// client   httpClient
	client   http.Client
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

func (c *httpClusterClient) add(addr string, client http.Client) {
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
	var rm []*httpWeightClient
	for _, cli := range c.clients {
		var has_cli bool
		for _, addr := range addrs {
			if cli.endpoint == addr {
				has_cli = true
				break
			}
		}
		if !has_cli {
			// heap.Remove(c, cli.index)
			rm = append(rm, cli)
		} else if cli.errcnt > 0 {
			if cli.weight >= errWeight*uint64(cli.errcnt) {
				cli.weight -= errWeight * uint64(cli.errcnt)
				cli.errcnt = 0
				if c.Len() >= minHeapSize {
					heap.Fix(c, cli.index)
				}
			}
		}
	}

	for _, cli := range rm {
		// p will up, down, or not move, so append it to rm list.
		heap.Remove(c, cli.index)
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
	if client.weight > 0 {
		client.weight--
	}
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
			c.add(ips[i], newHTTPClient(ips[i], port, c.cfg.timeoutPerRequest(), c.cfg.Cert))
		}
	}

	if c.Len() == 0 {
		log.Println("cluster has no client to use")
	}

}

func (c *httpClusterClient) Do(ctx context.Context, request *http.Request) (*http.Response, error) {
	var err error
	var retry int
	var act_base *basicAction
	var act httpAction

	act_base = &basicAction{
		req: request,
	}
	act = httpAction(act_base)
	if c.credentials != nil {
		act = httpAction(&authedAction{
			act:         act,
			credentials: *c.credentials,
		})
	}

	if c.Len() == 0 {
		err = fmt.Errorf("cluster do not have client to use")
		return nil, err
	}

	for retry = 0; retry < c.cfg.retry(); retry++ {
		client := c.get()
		if client == nil {
			continue
		}

		// resp, body, err := client.client.DoRequest(ctx, action)
		req := act.HTTPRequest()

		c.use(client)
		resp, err := client.client.Do(req)
		c.done(client)
		c.occurErr(client, err)

		if nil != err {
			// mask previous errors with context error, which is controlled by user
			if err == context.Canceled || err == context.DeadlineExceeded {
				// return nil, nil, err
				log.Println("context err, retry")
			}

			// c.occurErr(client, err)
			log.Printf("cluster: put client back %v err: %v", client.endpoint, err)
			continue
		}

		return resp, nil
	}
	if retry >= c.cfg.retry() && err != nil {
		log.Println("cluster call failed after %v times", c.cfg.retry())
	}

	return nil, err
}
