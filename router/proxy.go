package router

/***
Modified version of Go's Reverse-Proxy which takes a
custom copy action that can modify the response.
**/

import (
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ReverseProxyAction is a callback type used for intercepting the upstream response.
type ReverseProxyAction interface {
	ProxyHTTP(rw http.ResponseWriter, res *http.Response)
}

// The ReverseProxyFunction type is an adapter to allow the use of
// ordinary functions as reverse proxy actions. If f is a function
// with the appropriate signature, ReverseProxyFunction(f) is a
// ReverseProxyAction that calls f.
type ReverseProxyFunction func(rw http.ResponseWriter, res *http.Response)

// ProxyHTTP calls f(rw, res)
func (f ReverseProxyFunction) ProxyHTTP(rw http.ResponseWriter, res *http.Response) {
	f(rw, res)
}

// Proxy provides an http handler that forwards a request to an upstream service.
type Proxy struct {
	Director  func(*http.Request)
	Transport http.RoundTripper
}

// CopyResponse copies the response headers, status code, and body
// from response to res
func CopyResponse(rw http.ResponseWriter, res *http.Response) {
	copyHeader(rw.Header(), res.Header)
	rw.WriteHeader(res.StatusCode)
	io.Copy(rw, res.Body)
}

// NewProxy constructs a new Proxy that maps incoming requests
// relative to the target URL.
func NewProxy(target *url.URL) *Proxy {
	targetQuery := target.RawQuery

	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
	}

	return &Proxy{Director: director}
}

func (p *Proxy) ServeHTTP(rw http.ResponseWriter, req *http.Request, action ReverseProxyAction) {
	transport := p.Transport

	if transport == nil {
		transport = http.DefaultTransport
	}

	outreq := new(http.Request)
	*outreq = *req // includes shallow copies of maps, but okay

	p.Director(outreq)
	outreq.Proto = "HTTP/1.1"
	outreq.ProtoMajor = 1
	outreq.ProtoMinor = 1
	outreq.Close = false

	copiedHeaders := false
	for _, h := range hopHeaders {
		if outreq.Header.Get(h) != "" {
			if !copiedHeaders {
				outreq.Header = make(http.Header)
				copyHeader(outreq.Header, req.Header)
				copiedHeaders = true
			}
			outreq.Header.Del(h)
		}
	}

	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		if prior, ok := outreq.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		outreq.Header.Set("X-Forwarded-For", clientIP)
	}

	res, err := transport.RoundTrip(outreq)
	if err != nil {
		p.logf("http: proxy error: %v", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	for _, h := range hopHeaders {
		res.Header.Del(h)
	}

	action.ProxyHTTP(rw, res)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func (p *Proxy) logf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Accept-Encoding", // make sure upstream doesnt send us any compressed content!!!
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}
