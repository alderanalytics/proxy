package router

import (
	"net/http"
	"net/http/httputil"
	"net/url"
)

type httpUpstream struct {
	URL          string      `json:"url"`
	Headers      http.Header `json:"headers"`
	PreserveHost bool        `json:"preserve_host"`
	reverseProxy *httputil.ReverseProxy
	hURL         *url.URL
}

func (h *httpUpstream) finalize() error {
	var err error

	h.hURL, err = url.Parse(h.URL)
	if err != nil {
		return err
	}

	h.reverseProxy = httputil.NewSingleHostReverseProxy(h.hURL)
	return nil
}

func (h *httpUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for headerName, valueList := range h.Headers {
		for _, value := range valueList {
			r.Header.Add(headerName, value)
		}
	}

	if !h.PreserveHost {
		r.Host = h.hURL.Host
	}

	h.reverseProxy.ServeHTTP(w, r)
}
