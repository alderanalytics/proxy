package router

import (
	"io"
	"net/http"
	"net/url"
	"strings"
)

type httpUpstream struct {
	URL          string      `json:"url"`
	Headers      http.Header `json:"headers"`
	PreserveHost bool        `json:"preserve_host"`
	SessionName  string      `json:"session_name"`
	sess         *session
	reverseProxy *Proxy
	hURL         *url.URL
}

func (h *httpUpstream) finalize(s *session) error {
	var err error

	h.hURL, err = url.Parse(h.URL)
	if err != nil {
		return err
	}

	h.sess = s
	h.reverseProxy = NewProxy(h.hURL)
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

	var action ReverseProxyFunction
	action = CopyResponse

	if h.sess == nil {
		h.reverseProxy.ServeHTTP(w, r, action)
		return
	}

	prefix := h.sess.SessionHeaderPrefix

	// drop session control headers from the client
	for k := range r.Header {
		if k == prefix || strings.HasPrefix(k, prefix+"-") {
			r.Header.Del(k)
		}
	}

	// under error unpackStore returns an empty (non-nil) sessionStore
	store, _ := h.sess.unpackStore(r)

	// pass session data upstream via headers
	for k, v := range store {
		r.Header.Add(prefix+"-"+k, v)
	}

	action = func(rw http.ResponseWriter, res *http.Response) {
		var deleteStorage bool

		// loop over response headers
		for k, v := range res.Header {
			s := strings.SplitN(k, prefix, 2)

			// header didn't have our prefix anywhere
			if len(s) != 2 {
				for _, vv := range v {
					rw.Header().Add(k, vv)
				}

				continue
			}

			parts := strings.SplitN(s[1], "-", 3)

			for _, vv := range v {
				switch {
				case len(parts) == 1 && vv == "Delete":
					deleteStorage = true
				case len(parts) == 3 && parts[1] == "Del":
					for _, field := range strings.Split(vv, ",") {
						delete(store, field)
					}
				case len(parts) == 3 && parts[1] == "Set":
					store[parts[2]] = vv
				}
			}
		}

		if deleteStorage {
			h.sess.deleteStore(rw)
		} else {
			h.sess.packStore(store, rw)
		}

		rw.WriteHeader(res.StatusCode)
		io.Copy(rw, res.Body)
	}

	h.reverseProxy.ServeHTTP(w, r, action)
}
