package router

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
)

const schemeHandler = "handler"

var (
	errInvalidHandlerURL               = fmt.Errorf("handler urls must use the handler scheme (i.e. %s://)", schemeHandler)
	errPrivateRuleWithoutAuthenticator = errors.New("private rule without authenticator")
)

type rule struct {
	Rule       string `json:"rule"`
	HandlerURL string `json:"handler"`
	Public     bool   `json:"public"`
	regexp     *regexp.Regexp
}

type domain struct {
	TLS                bool    `json:"tls"`
	TLSCertificateFile string  `json:"tls_certificate_file"`
	TLSKeyFile         string  `json:"tls_key_file"`
	Rules              []*rule `json:"rules"`
	AuthenticatorName  string  `json:"authenticator"`
	certificate        tls.Certificate
	auth               authenticator
}

type backends struct {
	S3   map[string]*s3Upstream   `json:"s3"`
	HTTP map[string]*httpUpstream `json:"http"`
}

type Router struct {
	BindAddress    string                          `json:"bind_address"`
	CookieSecret   string                          `json:"cookie_secret"`
	Backends       backends                        `json:"backends"`
	Domains        map[string]*domain              `json:"domains"`
	Authentication map[string]staticAuthentication `json:"authentication"`
	handlers       map[string]http.Handler
	authenticators map[string]authenticator
	mutex          sync.RWMutex
}

func (r *Router) addHandler(name string, handler http.Handler) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.handlers == nil {
		r.handlers = make(map[string]http.Handler)
	}

	if _, present := r.handlers[name]; present {
		return fmt.Errorf("a handler named '%s' already exists", name)
	}

	r.handlers[name] = handler

	return nil
}

func (r *Router) getHandler(name string) (http.Handler, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	if handler, present := r.handlers[name]; present {
		return handler, nil
	}

	return nil, fmt.Errorf("no handler named '%s'", name)
}

func (r *Router) addAuthenticator(name string, auth authenticator) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.authenticators == nil {
		r.authenticators = make(map[string]authenticator)
	}

	if _, present := r.authenticators[name]; present {
		return fmt.Errorf("an authenticator named '%s' already exists", name)
	}

	r.authenticators[name] = auth

	return nil
}

func (r *Router) getAuthenticator(name string) (authenticator, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	if auth, present := r.authenticators[name]; present {
		return auth, nil
	}

	return nil, fmt.Errorf("no authenticator named '%s'", name)
}

func ruleError(domainName string, i int, err error) error {
	return fmt.Errorf("(%s,rule:%d) %s", domainName, i+1, err)
}

func handlerError(handlerName string, err error) error {
	return fmt.Errorf("(handler:%s) %s", handlerName, err)
}

func NewRouterFromConfig(configFile string) (*Router, error) {
	file, err := os.Open(configFile)
	if err != nil {
		return nil, err
	}

	r := &Router{}
	if err := json.NewDecoder(file).Decode(r); err != nil {
		return nil, err
	}

	for handlerName, s3def := range r.Backends.S3 {
		s3def.finalize()
		if err := r.addHandler(handlerName, s3def); err != nil {
			return nil, handlerError(handlerName, err)
		}
	}

	for handlerName, httpDef := range r.Backends.HTTP {
		if err := httpDef.finalize(); err != nil {
			return nil, handlerError(handlerName, err)
		}

		if err := r.addHandler(handlerName, httpDef); err != nil {
			return nil, handlerError(handlerName, err)
		}
	}

	for handlerName, authDef := range r.Authentication {
		authDef.r = r

		if err := authDef.finalize(); err != nil {
			return nil, handlerError(handlerName, err)
		}

		if err := r.addAuthenticator(handlerName, &authDef); err != nil {
			return nil, handlerError(handlerName, err)
		}

		if err := r.addHandler(handlerName, &authDef); err != nil {
			return nil, handlerError(handlerName, err)
		}
	}

	if r.Domains == nil {
		r.Domains = make(map[string]*domain)
	}

	for domainName, domainDef := range r.Domains {

		if domainDef.TLS {
			if domainDef.TLSCertificateFile != "" || domainDef.TLSKeyFile != "" {
				domainDef.certificate, err = tls.LoadX509KeyPair(domainDef.TLSCertificateFile, domainDef.TLSKeyFile)
				if err != nil {
					return nil, fmt.Errorf("error loading certificates for domain '%s': %s", domainName, err)
				}
			} else {
				domainDef.certificate, err = makeCertificate(domainName)
				if err != nil {
					return nil, fmt.Errorf("error generating certificate for domain '%s': %s", domainName, err)
				}
			}
		}

		if domainDef.AuthenticatorName != "" {
			if domainDef.auth, err = r.getAuthenticator(domainDef.AuthenticatorName); err != nil {
				return nil, fmt.Errorf("domain '%s' references undefined authenticator '%s'", domainName, domainDef.AuthenticatorName)
			}
		}

		for i, ruleDef := range domainDef.Rules {
			if !ruleDef.Public && domainDef.auth == nil {
				return nil, ruleError(domainName, i, errPrivateRuleWithoutAuthenticator)
			}

			handlerURL, err := parseHandlerURL(ruleDef.HandlerURL)
			if err != nil {
				return nil, ruleError(domainName, i, err)
			}

			handlerName := handlerURL.Host
			handler, _ := r.getHandler(handlerName)
			if handler == nil {
				return nil, ruleError(domainName, i, fmt.Errorf("no handler named '%s", handlerName))
			}

			ruleDef.regexp, err = regexp.Compile(ruleDef.Rule)
			if err != nil {
				return nil, err
			}
		}
	}

	return r, nil
}

func (r *Router) Certificates() []tls.Certificate {
	var certs []tls.Certificate
	for _, domainDef := range r.Domains {
		if domainDef.TLS {
			certs = append(certs, domainDef.certificate)
		}
	}

	return certs
}

func (r *Router) routeInternal(w http.ResponseWriter, req *http.Request) {
	handler, err := r.getHandler(req.URL.Host)
	if err != nil {
		internalServerError(w)
		return
	}

	handler.ServeHTTP(w, req)
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	host, _, _ := splitHostPortOptional(req.Host)
	domain, hasDomain := r.Domains[host]

	if hasDomain {
		for _, rule := range domain.Rules {
			if !rule.regexp.MatchString(req.URL.Path) {
				continue
			}

			if !rule.Public && !domain.auth.authenticate(req) {
				continue
			}

			rawURL := rule.regexp.ReplaceAllString(req.URL.Path, rule.HandlerURL)
			handlerURL, err := url.Parse(rawURL)
			if err != nil {
				internalServerError(w)
				return
			}

			query := req.URL.RawQuery
			*req.URL = *handlerURL
			req.URL.RawQuery = query

			r.routeInternal(w, req)
			return
		}
	}

	http.NotFound(w, req)
}

func internalServerError(w http.ResponseWriter) {
	w.WriteHeader(500)
}

func parseHandlerURL(rawurl string) (*url.URL, error) {
	url, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}

	if url.Scheme != schemeHandler {
		return nil, err
	}

	return url, nil
}

func splitHostPortOptional(s string) (host, port string, err error) {
	if !hasPort(s) {
		host = s
	} else {
		host, port, err = net.SplitHostPort(s)
	}

	return
}

func hasPort(s string) bool {
	return strings.LastIndex(s, ":") > strings.LastIndex(s, "]")
}
