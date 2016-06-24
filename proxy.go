package main

import (
	"log"
	"net/http"
	"regexp"
)

type rule struct {
	Rule        string `json:"rule"`
	HandlerName string `json:"handler"`
	Domain      string `json:"domain"`
	Public      bool   `json:"public"`
	Regexp      *regexp.Regexp
	Handler     http.Handler
}

type proxy struct {
	BindAddress string            `json:"bind_address"`
	Handlers    map[string]string `json:"handlers"`
	Rules       []*rule           `json:"rules"`
	Username    string            `json:"username"`
	Password    string            `json:"password"`
}

func (c *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for i, rule := range c.Rules {
		if rule.Regexp.MatchString(r.URL.Path) {
			log.Printf("(rule:%d) %s\n", i, r.URL.Path)
			rule.Handler.ServeHTTP(w, r)
			return
		}
	}

	log.Printf("(no-match) %s\n", r.URL.Path)
	http.NotFound(w, r)
}
