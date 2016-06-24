package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"regexp"
)

var (
	dataPath = flag.String("path", ".", "path to proxy data")
)

func loadConfig() *proxy {
	configFile := path.Join(*dataPath, "config.json")
	file, err := os.Open(configFile)
	if err != nil {
		log.Panic(err)
	}

	decoder := json.NewDecoder(file)
	c := &proxy{}
	err = decoder.Decode(c)
	if err != nil {
		log.Panic(err)
	}

	handlers := make(map[string]http.Handler)

	for name, remote := range c.Handlers {
		remoteURL, err := url.Parse(remote)
		if err != nil {
			log.Panic(err)
		}

		handlers[name] = httputil.NewSingleHostReverseProxy(remoteURL)
	}

	for i, rule := range c.Rules {
		log.Printf("(rule:%d) compiling '%s'", i, rule.Rule)
		rule.Regexp, err = regexp.Compile(rule.Rule)
		if err != nil {
			log.Panic(err)
		}

		handler, ok := handlers[rule.HandlerName]
		if !ok {
			log.Panic("undefined handler", rule.Handler)
		}

		rule.Handler = handler
	}

	return c
}

func main() {
	flag.Parse()
	config := loadConfig()

	log.Printf("Binding %s\n", config.BindAddress)
	log.Panic(http.ListenAndServe(config.BindAddress, config))
}
