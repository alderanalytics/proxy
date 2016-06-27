package main

import (
	"flag"
	"log"
	"net/http"
	"path"

	"crypto/tls"
	"github.com/alderanalytics/proxyd/router"
)

var (
	dataPath = flag.String("path", ".", "path to proxy data")
)

func main() {
	flag.Parse()

	configFile := path.Join(*dataPath, "config.json")

	router, err := router.NewRouterFromConfig(configFile)
	if err != nil {
		log.Panicln(err)
	}

	cfg := &tls.Config{}

	for _, cert := range router.Certificates() {
		cfg.Certificates = append(cfg.Certificates, cert)
	}

	cfg.BuildNameToCertificate()

	server := http.Server{
		Addr:      router.BindAddress,
		Handler:   router,
		TLSConfig: cfg,
	}

	log.Printf("Binding %s\n", router.BindAddress)
	log.Panicln(server.ListenAndServeTLS("", ""))
}
