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

	log.Printf("Binding %s\n", router.BindAddress)
	server := http.Server{
		Addr:    router.BindAddress,
		Handler: router,
	}

	if certs := router.Certificates(); len(certs) > 0 {

		cfg := &tls.Config{}

		for _, cert := range certs {
			cfg.Certificates = append(cfg.Certificates, cert)
		}

		cfg.BuildNameToCertificate()
		server.TLSConfig = cfg

		log.Panicln(server.ListenAndServeTLS("", ""))
	} else {
		log.Panicln(server.ListenAndServe())
	}
}
