package main

import (
	"flag"
	"log"
	"net/http"
	"strings"

	"github.com/mhlotto/go-scitt-scrapi/scrapi"
	"github.com/mhlotto/go-scitt-scrapi/scrapi/httpserver"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	service := scrapi.NewInMemoryTransparencyService()

	hostPort := *addr
	if !strings.HasPrefix(hostPort, "http://") && !strings.HasPrefix(hostPort, "https://") {
		hostPort = "http://localhost" + hostPort
	}

	mux := httpserver.NewMux(httpserver.HandlerOptions{
		Service:   service,
		IssuerURL: hostPort,
	})

	log.Printf("starting SCRAPI demo server on %s", *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
