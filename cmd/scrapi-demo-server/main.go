package main

import (
	"flag"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/mhlotto/go-scitt-scrapi/scrapi"
	"github.com/mhlotto/go-scitt-scrapi/scrapi/httpserver"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	// Use async mode to demonstrate pending -> success flow.
	service := scrapi.NewInMemoryTransparencyServiceAsync(2 * time.Second)
	stmtSigner, _, stmtKID, err := scrapi.NewEd25519Signer("demo-stmt-key")
	if err != nil {
		log.Fatalf("init statement signer: %v", err)
	}

	hostPort := *addr
	if !strings.HasPrefix(hostPort, "http://") && !strings.HasPrefix(hostPort, "https://") {
		hostPort = "http://localhost" + hostPort
	}

	mux := httpserver.NewMux(httpserver.HandlerOptions{
		Service:       service,
		IssuerURL:     hostPort,
		LogPubKey:     service.LogPublicKey(),
		LogKeyID:      service.LogKeyID(),
		HashAlg:       "sha-256",
		TreeType:      "binary-merkle-v1",
		SCRAPIVersion: "draft-ietf-scitt-scrapi-05",
		StmtSigner:    stmtSigner,
		StmtSignerKID: stmtKID,
	})

	log.Printf("starting SCRAPI demo server on %s", *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
