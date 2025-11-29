package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mhlotto/go-scitt-scrapi/scrapi"
	"github.com/mhlotto/go-scitt-scrapi/scrapi/httpserver"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	token := flag.String("auth-token", "", "optional bearer token required for requests")
	tlsCert := flag.String("tls-cert", "", "path to TLS certificate for HTTPS (optional)")
	tlsKey := flag.String("tls-key", "", "path to TLS key for HTTPS (optional)")
	tlsClientCA := flag.String("tls-client-ca", "", "path to CA bundle to require and verify client certs (mTLS, optional)")
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
		AuthSchemes:   authSchemes(*token, *tlsClientCA),
		AuthFunc:      bearerAuthFunc(*token),
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	if err := configureTLS(srv, *tlsCert, *tlsKey, *tlsClientCA); err != nil {
		log.Fatalf("configure TLS: %v", err)
	}

	log.Printf("starting SCRAPI demo server on %s", *addr)
	if srv.TLSConfig != nil && *tlsCert != "" && *tlsKey != "" {
		if err := srv.ListenAndServeTLS(*tlsCert, *tlsKey); err != nil {
			log.Fatalf("server error: %v", err)
		}
		return
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func bearerAuthFunc(token string) func(*http.Request) error {
	if token == "" {
		return nil
	}
	return func(r *http.Request) error {
		h := r.Header.Get("Authorization")
		want := "Bearer " + token
		if h != want {
			return fmt.Errorf("invalid or missing bearer token")
		}
		return nil
	}
}

func authSchemes(token, clientCA string) []string {
	var schemes []string
	if token != "" {
		schemes = append(schemes, "bearer")
	}
	if clientCA != "" {
		schemes = append(schemes, "mtls")
	}
	return schemes
}

func configureTLS(srv *http.Server, cert, key, clientCA string) error {
	if cert == "" || key == "" {
		return nil
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if clientCA != "" {
		certPool := x509.NewCertPool()
		data, err := os.ReadFile(clientCA)
		if err != nil {
			return fmt.Errorf("read client CA: %w", err)
		}
		if ok := certPool.AppendCertsFromPEM(data); !ok {
			return fmt.Errorf("failed to append client CA")
		}
		tlsCfg.ClientCAs = certPool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	srv.TLSConfig = tlsCfg
	return nil
}
