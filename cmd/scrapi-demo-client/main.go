package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/fxamacker/cbor/v2"
	"github.com/mhlotto/go-scitt-scrapi/scrapi/client"
	"github.com/veraison/go-cose"
)

func main() {
	addr := flag.String("addr", "http://localhost:8080", "base URL of the SCRAPI service")
	file := flag.String("file", "", "path to a COSE_Sign1 payload to submit (optional)")
	out := flag.String("out", "", "path to write the returned receipt (optional)")
	message := flag.String("message", "hello from scrapi-client", "payload to embed in a generated COSE_Sign1 when no file is provided")
	flag.Parse()

	cosePayload, err := loadPayload(*file, *message)
	if err != nil {
		log.Fatalf("prepare payload: %v", err)
	}

	c := client.Client{BaseURL: *addr}
	locator, receipt, err := c.Register(context.Background(), cosePayload)
	if err != nil {
		log.Fatalf("register entry: %v", err)
	}

	fmt.Printf("Registered entry locator: %s\n", locator)
	fmt.Printf("Receipt size: %d bytes\n", len(receipt))

	if *out != "" && len(receipt) > 0 {
		if err := os.WriteFile(*out, receipt, 0644); err != nil {
			log.Fatalf("write receipt: %v", err)
		}
		fmt.Printf("Receipt written to %s\n", *out)
	}
}

// loadPayload returns COSE_Sign1 bytes either from a file or by generating a simple message.
func loadPayload(path string, msg string) ([]byte, error) {
	if path != "" {
		return os.ReadFile(path)
	}

	sign1 := cose.Sign1Message{
		Payload: []byte(msg),
	}
	return cbor.Marshal(sign1)
}
