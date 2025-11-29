package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/mhlotto/go-scitt-scrapi/scrapi"
	"github.com/mhlotto/go-scitt-scrapi/scrapi/client"
	"github.com/veraison/go-cose"
)

func main() {
	addr := flag.String("addr", "http://localhost:8080", "base URL of the SCRAPI service")
	file := flag.String("file", "", "path to a COSE_Sign1 payload to submit (optional)")
	out := flag.String("out", "", "path to write the returned receipt (optional)")
	message := flag.String("message", "hello from scrapi-client", "payload to embed in a generated COSE_Sign1 when no file is provided")
	expectLeaf := flag.Bool("check-leaf", true, "check receipt leaf hash matches submitted payload hash")
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

	if len(receipt) > 0 {
		if err := verifyReceipt(context.Background(), *addr, locator, receipt, cosePayload, *expectLeaf); err != nil {
			log.Fatalf("verify receipt: %v", err)
		}
	}

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

func verifyReceipt(ctx context.Context, baseURL, locator string, receiptRaw []byte, submitted []byte, checkLeaf bool) error {
	// Fetch configuration to get the log public key.
	cfgURL := strings.TrimSuffix(baseURL, "/") + "/.well-known/transparency-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfgURL, nil)
	if err != nil {
		return fmt.Errorf("build config request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("get config: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("config status %s", resp.Status)
	}
	var cfg map[string]any
	if err := cbor.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return fmt.Errorf("decode config: %w", err)
	}

	rawKey, ok := cfg["log_public_key"]
	if !ok {
		return fmt.Errorf("missing log_public_key in config")
	}
	pubKeyBytes, ok := rawKey.([]byte)
	if !ok || len(pubKeyBytes) == 0 {
		return fmt.Errorf("log_public_key has unexpected type")
	}

	verifier, err := cose.NewVerifier(cose.AlgorithmEdDSA, ed25519.PublicKey(pubKeyBytes))
	if err != nil {
		return fmt.Errorf("build verifier: %w", err)
	}

	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(receiptRaw); err != nil {
		return fmt.Errorf("unmarshal receipt COSE: %w", err)
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return fmt.Errorf("verify COSE signature: %w", err)
	}

	var payload scrapi.ReceiptPayload
	if err := cbor.Unmarshal(msg.Payload, &payload); err != nil {
		return fmt.Errorf("decode receipt payload: %w", err)
	}

	fmt.Printf("Receipt verified\n")
	fmt.Printf("  log_id:   %s\n", payload.LogID)
	fmt.Printf("  tree_size:%d\n", payload.TreeSize)
	fmt.Printf("  root:     %x\n", payload.RootHash)
	fmt.Printf("  leaf:     %x\n", payload.LeafHash)
	fmt.Printf("  ts:       %s\n", time.Unix(payload.Timestamp, 0).UTC().Format(time.RFC3339))

	if err := checkMerkleProof(payload); err != nil {
		return fmt.Errorf("merkle proof check failed: %w", err)
	}
	fmt.Println("  merkle proof: ok")

	if checkLeaf {
		localLeaf := scrapiMerkleLeaf(submitted)
		if !equalBytes(localLeaf, payload.LeafHash) {
			return fmt.Errorf("leaf hash mismatch: local %x receipt %x", localLeaf, payload.LeafHash)
		}
		fmt.Println("  leaf hash matches submitted statement")
	}

	return nil
}

// checkMerkleProof recomputes the root from leaf and path.
func checkMerkleProof(p scrapi.ReceiptPayload) error {
	root := p.LeafHash
	for _, n := range p.Path {
		switch n.Position {
		case "left":
			root = scrapiMerkleNode(n.Hash, root)
		case "right":
			root = scrapiMerkleNode(root, n.Hash)
		default:
			return fmt.Errorf("unknown position %q", n.Position)
		}
	}
	if !equalBytes(root, p.RootHash) {
		return fmt.Errorf("computed root mismatch")
	}
	return nil
}

func scrapiMerkleNode(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

func scrapiMerkleLeaf(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
