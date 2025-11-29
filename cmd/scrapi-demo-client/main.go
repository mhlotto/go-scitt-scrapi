package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
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
	sbom := flag.String("sbom", "", "path to an SBOM (CycloneDX/SPDX JSON) to submit")
	wrapSBOM := flag.Bool("wrap-sbom", true, "wrap SBOM bytes into a COSE_Sign1 before sending")
	vex := flag.String("vex", "", "path to a VEX/CSAF-like advisory JSON to submit")
	out := flag.String("out", "", "path to write the returned receipt (optional)")
	message := flag.String("message", "hello from scrapi-client", "payload to embed in a generated COSE_Sign1 when no file is provided")
	expectLeaf := flag.Bool("check-leaf", true, "check receipt leaf hash matches submitted payload hash")
	token := flag.String("token", "", "optional bearer token for Authorization header")
	caPath := flag.String("tls-ca", "", "path to CA bundle to trust (optional)")
	clientCert := flag.String("tls-cert", "", "path to client TLS cert (optional)")
	clientKey := flag.String("tls-key", "", "path to client TLS key (optional)")
	noPoll := flag.Bool("no-poll", false, "do not poll for receipt if registration is pending")
	pollAttempts := flag.Int("poll-attempts", 10, "max polling attempts when waiting for receipt")
	pollInterval := flag.Duration("poll-interval", 2*time.Second, "poll interval when waiting for receipt")
	printReceiptJSON := flag.Bool("print-receipt-json", false, "print decoded receipt payload as JSON")
	fetchReceipts := flag.Bool("fetch-receipts", false, "fetch /receipts/{id} after registration")
	flag.Parse()

	payload, contentType, checkLeaf, err := loadPayload(*file, *sbom, *vex, *message, *wrapSBOM, *expectLeaf)
	if err != nil {
		log.Fatalf("prepare payload: %v", err)
	}

	transport := http.DefaultTransport
	if *caPath != "" || *clientCert != "" || *clientKey != "" {
		cfg, err := buildTLSConfig(*caPath, *clientCert, *clientKey)
		if err != nil {
			log.Fatalf("tls config: %v", err)
		}
		transport = &http.Transport{TLSClientConfig: cfg}
	}
	httpClient := &http.Client{Transport: transport}

	c := client.Client{BaseURL: *addr, HTTPClient: httpClient, Token: *token}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	locator, receipt, err := c.RegisterWithContentType(ctx, payload, contentType)
	if err != nil {
		log.Fatalf("register entry: %v", err)
	}

	fmt.Printf("Registered entry locator: %s\n", locator)
	fmt.Printf("Receipt size: %d bytes\n", len(receipt))

	if len(receipt) == 0 && !*noPoll {
		fmt.Println("No receipt yet; polling /entries/{id} ...")
		receipt, err = c.FetchReceipt(ctx, locator, *pollAttempts, *pollInterval)
		if err != nil {
			log.Fatalf("poll for receipt: %v", err)
		}
		fmt.Printf("Fetched receipt after polling (%d bytes)\n", len(receipt))
	}

	if len(receipt) > 0 {
		if err := verifyReceipt(context.Background(), httpClient, *addr, locator, receipt, payload, checkLeaf, *printReceiptJSON); err != nil {
			log.Fatalf("verify receipt: %v", err)
		}
	}

	if *fetchReceipts {
		fmt.Println("Fetching /receipts/{id} ...")
		data, err := c.FetchReceipt(ctx, locator, 1, 0)
		if err != nil {
			log.Fatalf("fetch /receipts/{id}: %v", err)
		}
		fmt.Printf("Fetched receipt directly (%d bytes)\n", len(data))
		if err := verifyReceipt(context.Background(), httpClient, *addr, locator, data, payload, checkLeaf, *printReceiptJSON); err != nil {
			log.Fatalf("verify fetched receipt: %v", err)
		}
	}

	if *out != "" && len(receipt) > 0 {
		if err := os.WriteFile(*out, receipt, 0600); err != nil {
			log.Fatalf("write receipt: %v", err)
		}
		fmt.Printf("Receipt written to %s\n", *out)
	}
}

// loadPayload returns the bytes to submit, content type, and whether to check leaf hash.
func loadPayload(cosePath, sbomPath, vexPath, msg string, wrapSBOM bool, checkLeaf bool) ([]byte, string, bool, error) {
	switch {
	case cosePath != "":
		data, err := os.ReadFile(filepath.Clean(cosePath))
		return data, "application/cose", checkLeaf, err
	case vexPath != "":
		data, err := os.ReadFile(filepath.Clean(vexPath))
		if err != nil {
			return nil, "", checkLeaf, err
		}
		signer, _, kid, err := scrapi.NewEd25519Signer("vex-demo-key")
		if err != nil {
			return nil, "", checkLeaf, err
		}
		ss, err := scrapi.WrapPayloadAsCOSE(data, signer, kid)
		if err != nil {
			return nil, "", checkLeaf, err
		}
		return ss.Raw, "application/cose", checkLeaf, nil
	case sbomPath != "":
		data, err := os.ReadFile(filepath.Clean(sbomPath))
		if err != nil {
			return nil, "", checkLeaf, err
		}
		if wrapSBOM {
			signer, _, kid, err := scrapi.NewEd25519Signer("sbom-demo-key")
			if err != nil {
				return nil, "", checkLeaf, err
			}
			ss, err := scrapi.WrapPayloadAsCOSE(data, signer, kid)
			if err != nil {
				return nil, "", checkLeaf, err
			}
			return ss.Raw, "application/cose", checkLeaf, nil
		}
		// Sending raw SBOM; skip leaf check since server will re-wrap.
		return data, guessSBOMContentType(sbomPath), false, nil
	default:
		sign1 := cose.Sign1Message{
			Payload: []byte(msg),
		}
		raw, err := cbor.Marshal(sign1)
		return raw, "application/cose", checkLeaf, err
	}
}

func verifyReceipt(ctx context.Context, httpClient *http.Client, baseURL, locator string, receiptRaw []byte, submitted []byte, checkLeaf bool, printJSON bool) error {
	// Fetch configuration to get the log public key.
	cfgURL := strings.TrimSuffix(baseURL, "/") + "/.well-known/transparency-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfgURL, nil)
	if err != nil {
		return fmt.Errorf("build config request: %w", err)
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
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
	if printJSON {
		encoded, _ := cbor.Marshal(payload)
		fmt.Printf("  payload-cbor: %x\n", encoded)
		jsonBytes, _ := json.MarshalIndent(payload, "", "  ")
		fmt.Printf("  payload-json:\n%s\n", string(jsonBytes))
	}

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

func guessSBOMContentType(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".cdx.json"), strings.HasSuffix(lower, ".cyclonedx.json"):
		return "application/vnd.cyclonedx+json"
	case strings.HasSuffix(lower, ".spdx.json"), strings.HasSuffix(lower, ".spdx.jsonld"):
		return "application/spdx+json"
	default:
		return "application/sbom+json"
	}
}

func buildTLSConfig(caPath, certPath, keyPath string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caPath != "" {
		rootCAs, err := x509.SystemCertPool()
		if err != nil {
			rootCAs = x509.NewCertPool()
		}
		data, err := os.ReadFile(filepath.Clean(caPath))
		if err != nil {
			return nil, fmt.Errorf("read ca: %w", err)
		}
		if ok := rootCAs.AppendCertsFromPEM(data); !ok {
			return nil, fmt.Errorf("failed to append CA certs")
		}
		cfg.RootCAs = rootCAs
	}
	if certPath != "" && keyPath != "" {
		cert, err := tls.LoadX509KeyPair(filepath.Clean(certPath), filepath.Clean(keyPath))
		if err != nil {
			return nil, fmt.Errorf("load client cert/key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
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
