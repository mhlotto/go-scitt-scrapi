package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/mhlotto/go-scitt-scrapi/scrapi"
	"github.com/veraison/go-cose"
)

func main() {
	source := flag.String("source", ".", "target to catalog (dir, file, or image ref)")
	out := flag.String("out", "", "path to write the SBOM (default stdout)")
	formatName := flag.String("format", "cyclonedx-json", "output format: cyclonedx-json|spdx-json|syft-json")
	sign := flag.Bool("sign", false, "sign the SBOM into COSE_Sign1")
	signKid := flag.String("sign-kid", "sbom-demo-kid", "kid to place in COSE header when signing")
	privKeyPath := flag.String("sign-priv", "", "Ed25519 private key (PKCS#8 PEM); if empty, a new key is generated")
	coseOut := flag.String("cose-out", "", "path to write signed COSE_Sign1 (requires -sign)")
	pubOut := flag.String("pub-out", "", "path to write signer public key PEM (requires -sign)")
	flag.Parse()

	enc, err := encoderFor(*formatName)
	if err != nil {
		log.Fatalf("format: %v", err)
	}

	ctx := context.Background()
	src, err := syft.GetSource(ctx, *source, nil)
	if err != nil {
		log.Fatalf("get source: %v", err)
	}
	defer src.Close()

	sbom, err := syft.CreateSBOM(ctx, src, nil)
	if err != nil {
		log.Fatalf("create sbom: %v", err)
	}

	data, err := format.Encode(*sbom, enc)
	if err != nil {
		log.Fatalf("encode sbom: %v", err)
	}

	if *sign {
		ss, pub, err := signSbom(data, *signKid, *privKeyPath)
		if err != nil {
			log.Fatalf("sign sbom: %v", err)
		}
		if *coseOut == "" {
			fmt.Print(string(data))
			log.Fatalf("cose-out is required when -sign is set")
		}
		if err := os.WriteFile(*coseOut, ss.Raw, 0600); err != nil {
			log.Fatalf("write cose: %v", err)
		}
		fmt.Printf("Signed COSE_Sign1 written to %s\n", *coseOut)
		if *pubOut != "" {
			if err := writePublicKeyPEM(pub, *pubOut); err != nil {
				log.Fatalf("write pubkey: %v", err)
			}
			fmt.Printf("Signer public key written to %s\n", *pubOut)
		}
	}

	if *out == "" {
		fmt.Print(string(data))
		return
	}
	if err := os.WriteFile(*out, data, 0600); err != nil {
		log.Fatalf("write sbom: %v", err)
	}
	fmt.Printf("SBOM written to %s\n", *out)
}

func encoderFor(name string) (sbom.FormatEncoder, error) {
	switch name {
	case "cyclonedx-json":
		return cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	case "spdx-json":
		return spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())
	case "syft-json":
		return syftjson.NewFormatEncoder(), nil
	default:
		return nil, fmt.Errorf("unsupported format %q", name)
	}
}

func signSbom(sbomBytes []byte, kid string, privPath string) (scrapi.SignedStatement, ed25519.PublicKey, error) {
	var priv ed25519.PrivateKey
	var pub ed25519.PublicKey
	if privPath != "" {
		pemBytes, err := os.ReadFile(filepath.Clean(privPath))
		if err != nil {
			return scrapi.SignedStatement{}, nil, fmt.Errorf("read priv: %w", err)
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return scrapi.SignedStatement{}, nil, fmt.Errorf("decode priv: empty PEM")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return scrapi.SignedStatement{}, nil, fmt.Errorf("parse priv: %w", err)
		}
		var ok bool
		priv, ok = key.(ed25519.PrivateKey)
		if !ok {
			return scrapi.SignedStatement{}, nil, fmt.Errorf("priv is not ed25519")
		}
		pub = priv.Public().(ed25519.PublicKey)
	} else {
		var err error
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return scrapi.SignedStatement{}, nil, fmt.Errorf("generate ed25519: %w", err)
		}
	}

	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, priv)
	if err != nil {
		return scrapi.SignedStatement{}, nil, fmt.Errorf("create signer: %w", err)
	}
	ss, err := scrapi.WrapPayloadAsCOSE(sbomBytes, signer, []byte(kid))
	if err != nil {
		return scrapi.SignedStatement{}, nil, fmt.Errorf("wrap cose: %w", err)
	}
	return ss, pub, nil
}

func writePublicKeyPEM(pub ed25519.PublicKey, path string) error {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("marshal pub: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return os.WriteFile(filepath.Clean(path), pemBytes, 0600)
}
