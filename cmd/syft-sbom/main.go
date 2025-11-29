package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
)

func main() {
	source := flag.String("source", ".", "target to catalog (dir, file, or image ref)")
	out := flag.String("out", "", "path to write the SBOM (default stdout)")
	formatName := flag.String("format", "cyclonedx-json", "output format: cyclonedx-json|spdx-json|syft-json")
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
