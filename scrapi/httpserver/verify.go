package httpserver

import (
	"net/http"

	"github.com/fxamacker/cbor/v2"
	"github.com/mhlotto/go-scitt-scrapi/scrapi"
)

// verifyHandler returns receipt + STH payload (and consistency proof when applicable) in one call.
func verifyHandler(opts HandlerOptions, logger *log.Logger) http.HandlerFunc {
	type response struct {
		Receipt []byte             `cbor:"receipt,omitempty"`
		STH     []byte             `cbor:"sth,omitempty"`
		Proof   []scrapi.ProofNode `cbor:"consistency_proof,omitempty"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := authorize(opts, r); err != nil {
			writeProblem(w, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}

		id, err := extractID(r.URL.Path, "/verify/")
		if err != nil {
			writeProblem(w, http.StatusNotFound, "missing id", err.Error())
			return
		}

		status, receipt, err := opts.Service.QueryStatus(r.Context(), scrapi.Locator{ID: id})
		if err != nil || status != scrapi.StatusSuccess || receipt == nil {
			writeProblem(w, http.StatusNotFound, "receipt not found", "locator not registered or receipt unavailable")
			return
		}

		sth, err := opts.Service.CurrentSTH(r.Context())
		if err != nil {
			writeProblem(w, http.StatusNotFound, "sth not available", err.Error())
			return
		}

		var proof []scrapi.ProofNode
		// Try to parse receipt payload to determine size and fetch consistency proof if newer STH.
		if receipt.Msg != nil {
			var payload scrapi.ReceiptPayload
			if err := cbor.Unmarshal(receipt.Msg.Payload, &payload); err == nil {
				if payload.TreeSize < sthPayloadSize(sth) {
					if p, err := opts.Service.ConsistencyProof(r.Context(), payload.TreeSize, sthPayloadSize(sth)); err == nil {
						proof = p
					}
				}
			}
		}

		resp := response{
			Receipt: receipt.Raw,
			STH:     sth.Raw,
			Proof:   proof,
		}

		body, err := cbor.Marshal(resp)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "encode verify response", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/cbor")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
}

func sthPayloadSize(sth *scrapi.SignedTreeHead) uint64 {
	if sth == nil || sth.Msg == nil {
		return 0
	}
	var payload scrapi.STHPayload
	if err := cbor.Unmarshal(sth.Msg.Payload, &payload); err != nil {
		return 0
	}
	return payload.TreeSize
}
