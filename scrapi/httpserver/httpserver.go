package httpserver

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/mhlotto/go-scitt-scrapi/scrapi"
	"github.com/veraison/go-cose"
)

type HandlerOptions struct {
	Service         scrapi.TransparencyService
	Logger          *log.Logger
	LogKeyID        []byte
	LogPubKey       []byte
	HashAlg         string
	TreeType        string
	SCRAPIVersion   string
	AuthSchemes     []string
	AuthFunc        func(*http.Request) error
	ServiceEndpoint string
}

// NewMux wires up SCRAPI-flavored routes.
func NewMux(opts HandlerOptions) http.Handler {
	logger := opts.Logger
	if logger == nil {
		logger = log.Default()
	}
	mux := http.NewServeMux()
	mux.Handle("/.well-known/scitt", scittConfigHandler(opts, logger))
	mux.Handle("/.well-known/transparency-sth", sthHandler(opts, logger))
	mux.Handle("/consistency", consistencyHandler(opts, logger))
	mux.Handle("/statements", statementsHandler(opts, logger))
	mux.Handle("/statements/", statementStatusHandler(opts, logger))
	mux.Handle("/receipts/", resolveReceiptHandler(opts, logger))
	return mux
}

func scittConfigHandler(opts HandlerOptions, logger *log.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		cfg := map[string]any{
			"serviceEndpoint": opts.ServiceEndpoint,
			"version":         opts.SCRAPIVersion,
			"treeAlgorithm":   opts.TreeType,
			"hashAlgorithm":   opts.HashAlg,
		}
		if len(opts.LogPubKey) > 0 {
			cfg["tsPublicKeys"] = []map[string]any{
				{
					"kid":       opts.LogKeyID,
					"publicKey": opts.LogPubKey,
					"alg":       cose.AlgorithmEdDSA,
					"format":    "ed25519-pkcs8",
				},
			}
		}
		if len(opts.AuthSchemes) > 0 {
			cfg["auth_schemes"] = opts.AuthSchemes
		}
		cfg["extensions"] = map[string]any{
			"sth_endpoint":         "/.well-known/transparency-sth",
			"consistency_endpoint": "/consistency",
			"receipts_endpoint":    "/receipts/{statement_id}",
		}

		payload, err := json.Marshal(cfg)
		if err != nil {
			logger.Printf("config encode error: %v", err)
			writeProblem(w, http.StatusInternalServerError, "encode configuration", err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}
}

func sthHandler(opts HandlerOptions, logger *log.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := authorize(opts, r); err != nil {
			writeProblem(w, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}
		sth, err := opts.Service.CurrentSTH(r.Context())
		if err != nil {
			writeProblem(w, http.StatusNotFound, "sth not available", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/cose")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(sth.Raw)
		logger.Printf("served STH bytes=%d", len(sth.Raw))
	}
}

func consistencyHandler(opts HandlerOptions, logger *log.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := authorize(opts, r); err != nil {
			writeProblem(w, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}
		firstStr := r.URL.Query().Get("first")
		secondStr := r.URL.Query().Get("second")
		first, err1 := strconv.ParseUint(firstStr, 10, 64)
		second, err2 := strconv.ParseUint(secondStr, 10, 64)
		if err1 != nil || err2 != nil {
			writeProblem(w, http.StatusBadRequest, "invalid parameters", "first and second must be integers")
			return
		}
		proof, err := opts.Service.ConsistencyProof(r.Context(), first, second)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "consistency proof failed", err.Error())
			return
		}
		payload, err := cbor.Marshal(proof)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "encode proof", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/cbor")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
		logger.Printf("served consistency proof first=%d second=%d nodes=%d", first, second, len(proof))
	}
}

func statementsHandler(opts HandlerOptions, logger *log.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := authorize(opts, r); err != nil {
			writeProblem(w, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			logger.Printf("register read error: %v", err)
			writeProblem(w, http.StatusBadRequest, "read body", err.Error())
			return
		}
		defer r.Body.Close()

		const maxBody = 50 << 20 // 50 MiB guard for the demo
		if len(body) > maxBody {
			writeProblem(w, http.StatusRequestEntityTooLarge, "payload too large", "limit 50MiB for demo")
			return
		}

		ct := r.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, mediaTypeStatement) && !strings.HasPrefix(ct, "application/cose") {
			writeProblem(w, http.StatusUnsupportedMediaType, "invalid content type", "expected application/scitt-statement+cose")
			return
		}

		if accept := r.Header.Get("Accept"); accept != "" && !accepts(accept, "", mediaTypeReceipt, mediaTypeProblemJSON) {
			writeProblem(w, http.StatusNotAcceptable, "unsupported accept", "only application/scitt-receipt+cose or problem+json are supported")
			return
		}

		var msg cose.Sign1Message
		if err := cbor.Unmarshal(body, &msg); err != nil {
			logger.Printf("register unmarshal error: %v", err)
			writeProblem(w, http.StatusBadRequest, "parse COSE_Sign1", err.Error())
			return
		}
		if msg.Payload == nil {
			writeProblem(w, http.StatusBadRequest, "missing payload", "statement payload is empty")
			return
		}
		if _, err := scrapi.DecodeEnvelope(msg.Payload); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid statement envelope", err.Error())
			return
		}
		ss := scrapi.SignedStatement{Raw: body, Msg: &msg}

		loc, receipt, err := opts.Service.Register(r.Context(), ss)
		if err != nil {
			logger.Printf("registration failed: %v", err)
			writeProblem(w, http.StatusBadRequest, "registration failed", err.Error())
			return
		}

		logger.Printf("registered statement id=%s bytes=%d", loc.ID, len(body))

		location := "/statements/" + loc.ID
		w.Header().Set("Location", location)

		if receipt != nil {
			w.Header().Set("Content-Type", mediaTypeReceipt)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(receipt.Raw)
			return
		}

		w.WriteHeader(http.StatusAccepted)
	}
}

func statementStatusHandler(opts HandlerOptions, logger *log.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := authorize(opts, r); err != nil {
			writeProblem(w, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}

		id, err := extractID(r.URL.Path, "/statements/")
		if err != nil {
			writeProblem(w, http.StatusNotFound, "missing id", err.Error())
			return
		}

		status, receipt, err := opts.Service.QueryStatus(r.Context(), scrapi.Locator{ID: id})
		if err != nil {
			logger.Printf("status lookup failed id=%s: %v", id, err)
			writeProblem(w, http.StatusNotFound, "lookup failed", err.Error())
			return
		}

		switch status {
		case scrapi.StatusPending:
			w.Header().Set("Location", "/statements/"+id)
			w.WriteHeader(http.StatusAccepted)
			logger.Printf("status pending id=%s", id)
		case scrapi.StatusFailed:
			writeProblem(w, http.StatusConflict, "registration failed", "the statement could not be included")
			logger.Printf("status failed id=%s", id)
		case scrapi.StatusSuccess:
			if receipt == nil {
				w.WriteHeader(http.StatusNoContent)
				logger.Printf("status success id=%s no receipt", id)
				return
			}
			stmt, err := opts.Service.Statement(r.Context(), id)
			if err != nil {
				writeProblem(w, http.StatusNotFound, "statement not found", err.Error())
				return
			}
			if !accepts(r.Header.Get("Accept"), "", mediaTypeStatement, mediaTypeProblemJSON) {
				writeProblem(w, http.StatusNotAcceptable, "unsupported accept", "only application/scitt-statement+cose or problem+json are supported")
				return
			}
			w.Header().Set("Content-Type", mediaTypeStatement)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(stmt.Raw)
			logger.Printf("status success id=%s statement-bytes=%d", id, len(stmt.Raw))
		default:
			writeProblem(w, http.StatusInternalServerError, "unknown status", string(status))
			logger.Printf("status unknown id=%s status=%s", id, status)
		}
	}
}

func resolveReceiptHandler(opts HandlerOptions, logger *log.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := authorize(opts, r); err != nil {
			writeProblem(w, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}

		id, err := extractID(r.URL.Path, "/receipts/")
		if err != nil {
			writeProblem(w, http.StatusNotFound, "missing id", err.Error())
			return
		}

		receipt, err := opts.Service.ResolveReceipt(r.Context(), id)
		if err != nil || receipt == nil {
			writeProblem(w, http.StatusNotFound, "receipt not found", "no receipt with that id")
			logger.Printf("receipt not found id=%s: %v", id, err)
			return
		}

		if !accepts(r.Header.Get("Accept"), "", mediaTypeReceipt, mediaTypeProblemJSON) {
			writeProblem(w, http.StatusNotAcceptable, "unsupported accept", "only application/scitt-receipt+cose or problem+json are supported")
			return
		}

		w.Header().Set("Content-Type", mediaTypeReceipt)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(receipt.Raw)
		logger.Printf("receipt resolved id=%s bytes=%d", id, len(receipt.Raw))
	}
}

func extractID(path, prefix string) (string, error) {
	if !strings.HasPrefix(path, prefix) {
		return "", errors.New("invalid path")
	}
	id := strings.TrimPrefix(path, prefix)
	if id == "" {
		return "", errors.New("empty id")
	}
	if strings.Contains(id, "/") {
		return "", errors.New("unexpected extra path segments")
	}
	return id, nil
}

// writeProblem emits problem+json for SCRAPI-style errors.
func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", mediaTypeProblemJSON)
	w.WriteHeader(status)

	payload := map[string]any{
		"type":   "about:blank",
		"title":  title,
		"detail": detail,
		"status": status,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_, _ = w.Write(data)
}

func authorize(opts HandlerOptions, r *http.Request) error {
	if opts.AuthFunc == nil {
		return nil
	}
	return opts.AuthFunc(r)
}

func accepts(header, fallback string, allowed ...string) bool {
	if header == "" {
		header = fallback
	}
	if header == "" {
		return true
	}
	for _, a := range strings.Split(header, ",") {
		a = strings.TrimSpace(strings.SplitN(a, ";", 2)[0])
		for _, allow := range allowed {
			if allow != "" && strings.HasPrefix(a, allow) {
				return true
			}
		}
	}
	return false
}

const (
	mediaTypeStatement   = "application/scitt-statement+cose"
	mediaTypeReceipt     = "application/scitt-receipt+cose"
	mediaTypeProblemJSON = "application/problem+json"
)
