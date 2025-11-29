package httpserver

import (
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/mhlotto/go-scitt-scrapi/scrapi"
	"github.com/veraison/go-cose"
)

type HandlerOptions struct {
	Service   scrapi.TransparencyService
	IssuerURL string
	JWKSURL   string
	Logger    *log.Logger
	LogKeyID  []byte
	LogPubKey []byte
	HashAlg   string
	TreeType  string
}

// NewMux wires up SCRAPI-flavored routes.
func NewMux(opts HandlerOptions) http.Handler {
	logger := opts.Logger
	if logger == nil {
		logger = log.Default()
	}
	mux := http.NewServeMux()
	mux.Handle("/.well-known/transparency-configuration", transparencyConfigHandler(opts, logger))
	mux.Handle("/entries", registerHandler(opts, logger))
	mux.Handle("/entries/", queryStatusHandler(opts, logger))
	mux.Handle("/receipts/", resolveReceiptHandler(opts, logger))
	return mux
}

func transparencyConfigHandler(opts HandlerOptions, logger *log.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		cfg := map[string]any{
			"issuer": opts.IssuerURL,
		}
		if opts.JWKSURL != "" {
			cfg["jwks_uri"] = opts.JWKSURL
		}
		if len(opts.LogPubKey) > 0 {
			cfg["log_public_key"] = opts.LogPubKey
		}
		if len(opts.LogKeyID) > 0 {
			cfg["log_key_id"] = opts.LogKeyID
		}
		if opts.HashAlg != "" {
			cfg["hash_alg"] = opts.HashAlg
		}
		if opts.TreeType != "" {
			cfg["tree_type"] = opts.TreeType
		}

		payload, err := cbor.Marshal(cfg)
		if err != nil {
			logger.Printf("config encode error: %v", err)
			writeProblem(w, http.StatusInternalServerError, "encode configuration", err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/cbor")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}
}

func registerHandler(opts HandlerOptions, logger *log.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/cose") {
			writeProblem(w, http.StatusUnsupportedMediaType, "invalid content type", "expected application/cose")
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			logger.Printf("register read error: %v", err)
			writeProblem(w, http.StatusBadRequest, "read body", err.Error())
			return
		}
		defer r.Body.Close()

		var msg cose.Sign1Message
		if err := cbor.Unmarshal(body, &msg); err != nil {
			logger.Printf("register unmarshal error: %v", err)
			writeProblem(w, http.StatusBadRequest, "parse COSE_Sign1", err.Error())
			return
		}

		loc, receipt, err := opts.Service.Register(r.Context(), scrapi.SignedStatement{
			Raw: body,
			Msg: &msg,
		})
		if err != nil {
			logger.Printf("registration failed: %v", err)
			writeProblem(w, http.StatusBadRequest, "registration failed", err.Error())
			return
		}

		logger.Printf("registered statement id=%s bytes=%d", loc.ID, len(body))

		location := "/entries/" + loc.ID
		w.Header().Set("Location", location)

		if receipt != nil {
			w.Header().Set("Content-Type", "application/cose")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(receipt.Raw)
			return
		}

		w.WriteHeader(http.StatusSeeOther)
	}
}

func queryStatusHandler(opts HandlerOptions, logger *log.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		id, err := extractID(r.URL.Path, "/entries/")
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
			w.Header().Set("Location", "/entries/"+id)
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
			w.Header().Set("Content-Type", "application/cose")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(receipt.Raw)
			logger.Printf("status success id=%s receipt-bytes=%d", id, len(receipt.Raw))
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

		w.Header().Set("Content-Type", "application/cose")
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

// writeProblem emits Concise Problem Details encoded as CBOR.
func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/concise-problem-details+cbor")
	w.WriteHeader(status)

	payload := map[int]string{
		-1: title,
		-2: detail,
	}
	data, err := cbor.Marshal(payload)
	if err != nil {
		return
	}
	_, _ = w.Write(data)
}
