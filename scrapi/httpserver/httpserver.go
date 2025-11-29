package httpserver

import (
	"errors"
	"io"
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
}

// NewMux wires up SCRAPI-flavored routes.
func NewMux(opts HandlerOptions) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/.well-known/transparency-configuration", transparencyConfigHandler(opts))
	mux.Handle("/entries", registerHandler(opts))
	mux.Handle("/entries/", queryStatusHandler(opts))
	mux.Handle("/receipts/", resolveReceiptHandler(opts))
	return mux
}

func transparencyConfigHandler(opts HandlerOptions) http.HandlerFunc {
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

		payload, err := cbor.Marshal(cfg)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "encode configuration", err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/cbor")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}
}

func registerHandler(opts HandlerOptions) http.HandlerFunc {
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
			writeProblem(w, http.StatusBadRequest, "read body", err.Error())
			return
		}
		defer r.Body.Close()

		var msg cose.Sign1Message
		if err := cbor.Unmarshal(body, &msg); err != nil {
			writeProblem(w, http.StatusBadRequest, "parse COSE_Sign1", err.Error())
			return
		}

		loc, receipt, err := opts.Service.Register(r.Context(), scrapi.SignedStatement{
			Raw: body,
			Msg: &msg,
		})
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "registration failed", err.Error())
			return
		}

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

func queryStatusHandler(opts HandlerOptions) http.HandlerFunc {
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
			writeProblem(w, http.StatusNotFound, "lookup failed", err.Error())
			return
		}

		switch status {
		case scrapi.StatusPending:
			w.Header().Set("Location", "/entries/"+id)
			w.WriteHeader(http.StatusAccepted)
		case scrapi.StatusFailed:
			writeProblem(w, http.StatusConflict, "registration failed", "the statement could not be included")
		case scrapi.StatusSuccess:
			if receipt == nil {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.Header().Set("Content-Type", "application/cose")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(receipt.Raw)
		default:
			writeProblem(w, http.StatusInternalServerError, "unknown status", string(status))
		}
	}
}

func resolveReceiptHandler(opts HandlerOptions) http.HandlerFunc {
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
			return
		}

		w.Header().Set("Content-Type", "application/cose")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(receipt.Raw)
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
