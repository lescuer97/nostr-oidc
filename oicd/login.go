package oicd

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/go-chi/chi/v5"
	"github.com/lescuer97/nostr-oicd/templates"
	"github.com/nbd-wtf/go-nostr"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	queryAuthRequestID = "authRequestID"
)

type login struct {
	authenticate authenticate
	router       chi.Router
	callback     func(context.Context, string) string
}

func NewLogin(authenticate authenticate, callback func(context.Context, string) string, issuerInterceptor *op.IssuerInterceptor) *login {
	l := &login{
		authenticate: authenticate,
		callback:     callback,
	}
	l.createRouter(issuerInterceptor)
	return l
}
func (l *login) createRouter(issuerInterceptor *op.IssuerInterceptor) {
	l.router = chi.NewRouter()
	l.router.Get("/username", l.loginHandler)
	l.router.Post("/username", issuerInterceptor.HandlerFunc(l.checkLoginHandler))
}

type authenticate interface {
	CheckUserNpub(id string, publicKey *btcec.PublicKey) error
}

func (l *login) loginHandler(w http.ResponseWriter, r *http.Request) {
	// l.authenticate.
	// err := r.ParseForm()
	// if err != nil {
	// 	http.Error(w, fmt.Sprintf("cannot parse form:%s", err), http.StatusInternalServerError)
	// 	return
	// }

	// nonce, err := serverData.auth.MakeNonce()
	// if err != nil {
	// 	http.Error(w, "Something happened", http.StatusInternalServerError)
	// }

	templates.Login("test").Render(r.Context(), w)
}


func (l *login) checkLoginHandler(w http.ResponseWriter, r *http.Request) {
	var nostrEvent nostr.Event
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}
	defer r.Body.Close()
	err = json.Unmarshal(body, &nostrEvent)
	if err != nil {
		return
	}

	// check valid signature
	validSig, err := nostrEvent.CheckSignature()
	if err != nil {
		return
	}
	if !validSig {
		http.Error(w, "invalid signature", http.StatusBadRequest)
		return
	}

	pubkeyBytes, err := hex.DecodeString(nostrEvent.PubKey)
	if err != nil {
		return
	}
	pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
	if err != nil {
		return
	}

	id := r.FormValue("id")
	err = l.authenticate.CheckUserNpub(id, pubkey)
	if err != nil {
		// renderLogin(w, id, err)
		return
	}
	http.Redirect(w, r, l.callback(r.Context(), id), http.StatusFound)
}
