// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package state

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const oidcLoginSessionCookie = "non_existent_cookie"

var nonceChars = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

type state struct {
	OrigURL string
}

type Config struct {
	SchemeDefault string
	SchemeHeader  string
	SessionDomain string
}

type StateFunc func(*http.Request) *state

func NewStateFunc(config *Config) StateFunc {
	if len(config.SessionDomain) > 0 {
		return newSchemeAndHost(config)
	}
	return relativeURL
}

func relativeURL(r *http.Request) *state {
	return &state{
		OrigURL: r.URL.String(),
	}
}

func newSchemeAndHost(config *Config) StateFunc {
	return func(r *http.Request) *state {
		// Use header value if it exists
		s := r.Header.Get(config.SchemeHeader)
		if s == "" {
			s = config.SchemeDefault
		}
		// XXX Could return an error here. Would require changing the StateFunc type
		if !strings.HasSuffix(r.Host, config.SessionDomain) {
			log.Warnf("Request host %q is not a subdomain of %q", r.Host, config.SessionDomain)
		}
		return &state{
			OrigURL: s + "://" + r.Host + r.URL.String(),
		}
	}
}

// load retrieves a state from the store given its id.
func Load(store sessions.Store, id string) (*state, error) {
	// Make a fake request so that the store will find the cookie
	r := &http.Request{Header: make(http.Header)}
	r.AddCookie(&http.Cookie{Name: oidcLoginSessionCookie, Value: id, MaxAge: 10})

	session, err := store.Get(r, oidcLoginSessionCookie)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if session.IsNew {
		return nil, errors.New("session does not exist")
	}

	return &state{
		OrigURL: session.Values["origURL"].(string),
	}, nil
}

// save persists a state to the store and returns the entry's id.
func (s *state) Save(store sessions.Store) (string, error) {
	session := sessions.NewSession(store, oidcLoginSessionCookie)
	var err error
	// Nonce has 64 different characters. So 2^6 possibilities per character.
	// Total bits of randomness are 6*length. For at least 256 bits of
	// randomness, we need ceil(256/6)=43 characters.
	session.ID, err = createNonce(43)
	if err != nil {
		return "", errors.Wrap(err, "failed to generate a random session ID")
	}
	session.Options.MaxAge = int(time.Hour)
	session.Values["origURL"] = s.OrigURL

	// The current gorilla/sessions Store interface doesn't allow us
	// to set the session ID.
	// Because of that, we have to retrieve it from the cookie value.
	w := httptest.NewRecorder()
	err = session.Save(&http.Request{}, w)
	if err != nil {
		return "", errors.Wrap(err, "error trying to save session")
	}
	// Cookie is persisted in ResponseWriter, make a request to parse it.
	r := &http.Request{Header: make(http.Header)}
	r.Header.Set("Cookie", w.Header().Get("Set-Cookie"))
	c, err := r.Cookie(oidcLoginSessionCookie)
	if err != nil {
		return "", errors.Wrap(err, "error trying to save session")
	}
	return c.Value, nil
}

func createNonce(length int) (string, error) {
	// XXX: To avoid modulo bias, 256 / len(nonceChars) MUST equal 0.
	// In this case, 256 / 64 = 0. See:
	// https://research.kudelskisecurity.com/2020/07/28/the-definitive-guide-to-modulo-bias-and-how-to-avoid-it/
	const nonceChars = "abcdefghijklmnopqrstuvwxyz:ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789"
	nonce := make([]byte, length)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	for i := range nonce {
		nonce[i] = nonceChars[int(nonce[i])%len(nonceChars)]
	}

	return string(nonce), nil
}
