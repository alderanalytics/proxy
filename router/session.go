package router

import (
	"net/http"
	"time"

	"github.com/gorilla/context"
	"github.com/gorilla/securecookie"
)

type key int

const (
	sessionStoreKey key = iota
)

type session struct {
	CookieSecret             string `json:"cookie_secret"`
	CookieName               string `json:"cookie_name"`
	CookieDurationDays       int64  `json:"cookie_duration_days"`
	CookieFlagHTTPOnly       bool   `json:"cookie_flag_http_only"`
	CookieFlagSecure         bool   `json:"cookie_flag_secure"`
	SessionAuthenticationKey string `json:"session_authentication_key"`
	SessionHeaderPrefix      string `json:"session_header_prefix"`
	securecookie             *securecookie.SecureCookie
}

type sessionStore map[string]string

func (s sessionStore) hasItem(key string) bool {
	_, ok := s[key]
	return ok
}

func (s *session) finalize() {
	s.securecookie = securecookie.New([]byte(s.CookieSecret), nil)
}

func (s *session) authenticate(r *http.Request) bool {
	if s.SessionAuthenticationKey == "" {
		return false
	}

	if store, err := s.unpackStore(r); err == nil {
		return store.hasItem(s.SessionAuthenticationKey)
	}

	return false
}

func (s *session) unpackStore(r *http.Request) (sessionStore, error) {
	if cStore, ok := context.GetOk(r, sessionStoreKey); ok {
		return cStore.(sessionStore), nil
	}

	store := make(sessionStore)

	cookie, err := r.Cookie(s.CookieName)
	if err != nil {
		return store, err
	}

	if err = s.securecookie.Decode(s.CookieName, cookie.Value, &store); err != nil {
		return store, err
	}

	context.Set(r, sessionStoreKey, store)

	return store, nil
}

func (s *session) packStore(store sessionStore, w http.ResponseWriter) error {
	encoded, err := s.securecookie.Encode(s.CookieName, store)
	if err != nil {
		return err
	}

	expireTime := time.Duration(s.CookieDurationDays*24) * time.Hour

	http.SetCookie(w, &http.Cookie{
		Name:     s.CookieName,
		HttpOnly: s.CookieFlagHTTPOnly,
		Secure:   s.CookieFlagSecure,
		Value:    encoded,
		Path:     "/",
		Expires:  time.Now().Add(expireTime),
	})

	return nil
}

func (s *session) deleteStore(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   s.CookieName,
		Path:   "/",
		MaxAge: -1,
	})
}
