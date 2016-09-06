package router

import (
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
)

type session struct {
	CookieSecret        string `json:"cookie_secret"`
	CookieName          string `json:"cookie_name"`
	CookieDurationDays  int64  `json:"cookie_duration_days"`
	CookieFlagHttpOnly  bool   `json:"cooke_flag_http_only"`
	CookieFlagSecure    bool   `json:"cooke_flag_secure"`
	SessionHeaderPrefix string `json:"session_header_prefix"`
	securecookie        *securecookie.SecureCookie
}

type sessionStore map[string]string

func (s *session) finalize() {
	s.securecookie = securecookie.New([]byte(s.CookieSecret), nil)
}

func (s *session) unpackStore(r *http.Request) (sessionStore, error) {
	store := make(sessionStore)

	cookie, err := r.Cookie(s.CookieName)
	if err != nil {
		return store, err
	}

	err = s.securecookie.Decode(s.CookieName, cookie.Value, &store)
	return store, err
}

func (s *session) packStore(store sessionStore, w http.ResponseWriter) error {
	encoded, err := s.securecookie.Encode(s.CookieName, store)
	if err != nil {
		return err
	}

	expireTime := time.Duration(s.CookieDurationDays*24) * time.Hour

	http.SetCookie(w, &http.Cookie{
		Name:     s.CookieName,
		HttpOnly: s.CookieFlagHttpOnly,
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
		MaxAge: -1,
	})
}
