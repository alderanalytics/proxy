package router

import (
	"net/http"
)

type authenticator interface {
	authenticate(r *http.Request) bool
}
