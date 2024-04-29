package scslogin

import (
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"net/http"

	"github.com/alexedwards/scs/v2"
)

var ErrUserNotAuthenticated = errors.New("user is not authenticated")

const UserSessionKey = "user"
const ReturnToKey = "ReturnTo"

type UserProtocol[K any] interface {
	IsAuthenticated() bool
	GetID() K
}

// UserLoader is a function that takes a uniquely-identifying string and
// returns a user object of the specified type. This function is used to
// attach a user object to the request context.
type UserLoader[T UserProtocol[K], K comparable] func(context.Context, K) (T, error)

// AnonymousUser is a function that returns an anonymous user object. This
// function is used to attach an anonymous user object to the request context
// when the user is not authenticated.
type AnonymousUser[T UserProtocol[K], K comparable] func() T

type LoginRedirectConfig struct {
	// The URL to redirect to when the user is not authenticated. Should handle
	// redirection by checking the session for the "ReturnTo" key and redirecting
	// the user to that URL if it exists.
	LoginRedirectURL string

	// A function that can be used to customize the redirect response.
	// If this is nil, the default http.Redirect function will be used, redirecting
	// the user to the LoginRedirectURL with a 303 status code. Otherwise, this function
	// will be called with the redirect URL, the response writer, and the request.
	RedirectFunc func(string, http.ResponseWriter, *http.Request)
}

func DefaultLoginRedirectFunc(url string, w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, url, http.StatusSeeOther)
}

// DefaultLoginRedirectConfig returns a LoginRedirectConfig with the default
// redirect function, which uses http.Redirect to redirect the user to the
// specified URL with a 303 status code.
func DefaultLoginRedirectConfig(redirectURL string) LoginRedirectConfig {
	return LoginRedirectConfig{
		LoginRedirectURL: redirectURL,
		RedirectFunc:     DefaultLoginRedirectFunc,
	}
}

// NewLoginRedirectConfig returns a LoginRedirectConfig with the specified
// redirect URL and redirect function.
//
// Use this function if you want to customize the redirect behavior when the
// user is not authenticated, such as setting a different status code or adding
// additional headers.
func NewLoginRedirectConfig(redirectURL string, redirectFunc func(string, http.ResponseWriter, *http.Request)) LoginRedirectConfig {
	return LoginRedirectConfig{
		LoginRedirectURL: redirectURL,
		RedirectFunc:     redirectFunc,
	}
}

type IdentityManager[T UserProtocol[K], K comparable] struct {
	SessionManager      *scs.SessionManager
	LoginRedirectConfig LoginRedirectConfig
	// The function to load the user object from your preferred data store.
	// This function should take a uniquely-identifying string and return a
	// user object of the specified type.
	loadUser UserLoader[T, K]

	// The function to create an anonymous user object. This function should
	// return a user object of the specified type. If this function is nil,
	// the zero value of the user type will be used as the anonymous user.
	anonymousUser AnonymousUser[T, K]
}

// New creates a new LoginManager instance. The LoginManager
// requires a SessionManager instance, a login redirect URL, and a UserLoader
// function.
//
// This function handles registering the UserProtocol type with encoding/gob,
// which scs uses to encode and decode session data.
func New[T UserProtocol[K], K comparable](
	sm *scs.SessionManager,
	lc LoginRedirectConfig,
	loadUser UserLoader[T, K],
	anonymousUser AnonymousUser[T, K],
) *IdentityManager[T, K] {
	// Register the UserProtocol type with encoding/gob
	gob.Register(*new(T))

	return &IdentityManager[T, K]{
		SessionManager:      sm,
		LoginRedirectConfig: lc,
		loadUser:            loadUser,
		anonymousUser:       anonymousUser,
	}
}

// LoginUser logs in the user with the specified ID. The user object is
// loaded using the UserLoader function provided to the LoginManager.
//
// Call this function when you want to log in a user after they have
// successfully authenticated. This function will renew the session token
// to prevent session fixation attacks, and then attach the user object to
// the session.
func (im *IdentityManager[T, K]) LoginUser(r *http.Request, userID K) error {
	// Renew the session token to prevent session fixation attacks
	err := im.SessionManager.RenewToken(r.Context())
	if err != nil {
		return fmt.Errorf("failed to renew session token: %w", err)
	}

	user, err := im.loadUser(r.Context(), userID)
	if err != nil {
		return fmt.Errorf("failed to load user: %w", err)
	}

	im.SessionManager.Put(r.Context(), UserSessionKey, user)
	return nil
}

// LogoutUser logs out the current user. This function will remove the user
// object from the request context and destroy the session token.
func (im *IdentityManager[T, K]) LogoutUser(r *http.Request) error {
	err := im.SessionManager.Destroy(r.Context())
	if err != nil {
		return fmt.Errorf("failed to destroy session: %w", err)
	}

	return nil
}

func (im *IdentityManager[T, K]) getOrCreateSessionUser(r *http.Request) T {
	var anon T
	if im.anonymousUser != nil {
		anon = im.anonymousUser()
	}

	// Check if there even is a session
	if !im.SessionManager.Exists(r.Context(), UserSessionKey) {
		// If not, create an anonymous user
		im.SessionManager.Put(r.Context(), UserSessionKey, anon)
	}

	user, ok := im.SessionManager.Get(r.Context(), UserSessionKey).(T)
	if !ok {
		im.SessionManager.Put(r.Context(), UserSessionKey, anon)
		return anon
	}

	return user
}

// LoginRequired is a middleware function that checks if
// the request has an authenticated user attached to the context. If the user
// is not authenticated, the middleware will redirect the user to the login
// page.
//
// This middleware should be used after the LoadUser middleware.
func (im *IdentityManager[T, K]) LoginRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := im.AuthenticatedUser(r)
		if err != nil {
			// Set the ReturnTo key in the session to the current URL
			im.SessionManager.Put(r.Context(), "ReturnTo", r.URL.Path)

			im.LoginRedirectConfig.RedirectFunc(im.LoginRedirectConfig.LoginRedirectURL, w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// User returns the user object attached to the request context.
// This function should be used when you need to access the user object,
// but you don't need to check if the user is authenticated. It will return
// the zero value of the specified user type if there is no user object in
// the context.
func (im *IdentityManager[T, K]) User(r *http.Request) T {
	return im.getOrCreateSessionUser(r)
}

// AuthenticatedUser returns the authenticated user object attached to the
// request context. If the user is not authenticated, this function will return
// an error and an empty user object.
func (im *IdentityManager[T, K]) AuthenticatedUser(r *http.Request) (T, error) {
	user := im.User(r)
	if !user.IsAuthenticated() {
		return *new(T), ErrUserNotAuthenticated
	}
	return user, nil
}

// PopReturnTo returns the "ReturnTo" URL from the session and removes it from
// the session. If the "ReturnTo" key does not exist in the session, this function
// will return the root URL ("/").
//
// This should be used in your login handler to redirect the user back to the
// page they were trying to access before they were redirected to the login page.
func (im *IdentityManager[T, K]) PopReturnTo(r *http.Request) string {
	s := im.SessionManager.PopString(r.Context(), ReturnToKey)
	if s == "" {
		return "/"
	}
	return s
}
