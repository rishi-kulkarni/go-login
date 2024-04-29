package scslogin

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
)

type TestUser struct {
	ID    string
	Email string
}

func (u TestUser) IsAuthenticated() bool {
	return u.ID != ""
}

func (u TestUser) GetID() string {
	return u.ID
}

func loadUser(ctx context.Context, id string) (TestUser, error) {
	if id == "1" {
		return TestUser{ID: "1", Email: "user@example.com"}, nil
	}
	return TestUser{}, fmt.Errorf("user not found")
}

func newTestServer() *httptest.Server {
	sessionManager := scs.New()
	loginManager := New(sessionManager, DefaultLoginRedirectConfig("/login"), loadUser)

	r := chi.NewRouter()
	r.Use(sessionManager.LoadAndSave)

	// Public endpoint
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello, World!")
	})

	// Login endpoint
	r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Login page")
	})
	r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		err := loginManager.LoginUser(r, "1")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Get ReturnTo from session, which will just go to / if it doesn't exist
		http.Redirect(w, r, loginManager.PopReturnTo(r), http.StatusSeeOther)
	})

	// Guest session login endpoint
	r.Get("/guest", func(w http.ResponseWriter, r *http.Request) {
		err := loginManager.CreateGuestSession(r, TestUser{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, loginManager.PopReturnTo(r), http.StatusSeeOther)
	})

	// Misconfigured guest session login endpoint
	r.Get("/misconfigured-guest", func(w http.ResponseWriter, r *http.Request) {
		err := loginManager.CreateGuestSession(r, TestUser{ID: "1"})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, loginManager.PopReturnTo(r), http.StatusSeeOther)
	})

	// Logout endpoint
	r.Get("/logout", func(w http.ResponseWriter, r *http.Request) {
		err := loginManager.LogoutUser(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	// Protected endpoint
	r.With(loginManager.LoginRequired).Get("/protected", func(w http.ResponseWriter, r *http.Request) {
		user, _ := loginManager.AuthenticatedUser(r)
		fmt.Fprintf(w, "Hello, %s!", user.Email)
	})

	return httptest.NewServer(r)
}
func TestAnonymousEndpoint(t *testing.T) {
	server := newTestServer()
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	expected := "Hello, World!"
	if string(body) != expected {
		t.Errorf("expected body %q, got %q", expected, string(body))
	}

}

func TestAuthenticatedEndpoint(t *testing.T) {
	server := newTestServer()
	defer server.Close()

	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Prevent the client from following redirects
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", server.URL+"/protected", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("expected status code %d, got %d", http.StatusSeeOther, resp.StatusCode)
	}

	// Should have redirected to the login page
	if resp.Header.Get("Location") != "/login" {
		t.Errorf("expected redirect to %q, got %q", "/login", resp.Header.Get("Location"))
	}
}

func TestLogin(t *testing.T) {
	server := newTestServer()
	defer server.Close()

	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Prevent the client from following redirects
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("POST", server.URL+"/login", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("expected status code %d, got %d", http.StatusSeeOther, resp.StatusCode)
	}

	// Should have redirected to the protected page
	if resp.Header.Get("Location") != "/" {
		t.Errorf("expected redirect to %q, got %q", "/protected", resp.Header.Get("Location"))
	}
}

func TestGuestSession(t *testing.T) {
	server := newTestServer()
	defer server.Close()

	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Prevent the client from following redirects
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", server.URL+"/guest", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("expected status code %d, got %d", http.StatusSeeOther, resp.StatusCode)
	}

	// Should have redirected to the protected page
	if resp.Header.Get("Location") != "/" {
		t.Errorf("expected redirect to %q, got %q", "/protected", resp.Header.Get("Location"))
	}

	// Check that we got some cookies
	if len(resp.Cookies()) == 0 {
		t.Error("expected cookies in response")
	}
}

func TestMisconfiguredGuestSession(t *testing.T) {
	server := newTestServer()
	defer server.Close()

	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Prevent the client from following redirects
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", server.URL+"/misconfigured-guest", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Should have returned a 500 error
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status code %d, got %d", http.StatusInternalServerError, resp.StatusCode)
	}

	// No cookies should have been set
	if len(resp.Cookies()) != 0 {
		t.Error("expected no cookies in response")
	}
}

func TestAccessProtectedAfterLogin(t *testing.T) {
	server := newTestServer()
	defer server.Close()

	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Prevent the client from following redirects
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("POST", server.URL+"/login", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	req, err = http.NewRequest("GET", server.URL+"/protected", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Copy the cookies from the login response
	for _, cookie := range resp.Cookies() {
		req.AddCookie(cookie)
	}

	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	expected := "Hello, user@example.com!"
	if string(body) != expected {
		t.Errorf("expected body %q, got %q", expected, string(body))
	}
}

func TestLoseAccessToProtectedAfterLogout(t *testing.T) {
	server := newTestServer()
	defer server.Close()

	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Prevent the client from following redirects
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("POST", server.URL+"/login", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	req, err = http.NewRequest("GET", server.URL+"/protected", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Copy the cookies from the login response
	for _, cookie := range resp.Cookies() {
		req.AddCookie(cookie)
	}

	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	req, err = http.NewRequest("GET", server.URL+"/logout", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Copy the cookies from the protected response
	for _, cookie := range resp.Cookies() {
		req.AddCookie(cookie)
	}

	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	req, err = http.NewRequest("GET", server.URL+"/protected", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Copy the cookies from the logout response
	for _, cookie := range resp.Cookies() {
		req.AddCookie(cookie)
	}

	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("expected status code %d, got %d", http.StatusSeeOther, resp.StatusCode)
	}

	// Should have redirected to the login page
	if resp.Header.Get("Location") != "/login" {
		t.Errorf("expected redirect to %q, got %q", "/login", resp.Header.Get("Location"))
	}
}

func testServerWithCustomRedirectFunc() *httptest.Server {
	sessionManager := scs.New()
	loginManager := New(sessionManager, NewLoginRedirectConfig("/login", func(s string, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "custom")
		http.Redirect(w, r, s, http.StatusSeeOther)
	}), loadUser,
	)

	r := chi.NewRouter()
	r.Use(sessionManager.LoadAndSave)

	// Public endpoint
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello, World!")
	})

	// Login endpoint
	r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Login page")
	})
	r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		err := loginManager.LoginUser(r, "1")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/protected", http.StatusSeeOther)
	})

	// Logout endpoint
	r.Get("/logout", func(w http.ResponseWriter, r *http.Request) {
		err := loginManager.LogoutUser(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	// Protected endpoint
	r.With(loginManager.LoginRequired).Get("/protected", func(w http.ResponseWriter, r *http.Request) {
		user, _ := loginManager.AuthenticatedUser(r)
		fmt.Fprintf(w, "Hello, %s!", user.Email)
	})

	return httptest.NewServer(r)
}

func TestCustomRedirectFunc(t *testing.T) {
	server := testServerWithCustomRedirectFunc()
	defer server.Close()

	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Prevent the client from following redirects
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", server.URL+"/protected", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("expected status code %d, got %d", http.StatusSeeOther, resp.StatusCode)
	}

	// Should have redirected to the login page
	if resp.Header.Get("Location") != "/login" {
		t.Errorf("expected redirect to %q, got %q", "/login", resp.Header.Get("Location"))
	}

	// Should have set a custom header
	if resp.Header.Get("X-Custom-Header") != "custom" {
		t.Errorf("expected custom header %q, got %q", "custom", resp.Header.Get("X-Custom-Header"))
	}
}
