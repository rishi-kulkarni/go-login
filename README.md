# scs-login
This repository contains a small wrapper around alexedwards/scs that I've had to rewrite in several web apps. The wrapper is designed to manage user sessions with generic User structs, providing a simple and efficient way to handle user authentication and session management in your Go applications.

Inspired by flask-login, this wrapper also handles redirection to a login handler, login, and logout, making it a customizable helper for web applications that require user authentication.

## Features
* User session management with generic User structs
* Redirection to a login handler
* Login and logout functionality

## Installation
To install this package, you can use go get:

```bash
go get github.com/rishi-kulkarni/scs-login
```

## Usage
Here is a basic example of how to use this package:

```go
package main

import (
	"context"
	"net/http"

	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
	scslogin "github.com/rishi-kulkarni/scs-login"
)

// Define an implementation of the scslogin.UserProtocol interface.
type User struct {
	ID       int
	Username string
}

func (u User) IsAuthenticated() bool {
	return u.ID != 0
}

func (u User) GetID() int {
	return u.ID
}

// Define a UserLoader function that loads your User type from
// a database or some other source via a user ID. This function
// must have the signature func(context.Context, K) (T, error).
func loadUser(ctx context.Context, id int) (User, error) {
	// Load user from database
	if id == 1 {
		return User{ID: 1, Username: "test_user"}, nil
	}
	return User{}, nil
}

func main() {
	// Create a new scs session manager
	sessionManager := scs.New()

	// Create a new scslogin manager
	loginManager := scslogin.New(sessionManager, scslogin.DefaultLoginRedirectConfig("/login"), loadUser)

	// Create a new http router
	router := chi.NewRouter()
	router.Use(sessionManager.LoadAndSave)

	// Define a public handler
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("Hello, World!"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	// Define a login handler. Upon successful login, the user will be redirected using the ReturnTo URL
	// stored in the session, preventing open redirects.
	router.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// Get the user from the session
		_, err := loginManager.AuthenticatedUser(r)
		if err == nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		// Check if the request method is POST
		if r.Method == http.MethodPost {
			// Authenticate the user
			err = loginManager.LoginUser(r, 1)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// Get the returnTo URL from the session
			http.Redirect(w, r, loginManager.PopReturnTo(r), http.StatusFound)
			return
		}
		// Render the login form
		_, err = w.Write([]byte(`
		<!DOCTYPE html>
		<html>
		<head>
			<title>Login Page</title>
		</head>
		<body>
			<div>
				<form method="post">
					<input type="submit" value="Login">
				</form>
			</div>
		</body>
		</html>
		`))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	})

	// Define a logout handler, which will log the user out, destroy the session,
	// and redirect the user to the home page.
	router.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		// Logout the user
		err := loginManager.LogoutUser(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})

	// Define a protected handler using the loginManager.LoginRequired middleware. This will
	// redirect the user to the login page if they are not authenticated.
	router.With(loginManager.LoginRequired).HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		// An authenticated user can be retrieved using the loginManager.AuthenticatedUser function,
		// which will return an anonymous user and an error if the user is not authenticated.
		user, _ := loginManager.AuthenticatedUser(r)
		_, err := w.Write([]byte("Hello, " + user.Username))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	http.ListenAndServe(":8080", router)

}
```


Please refer to the `alexedwards/scs` documentation for more detailed information on session management and the storage backends that are available.

## License
This project is licensed under the MIT License - see the LICENSE file for details.