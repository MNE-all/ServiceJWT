package jwt

import (
	"fmt"
	"net/http"
	"strings"
)

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Our middleware logic goes here...
		// Retrieve the token from the cookie
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			w.WriteHeader(400)
			w.Write([]byte("Bad request"))
			//fmt.Fprintln(w, "Token missing in cookie")
			return
		}

		tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
		// Verify the token
		token, err := VerifyToken(tokenString)
		if err != nil {
			w.WriteHeader(401)
			w.Write([]byte(fmt.Sprintf("Token verification failed: %v\\n", err)))
			return
		}

		// Print information about the verified token
		fmt.Printf("Token verified successfully. Claims: %+v\\n", token.Claims)

		// Continue with the next middleware or route handler
		next.ServeHTTP(w, r)
	})
}
