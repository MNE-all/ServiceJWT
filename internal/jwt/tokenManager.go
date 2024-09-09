package jwt

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"log/slog"
	"time"
)

type JWT struct {
	Access_token  string `json:"access_token"`
	Refresh_token string `json:"refresh_token"`
}

var mySigningKey = []byte("mySecureSigningKey")

func GetTokenPair(uuid uuid.UUID, ip string) JWT {

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": uuid,                                    // Subject (user identifier)
		"iss": "ServiceJWT",                            // Issuer
		"exp": time.Now().Add(time.Minute * 15).Unix(), // Expiration time 15 minutes
		"iat": time.Now().Unix(),                       // Issued at
	})

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": uuid,                                        // Subject (user identifier)
		"iss": "ServiceJWT",                                // Issuer
		"exp": time.Now().Add(time.Hour * 24 * 180).Unix(), // Expiration time 180 days
		"iat": time.Now().Unix(),                           // Issuer
		"aud": ip,                                          // Audience (user role)
	})

	stringToken, err := token.SignedString(mySigningKey)
	if err != nil {
		slog.Warn(err.Error())
	}
	stringRefreshToken, err := refreshToken.SignedString(mySigningKey)
	if err != nil {
		slog.Warn(err.Error())
	}
	return JWT{stringToken, stringRefreshToken}
}

// Function to verify JWT tokens
func VerifyToken(tokenString string) (*jwt.Token, error) {
	// Parse the token with the secret key

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return mySigningKey, nil
	})

	// Check for verification errors
	if err != nil {
		return nil, err
	}

	// Check if the token is valid
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Return the verified token
	return token, nil
}
