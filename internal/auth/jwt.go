package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy-access",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
		Subject:   userID.String(),
	})
	signed, err := token.SignedString([]byte(tokenSecret))
	return signed, err
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	claimsStruct := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &claimsStruct, func(token *jwt.Token) (any, error) {
		return []byte(tokenSecret), nil
	})
	if err != nil {
		fmt.Errorf("Problem with validation: %v", err)
		return uuid.UUID{}, fmt.Errorf("problem with validation: %v", err)
	} else if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok {
		return uuid.Parse(claims.Subject)
	} else {
		fmt.Errorf("unknown claims type, cannot proceed")

	}
	return uuid.UUID{}, nil
}
func GetBearerToken(headers http.Header) (string, error) {
	text := headers.Get("Authorization")
	token := strings.TrimPrefix(text, "Bearer ")
	return token, nil
}
