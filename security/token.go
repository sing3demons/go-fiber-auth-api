package security

import (
	"fmt"
	"os"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/sing3demons/go-fiber-auth-api/util"
)

var (
	JwtSecretKey     = []byte(os.Getenv("JWT_SECRET_KEY"))
	JwtSigningMethod = jwt.SigningMethodHS256.Name
)

func NewToken(userId string) (string, error) {
	claims := jwt.RegisteredClaims{
		ID:        userId,
		Subject:   userId,
		Issuer:    userId,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 30)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(JwtSecretKey)
}

func validateSignedMethod(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return JwtSecretKey, nil
}

func ParseToken(tokenString string) (*jwt.RegisteredClaims, error) {
	claims := new(jwt.RegisteredClaims)
	// token, err := jwt.Parse(tokenString, validateSignedMethod)

	token, err := jwt.ParseWithClaims(tokenString, claims, validateSignedMethod)
	if err != nil {
		return nil, err
	}

	
	var ok bool
	claims, ok = token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		return nil, util.ErrInvalidAuthToken
	}
	return claims, nil
}
