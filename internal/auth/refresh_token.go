package auth

import (
	"crypto/rand"
	"encoding/hex"
)

func MakeRefreshToken() string {
	s := make([]byte, 32)
	rand.Read(s)
	return hex.EncodeToString(s)
}
