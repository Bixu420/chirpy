package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeAndValidateJWT_Success(t *testing.T) {
	userID := uuid.New()
	secret := "my-secret"

	tokenString, err := MakeJWT(userID, secret, time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT returned unexpected error: %v", err)
	}
	if tokenString == "" {
		t.Fatal("MakeJWT returned an empty token string")
	}

	gotID, err := ValidateJWT(tokenString, secret)
	if err != nil {
		t.Fatalf("ValidateJWT returned unexpected error: %v", err)
	}
	if gotID != userID {
		t.Errorf("ValidateJWT returned userID %v, want %v", gotID, userID)
	}
}

func TestValidateJWT_WrongSecret(t *testing.T) {
	userID := uuid.New()

	tokenString, err := MakeJWT(userID, "correct-secret", time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT returned unexpected error: %v", err)
	}

	_, err = ValidateJWT(tokenString, "wrong-secret")
	if err == nil {
		t.Fatal("expected an error when validating with the wrong secret, got nil")
	}
}

func TestValidateJWT_ExpiredToken(t *testing.T) {
	userID := uuid.New()
	secret := "my-secret"

	// Token that expired in the past.
	tokenString, err := MakeJWT(userID, secret, -time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT returned unexpected error: %v", err)
	}

	_, err = ValidateJWT(tokenString, secret)
	if err == nil {
		t.Fatal("expected an error when validating an expired token, got nil")
	}
}

func TestValidateJWT_MalformedToken(t *testing.T) {
	secret := "my-secret"

	_, err := ValidateJWT("this.is.not-a-valid-jwt", secret)
	if err == nil {
		t.Fatal("expected an error when validating a malformed token, got nil")
	}
}

func TestValidateJWT_EmptyToken(t *testing.T) {
	secret := "my-secret"

	_, err := ValidateJWT("", secret)
	if err == nil {
		t.Fatal("expected an error when validating an empty token, got nil")
	}
}

func TestMakeJWT_DifferentUsersProduceDifferentSubjects(t *testing.T) {
	secret := "my-secret"
	user1 := uuid.New()
	user2 := uuid.New()

	token1, err := MakeJWT(user1, secret, time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT returned unexpected error: %v", err)
	}
	token2, err := MakeJWT(user2, secret, time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT returned unexpected error: %v", err)
	}

	gotID1, err := ValidateJWT(token1, secret)
	if err != nil {
		t.Fatalf("ValidateJWT returned unexpected error: %v", err)
	}
	gotID2, err := ValidateJWT(token2, secret)
	if err != nil {
		t.Fatalf("ValidateJWT returned unexpected error: %v", err)
	}

	if gotID1 != user1 {
		t.Errorf("ValidateJWT returned userID %v, want %v", gotID1, user1)
	}
	if gotID2 != user2 {
		t.Errorf("ValidateJWT returned userID %v, want %v", gotID2, user2)
	}
	if gotID1 == gotID2 {
		t.Error("expected different user IDs from different tokens, got the same")
	}
}
