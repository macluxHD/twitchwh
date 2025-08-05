package twitchwh

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

func generateHmac(secret, message string) string {
	hash := hmac.New(sha256.New, []byte(secret))
	hash.Write([]byte(message))
	signature := hash.Sum(nil)
	return hex.EncodeToString(signature)
}

func verifyHmac(hmac1, hmac2 string) bool {
	return hmac.Equal([]byte(hmac1), []byte(hmac2))
}

func isMessageTooOld(timestamp string) bool {
	t, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return false
	}
	return time.Since(t) > 10*time.Minute
}
