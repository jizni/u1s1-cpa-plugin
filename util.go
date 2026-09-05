package main

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"
)

func nowUnix() int64 { return time.Now().Unix() }

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	// RFC 4122 v4 formatting for readability; the CLI strips dashes anyway.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b[0:4]) + "-" + hex.EncodeToString(b[4:6]) + "-" +
		hex.EncodeToString(b[6:8]) + "-" + hex.EncodeToString(b[8:10]) + "-" + hex.EncodeToString(b[10:16])
}

// isTruthyQuery reads a boolean management query parameter. Management routes
// are called both by the panel (which always sends "1") and by hand with curl,
// where "true" is the natural thing to type; accepting both keeps a mistyped
// flag from silently meaning "off".
func isTruthyQuery(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
