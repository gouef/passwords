package argon

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
	"strconv"
	"strings"
)

// Argon alias for Argon2id
var (
	Time    uint32 = 3
	Memory  uint32 = 64 * 1024
	Threads uint8  = 4
	KeyLen  uint32 = 16
	SaltLen uint32 = 32
)

func Default() {
	Time = 3
	Memory = 64 * 1024
	Threads = 4
	KeyLen = 16
	SaltLen = 32
}

func Hash(password string) (string, error) {
	salt := make([]byte, SaltLen)

	hash := argon2.IDKey([]byte(password), salt, Time, Memory, Threads, KeyLen)

	encodedHash := fmt.Sprintf("%d$%d$%d$%d$%s$%s",
		Time, Memory, Threads, KeyLen,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	return encodedHash, nil
}

func Verify(password, hash string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		return false
	}

	time, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}
	memory, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	threads, err := strconv.Atoi(parts[2])
	if err != nil {
		return false
	}
	keyLen, err := strconv.Atoi(parts[3])
	if err != nil {
		return false
	}

	salt, _ := base64.RawStdEncoding.DecodeString(parts[4])
	storedHash, _ := base64.RawStdEncoding.DecodeString(parts[5])

	computedHash := argon2.IDKey([]byte(password), salt, uint32(time), uint32(memory), uint8(threads), uint32(keyLen))

	return bytes.Equal(storedHash, computedHash)
}
