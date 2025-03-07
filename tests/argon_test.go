package tests

import (
	"encoding/base64"
	"fmt"
	"github.com/gouef/passwords/argon"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/argon2"
	"testing"
)

func TestArgon(t *testing.T) {

	t.Run("Simple", func(t *testing.T) {
		hash, err := argon.Hash("1234")
		assert.NoError(t, err)
		assert.NotNil(t, hash)

		assert.True(t, argon.Verify("1234", hash))
		assert.False(t, argon.Verify("4231", hash))
	})

	t.Run("Simple Modify var", func(t *testing.T) {
		argon.KeyLen = 32
		hash, err := argon.Hash("1234")
		assert.NoError(t, err)
		assert.NotNil(t, hash)

		assert.Equal(t, uint32(32), argon.KeyLen)
		assert.True(t, argon.Verify("1234", hash))
		assert.False(t, argon.Verify("4231", hash))

		argon.Default()
		assert.True(t, argon.Verify("1234", hash))

	})
	t.Run("Hash error", func(t *testing.T) {
		password := "1234"
		salt := make([]byte, argon.SaltLen)

		hash := argon2.IDKey([]byte(password), salt, argon.Time, argon.Memory, argon.Threads, argon.KeyLen)

		encodedHash := fmt.Sprintf("%d$%d$%d$%d$%s",
			argon.Time, argon.Memory, argon.Threads, argon.KeyLen,
			base64.RawStdEncoding.EncodeToString(hash),
		)
		assert.False(t, argon.Verify(password, encodedHash))

	})
	t.Run("Hash error Time", func(t *testing.T) {
		password := "1234"
		salt := make([]byte, argon.SaltLen)

		hash := argon2.IDKey([]byte(password), salt, argon.Time, argon.Memory, argon.Threads, argon.KeyLen)

		encodedHash := fmt.Sprintf("%s$%d$%d$%d$%s$%s",
			"fda", argon.Memory, argon.Threads, argon.KeyLen,
			base64.RawStdEncoding.EncodeToString(salt),
			base64.RawStdEncoding.EncodeToString(hash),
		)
		assert.False(t, argon.Verify(password, encodedHash))

	})
	t.Run("Hash error memory", func(t *testing.T) {
		password := "1234"
		salt := make([]byte, argon.SaltLen)

		hash := argon2.IDKey([]byte(password), salt, argon.Time, argon.Memory, argon.Threads, argon.KeyLen)

		encodedHash := fmt.Sprintf("%d$%s$%d$%d$%s$%s",
			argon.Time, "memory", argon.Threads, argon.KeyLen,
			base64.RawStdEncoding.EncodeToString(salt),
			base64.RawStdEncoding.EncodeToString(hash),
		)
		assert.False(t, argon.Verify(password, encodedHash))

	})
	t.Run("Hash error threads", func(t *testing.T) {
		password := "1234"
		salt := make([]byte, argon.SaltLen)

		hash := argon2.IDKey([]byte(password), salt, argon.Time, argon.Memory, argon.Threads, argon.KeyLen)

		encodedHash := fmt.Sprintf("%d$%d$%s$%d$%s$%s",
			argon.Time, argon.Memory, "argon.Threads", argon.KeyLen,
			base64.RawStdEncoding.EncodeToString(salt),
			base64.RawStdEncoding.EncodeToString(hash),
		)
		assert.False(t, argon.Verify(password, encodedHash))

	})
	t.Run("Hash error keylen", func(t *testing.T) {
		password := "1234"
		salt := make([]byte, argon.SaltLen)

		hash := argon2.IDKey([]byte(password), salt, argon.Time, argon.Memory, argon.Threads, argon.KeyLen)

		encodedHash := fmt.Sprintf("%d$%d$%d$%s$%s$%s",
			argon.Time, argon.Memory, argon.Threads, "argon.KeyLen",
			base64.RawStdEncoding.EncodeToString(salt),
			base64.RawStdEncoding.EncodeToString(hash),
		)
		assert.False(t, argon.Verify(password, encodedHash))

	})
	t.Run("Hash error salt", func(t *testing.T) {
		password := "1234"
		salt := make([]byte, argon.SaltLen)

		hash := argon2.IDKey([]byte(password), salt, argon.Time, argon.Memory, argon.Threads, argon.KeyLen)

		encodedHash := fmt.Sprintf("%d$%d$%d$%d$%d$%s",
			argon.Time, argon.Memory, argon.Threads, argon.KeyLen,
			45,
			base64.RawStdEncoding.EncodeToString(hash),
		)
		assert.False(t, argon.Verify(password, encodedHash))

	})
	t.Run("Hash error hash type", func(t *testing.T) {
		password := "1234"
		salt := make([]byte, argon.SaltLen)

		encodedHash := fmt.Sprintf("%d$%d$%d$%d$%s$%d",
			argon.Time, argon.Memory, argon.Threads, argon.KeyLen,
			base64.RawStdEncoding.EncodeToString(salt),
			1234,
		)
		assert.False(t, argon.Verify(password, encodedHash))

	})

	t.Run("Hash error decode salt", func(t *testing.T) {
		password := "1234"
		salt := make([]byte, argon.SaltLen)
		salt2 := make([]byte, argon.SaltLen+1)

		hash := argon2.IDKey([]byte(password), salt, argon.Time, argon.Memory, argon.Threads, argon.KeyLen)

		encodedHash := fmt.Sprintf("%d$%d$%d$%d$%s$%s",
			argon.Time, argon.Memory, argon.Threads, argon.KeyLen,
			base64.RawStdEncoding.EncodeToString(salt2),
			base64.RawStdEncoding.EncodeToString(hash),
		)
		assert.False(t, argon.Verify(password, encodedHash))

	})

	t.Run("Hash error decode hash", func(t *testing.T) {
		password := "1234"
		salt := make([]byte, argon.SaltLen)
		salt2 := make([]byte, argon.SaltLen+1)

		hash := argon2.IDKey([]byte(password), salt2, argon.Time, argon.Memory, argon.Threads, argon.KeyLen)

		encodedHash := fmt.Sprintf("%d$%d$%d$%d$%s$%s",
			argon.Time, argon.Memory, argon.Threads, argon.KeyLen,
			base64.RawStdEncoding.EncodeToString(salt),
			base64.RawStdEncoding.EncodeToString(hash),
		)
		assert.False(t, argon.Verify(password, encodedHash))

	})
}
