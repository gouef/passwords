package tests

import (
	"github.com/gouef/passwords"
	"github.com/gouef/passwords/bcrypt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPasswords(t *testing.T) {
	t.Run("Simple", func(t *testing.T) {
		hash, err := passwords.Hash("1234")
		assert.NoError(t, err)
		assert.NotNil(t, hash)

		assert.True(t, passwords.Verify("1234", hash))
		assert.False(t, passwords.Verify("4231", hash))
	})

	t.Run("Simple Use", func(t *testing.T) {
		passwords.Use(passwords.BCRYPT)
		bcrypt.Cost = 12
		hash, err := passwords.Hash("1234")
		assert.NoError(t, err)
		assert.NotNil(t, hash)

		assert.Equal(t, 12, bcrypt.Cost)
		assert.True(t, passwords.Verify("1234", hash))
		assert.False(t, passwords.Verify("4231", hash))

		passwords.Default()
		assert.True(t, passwords.Verify("1234", hash))

	})

	t.Run("change default", func(t *testing.T) {
		passwords.Use(passwords.ARGON)
		bcrypt.Cost = 12
		hash, err := passwords.Hash("1234")
		assert.NoError(t, err)
		assert.NotNil(t, hash)

		assert.Equal(t, 12, bcrypt.Cost)
		assert.True(t, passwords.Verify("1234", hash))
		assert.False(t, passwords.Verify("4231", hash))

		passwords.Default()
		assert.True(t, passwords.Verify("1234", hash))

	})
}
