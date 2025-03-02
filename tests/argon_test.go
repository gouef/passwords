package tests

import (
	"github.com/gouef/passwords/argon"
	"github.com/stretchr/testify/assert"
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
}
