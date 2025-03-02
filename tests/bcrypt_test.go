package tests

import (
	"github.com/gouef/passwords/bcrypt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBcrypt(t *testing.T) {
	t.Run("Simple", func(t *testing.T) {
		hash, err := bcrypt.Hash("1234")
		assert.NoError(t, err)
		assert.NotNil(t, hash)

		assert.True(t, bcrypt.Verify("1234", hash))
		assert.False(t, bcrypt.Verify("4231", hash))
	})

	t.Run("Simple Modify var", func(t *testing.T) {
		bcrypt.Cost = 12
		hash, err := bcrypt.Hash("1234")
		assert.NoError(t, err)
		assert.NotNil(t, hash)

		assert.Equal(t, 12, bcrypt.Cost)
		assert.True(t, bcrypt.Verify("1234", hash))
		assert.False(t, bcrypt.Verify("4231", hash))

		bcrypt.Default()
		assert.True(t, bcrypt.Verify("1234", hash))

	})

	t.Run("Simple Cost outside range", func(t *testing.T) {
		bcrypt.Cost = 32
		hash, err := bcrypt.Hash("1234")
		assert.Error(t, err)
		assert.Equal(t, "", hash)
	})
}
