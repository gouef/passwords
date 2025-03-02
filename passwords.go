package passwords

import (
	"github.com/gouef/passwords/argon"
	"github.com/gouef/passwords/bcrypt"
)

type AlgoType string

var (
	BCRYPT AlgoType = "Bcrypt"
	ARGON  AlgoType = "Argon"
)

var Algo AlgoType = ARGON

func Use(algo AlgoType) {
	Algo = algo
}

func Default() {
	if Algo == ARGON {
		argon.Default()
	} else if Algo == BCRYPT {
		bcrypt.Default()
	}
}

func Hash(password string) (string, error) {
	if Algo == BCRYPT {
		return bcrypt.Hash(password)
	}

	return argon.Hash(password)
}

func Verify(password, hash string) bool {
	if Algo == BCRYPT {
		return bcrypt.Verify(password, hash)
	}

	return argon.Verify(password, hash)
}
