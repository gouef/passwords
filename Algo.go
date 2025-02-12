package passwords

import "golang.org/x/crypto/bcrypt"

type Algo interface {
	Hash(password string) (string, error)
	Verify(password, hash string) bool
}

type AlgoType string

const (
	BCRYPT AlgoType = "Bcrypt"
)

func (a AlgoType) New() *Algo {
	switch a {
	case BCRYPT:
		return &Bcrypt{Cost: bcrypt.DefaultCost}
	}
}

type Bcrypt struct {
	Cost int
}

func NewBcrypt() *Bcrypt {
	return &Bcrypt{Cost: bcrypt.DefaultCost}
}

func (p *Bcrypt) Hash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), p.Cost)

	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func (p *Bcrypt) Verify(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))

	return err == nil
}
