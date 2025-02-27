package passwords

import (
	"golang.org/x/crypto/bcrypt"
	"strconv"
)

type Algo interface {
	Hash(password string) (string, error)
	Verify(password, hash string) bool
}

type AlgoType string

const (
	BCRYPT AlgoType = "Bcrypt"
)

func (a AlgoType) New(options map[string]any) Algo {
	switch a {
	case BCRYPT:
		c, exists := options["cost"]

		if exists {
			switch cost := c.(type) {
			case int:
				return &Bcrypt{Cost: cost}
			case string:
				cc, _ := strconv.Atoi(cost)
				return &Bcrypt{Cost: cc}
			}
		}
		return &Bcrypt{Cost: bcrypt.DefaultCost}
	default:
		return &Bcrypt{Cost: bcrypt.DefaultCost}
	}
}

type Bcrypt struct {
	Cost int
}

func NewBcrypt(cost int) *Bcrypt {
	if cost <= 0 {
		cost = bcrypt.DefaultCost
	}
	return &Bcrypt{Cost: cost}
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
