package bcrypt

import "golang.org/x/crypto/bcrypt"

var (
	Cost int = bcrypt.DefaultCost
)

func Default() {
	Cost = bcrypt.DefaultCost
}

func Hash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), Cost)

	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func Verify(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))

	return err == nil
}
