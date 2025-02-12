package passwords

type Passwords struct {
	Algo    string
	Options []string
}

func (p *Passwords) Hash(password string) (string, error) {

}

func (p *Passwords) Verify(password, hash string) bool {

}
