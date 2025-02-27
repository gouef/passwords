package passwords

type Passwords struct {
	Algo    Algo
	Options map[string]any
}

func NewPassword(algoType AlgoType, options map[string]any) *Passwords {
	algo := algoType.New(options)
	return &Passwords{Algo: algo}
}

func (p *Passwords) Hash(password string) (string, error) {

}

func (p *Passwords) Verify(password, hash string) bool {

}
