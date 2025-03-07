module github.com/gouef/passwords

go 1.23.7

require (
	github.com/stretchr/testify v1.10.0
	golang.org/x/crypto v0.36.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/gouef/passwords/argon => ./argon
	github.com/gouef/passwords/bcrypt => ./bcrypt
)
