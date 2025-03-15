# Documentation for `passwords` package

## Overview
The `passwords` package provides functions for hashing and verifying passwords using the Argon2id and bcrypt algorithms. It allows switching between these algorithms using a global variable.

## Installation

```sh
 go get -u github.com/gouef/passwords
```

## Usage

### Argon
```go
package main

import (
    "fmt"
    "github.com/gouef/passwords"
)

func main() {
    passwords.Use(passwords.ARGON) // Use Argon2id
    hash, err := passwords.Hash("mypassword")
    if err != nil {
        fmt.Println("Error hashing password:", err)
        return
    }

    fmt.Println("Hash:", hash)
    
    isValid := passwords.Verify("mypassword", hash)
    fmt.Println("Verification:", isValid)
}
```


### Bcrypt
```go
package main

import (
    "fmt"
    "github.com/gouef/passwords"
)

func main() {
    passwords.Use(passwords.BCRYPT) // Use Bcrypt
    hash, err := passwords.Hash("mypassword")
    if err != nil {
        fmt.Println("Error hashing password:", err)
        return
    }

    fmt.Println("Hash:", hash)
    
    isValid := passwords.Verify("mypassword", hash)
    fmt.Println("Verification:", isValid)
}
```

## Next
You can use [Bcrypt](./Bcrypt.md) and [Argon](./Argon.md) its self.