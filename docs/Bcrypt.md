# `bcrypt` Package

## Overview
The `bcrypt` package provides functions for hashing passwords using bcrypt.

## Configuration
```go
var (
    Cost int = bcrypt.DefaultCost // Hashing cost factor
)
```

### Reset to Default Configuration
```go
bcrypt.Default()
```

### Hashing a Password
```go
hash, err := bcrypt.Hash("mypassword")
```

### Verifying a Password
```go
isValid := bcrypt.Verify("mypassword", hash)
```

