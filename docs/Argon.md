# `argon` Package

## Overview
The `argon` package implements password hashing using Argon2id.

## Configuration
Configuration variables:

```go
var (
    Time    uint32 = 3        // Number of iterations
    Memory  uint32 = 64 * 1024 // Memory size (KB)
    Threads uint8  = 4        // Number of threads
    KeyLen  uint32 = 16       // Key length
    SaltLen uint32 = 32       // Salt length
)
```

### Reset to Default Configuration
```go
argon.Default()
```

### Hashing a Password
```go
hash, err := argon.Hash("mypassword")
```

### Verifying a Password
```go
isValid := argon.Verify("mypassword", hash)
```