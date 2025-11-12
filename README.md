# Happ Encryption/Decryption Module

A Go module for encrypting and decrypting Happ links using RSA encryption with PKCS1v15 padding.

## Features

 - 🔐 RSA encryption/decryption with PKCS1v15 padding
 - 🔗 All Happ link format support (`happ://crypt/...`, `happ://crypt2/...`, `happ://crypt3/...`)
 - 🗝️ Multiple key version support
 - 🛡️ Comprehensive error handling

## Installation

```bash
go get github.com/nf776/happ-decryptor@v1.0.0
```

## Usage

```go
package main

import (
    "fmt"
    "log"
    "github.com/nf776/happ-decryptor"
)

func main() {
    // Initialize keys
    privateKeys := map[string]string {
        "crypt":  "keys/private_crypt.pem",
        "crypt2": "keys/private_crypt2.pem",
        "crypt3": "keys/private_crypt3.pem",
    }

    publicKeys := map[string]string {
        "crypt":  "keys/public_crypt.pem",
        "crypt2": "keys/public_crypt2.pem",
        "crypt3": "keys/public_crypt3.pem",
    }

    // Initialize processor with key paths
    processor, err := happ.New(privateKeys, publicKeys)
    if err != nil {
        log.Fatal(err)
    }

    // Encrypt data
    result, err := processor.Encrypt("secret data", "crypt3")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Encrypted link: %s\n", result.Link)

    // Decrypt data
    decrypted, err := processor.Decrypt(result.Link)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Decrypted data: %s\n", decrypted.DecryptedData)
    fmt.Printf("Used key: %s\n", decrypted.UsedKey)
}
```

## Key Requirements
 - Private Keys: For decryption (keys from app)
 - Public Keys: For encryption (PKCS8 PEM format)
 - Key Versions: Support for crypt, crypt2, crypt3 versions

## Error Handling

The module provides comprehensive error handling with clear error messages:

```go
result, err := processor.Encrypt("data", "unknown")
if err != nil {
    switch err.Error() {
    case happ.ErrEmptyPath:
        // Handle missing path
    case happ.ErrPrivateKeyNotRSA:
        // Handle private key error
    // ... other cases
    }
}
```

## Smart Decryption

 - Automatically tries multiple key versions if the specified one fails
 - Fallback order: specified version → crypt → crypt2 → crypt3
 - Returns the actual key used for decryption
