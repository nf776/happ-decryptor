package happ

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"regexp"
)

type Processor struct {
	privateKeys map[string]*rsa.PrivateKey
	publicKeys  map[string]*rsa.PublicKey
}

type Result struct {
	Version       string
	UsedKey       string
	EncryptedData string
	DecryptedData string
	Link          string
}

func New(privateKeyPaths map[string]string, publicKeyPaths map[string]string) (*Processor, error) {
	p := &Processor{
		privateKeys: make(map[string]*rsa.PrivateKey),
		publicKeys:  make(map[string]*rsa.PublicKey),
	}

	for version, path := range privateKeyPaths {
		if err := p.loadKey(path, version, "private"); err != nil {
			return nil, err
		}
	}

	for version, path := range publicKeyPaths {
		if err := p.loadKey(path, version, "public"); err != nil {
			return nil, err
		}
	}

	return p, nil
}

func (p *Processor) loadKey(path, version, keyType string) error {
	if path == "" {
		return errors.New(ErrEmptyPath)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return errors.New(ErrFileRead)
	}

	if len(data) == 0 {
		return errors.New(ErrFileEmpty)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return errors.New(ErrPEMDecode)
	}

	if keyType == "private" {
		priv, err := parsePrivateKey(block)
		if err != nil {
			return errors.New(ErrPrivateKeyParse)
		}
		if priv == nil {
			return errors.New(ErrPrivateKeyNil)
		}
		p.privateKeys[version] = priv
	} else {
		pub, err := parsePublicKey(block)
		if err != nil {
			return errors.New(ErrPublicKeyParse)
		}
		if pub == nil {
			return errors.New(ErrPublicKeyNil)
		}
		p.publicKeys[version] = pub
	}
	return nil
}

func (p *Processor) Decrypt(link string) (Result, error) {
	if link == "" {
		return Result{}, errors.New(ErrDecryptEmptyLink)
	}

	version, encryptedData, err := parseLink(link)
	if err != nil {
		return Result{}, err
	}

	keysToTry := []string{version, "crypt", "crypt2", "crypt3"}

	for _, keyVersion := range keysToTry {
		priv, exists := p.privateKeys[keyVersion]
		if !exists || priv == nil {
			continue
		}

		decrypted, err := decryptData(encryptedData, priv)
		if err == nil {
			return Result{
				Version:       version,
				UsedKey:       keyVersion,
				DecryptedData: decrypted,
			}, nil
		} else {
			continue
		}
	}

	return Result{}, errors.New(ErrDecryptBadData)
}

func (p *Processor) Encrypt(data, version string) (Result, error) {
	if data == "" {
		return Result{}, errors.New(ErrEmptyData)
	}

	if version == "" {
		return Result{}, errors.New(ErrEmptyVersion)
	}

	pub, exists := p.publicKeys[version]
	if !exists {
		return Result{}, fmt.Errorf(ErrWrongVersion, version)
	}

	if pub == nil {
		return Result{}, fmt.Errorf(ErrWrongKeyForVersion, version)
	}

	encrypted, err := encryptData(data, pub)
	if err != nil {
		return Result{}, err
	}

	return Result{
		Version:       version,
		EncryptedData: encrypted,
		Link:          fmt.Sprintf("happ://%s/%s", version, encrypted),
	}, nil
}

func parsePrivateKey(block *pem.Block) (*rsa.PrivateKey, error) {
	if block == nil {
		return nil, errors.New(ErrPEMNil)
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return priv, nil
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New(ErrPrivateKeyParse)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New(ErrPrivateKeyNotRSA)
	}

	return rsaKey, nil
}

func parsePublicKey(block *pem.Block) (*rsa.PublicKey, error) {
	if block == nil {
		return nil, errors.New(ErrPEMNil)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New(ErrPublicKeyNil)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New(ErrPublicKeyNotRSA)
	}

	return rsaPub, nil
}

func parseLink(link string) (string, string, error) {
	if link == "" {
		return "", "", errors.New(ErrDecryptEmptyLink)
	}

	re := regexp.MustCompile(`happ://(crypt|crypt2|crypt3)/(.+)`)
	matches := re.FindStringSubmatch(link)
	if matches == nil {
		return "", "", errors.New(ErrInvalidLinkFormat)
	}
	return matches[1], matches[2], nil
}

func decryptData(encryptedB64 string, privateKey *rsa.PrivateKey) (string, error) {
	if encryptedB64 == "" {
		return "", errors.New(ErrEncryptedDataIsEmpty)
	}

	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedB64)
	if err != nil {
		return "", fmt.Errorf(ErrB64Decode, err)
	}

	decryptedBytes, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedBytes)
	if err != nil {
		return "", fmt.Errorf(ErrRSADecode, err)
	}

	return string(decryptedBytes), nil
}

func encryptData(data string, publicKey *rsa.PublicKey) (string, error) {
	dataBytes := []byte(data)
	maxSize := (publicKey.N.BitLen() / 8) - 11
	if len(dataBytes) > maxSize {
		return "", errors.New(ErrLargeData)
	}

	encryptedBytes, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, dataBytes)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(encryptedBytes), nil
}
