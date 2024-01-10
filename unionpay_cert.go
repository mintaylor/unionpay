package unionpay

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"software.sslmate.com/src/go-pkcs12"
)

// hashMessage hash message twice.
func hashMessage(m map[string]string) []byte {
	str := SortUnionMap(m)
	firstHash := sha256.Sum256([]byte(str))
	secondHash := sha256.Sum256([]byte(fmt.Sprintf("%x", firstHash)))
	return secondHash[:]
}

// SignMapWithPrivate sign with privateKey.
func SignMapWithPrivate(m map[string]string, private *rsa.PrivateKey) (string, error) {
	hashed := hashMessage(m)
	sign, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, hashed)
	if err != nil {
		return "", fmt.Errorf("error signing data: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sign), nil
}

// SignVerify verify the signature.
func SignVerify(m map[string]string) error {
	sign, ok := m["signature"]
	if !ok {
		return errors.New("signature not found in params")
	}

	signPubKeyCert, ok := m["signPubKeyCert"]
	if !ok {
		return errors.New("signPubKeyCert not found in params")
	}

	hashed := hashMessage(m)

	signBytes, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return fmt.Errorf("error decoding signature: %v", err)
	}

	block, _ := pem.Decode([]byte(signPubKeyCert))
	if block == nil {
		return errors.New("error decoding public key certificate")
	}

	publicCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing certificate: %v", err)
	}

	publicKey, ok := publicCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("error asserting type: publicKey is not of type *rsa.PublicKey")
	}

	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed, signBytes); err != nil {
		return fmt.Errorf("signature verification failed: %v", err)
	}

	return nil
}

// ParserPfxToCert parse pfx file to private key and certificate.
func ParserPfxToCert(path string, password string) (*rsa.PrivateKey, *x509.Certificate, error) {
	pfxData, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read pfx file: %v", err)
	}

	priv, cert, _, err := pkcs12.DecodeChain(pfxData, password)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding pfx data: %v", err)
	}

	private, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("decoded key is not RSA private key")
	}

	return private, cert, nil
}
