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
	"io/ioutil"

	"software.sslmate.com/src/go-pkcs12"
)

// Sign sign with privateKey.
func Sign(params map[string]string, private *rsa.PrivateKey) (string, error) {
	str := SortUnionMap(params)
	hashed := sha256.Sum256([]byte(fmt.Sprintf("%x", sha256.Sum256([]byte(str)))))
	sign, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sign), nil
}

// SignVerify verify the signature.
func SignVerify(params map[string]string) (bool, error) {
	sign := params["signature"]
	str := SortUnionMap(params)
	hashed := sha256.Sum256([]byte(fmt.Sprintf("%x", sha256.Sum256([]byte(str)))))
	signBytes, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return false, fmt.Errorf("signature base64 decode error: %v", err)
	}

	block, _ := pem.Decode([]byte(params["signPubKeyCert"]))
	if block == nil {
		return false, errors.New("public key error")
	}

	pubilcCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}

	err = rsa.VerifyPKCS1v15(pubilcCert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hashed[:], signBytes)
	if err != nil {
		return false, fmt.Errorf("sign verify failed: %v", err)
	}
	return true, nil
}

// ParserPfxToCert 根据银联获取到的PFX文件和密码来解析出里面包含的私钥(rsa)和证书(x509)
func ParserPfxToCert(path string, password string) (private *rsa.PrivateKey, cert *x509.Certificate, err error) {
	var pfxData []byte
	pfxData, err = ioutil.ReadFile(path)
	if err != nil {
		return
	}

	priv, cert, _, err := pkcs12.DecodeChain(pfxData, password)
	if err != nil {
		return
	}

	private = priv.(*rsa.PrivateKey)
	return
}

// ParseCertificateFromFile 根据文件名解析出证书
// openssl pkcs12 -in xxxx.pfx -clcerts -nokeys -out key.cert
func ParseCertificateFromFile(path string) (cert *x509.Certificate, err error) {
	// Read the verify sign certification key
	pemData, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}

	// Extract the PEM-encoded data block
	block, _ := pem.Decode(pemData)
	if block == nil {
		err = fmt.Errorf("bad key data: %s", "not PEM-encoded")
		return
	}
	if got, want := block.Type, "CERTIFICATE"; got != want {
		err = fmt.Errorf("unknown key type %q, want %q", got, want)
		return
	}

	// Decode the certification
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		err = fmt.Errorf("bad private key: %s", err)
		return
	}
	return
}
