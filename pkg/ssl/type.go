package ssl

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func (c *CertMagicClient) convertCertToPEM(cert tls.Certificate) (string, string, error) {

	var certPEM bytes.Buffer
	for _, der := range cert.Certificate {
		block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
		if err := pem.Encode(&certPEM, block); err != nil {
			return "", "", fmt.Errorf("证书 PEM 编码失败: %v", err)
		}
	}

	var keyPEM bytes.Buffer
	switch key := cert.PrivateKey.(type) {
	case *rsa.PrivateKey:
		block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
		if err := pem.Encode(&keyPEM, block); err != nil {
			return "", "", fmt.Errorf("RSA 私钥 PEM 编码失败: %v", err)
		}
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return "", "", fmt.Errorf("ECDSA 私钥编码失败: %v", err)
		}
		block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
		if err := pem.Encode(&keyPEM, block); err != nil {
			return "", "", fmt.Errorf("ECDSA 私钥 PEM 编码失败: %v", err)
		}
	default:
		return "", "", fmt.Errorf("未知的私钥类型: %T", cert.PrivateKey)
	}

	return certPEM.String(), keyPEM.String(), nil
}
