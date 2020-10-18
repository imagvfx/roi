// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build ignore

// Based on `go env GOROOT`/src/crypto/tls/generate_cert.go

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	if _, err := os.Stat("cert/cert.pem"); err == nil || !errors.Is(err, os.ErrNotExist) {
		log.Fatalf("cert/cert.pem is already exists; please remove it manually")
	}
	if _, err := os.Stat("cert/key.pem"); err == nil || !errors.Is(err, os.ErrNotExist) {
		log.Fatalf("cert/key.pem is already exists; please remove it manually")
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %v", err)
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"ImagVFX Co"},
		},
		NotBefore: now,
		NotAfter:  now.Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    []string{"localhost"},
	}

	nBits := 2048
	priv, err := rsa.GenerateKey(rand.Reader, nBits)
	if err != nil {
		log.Fatalf("failed to generate private key: %v", err)
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("failed to create certificate: %v", err)
	}

	certOut, err := os.Create("cert/cert.pem")
	if err != nil {
		log.Fatalf("failed to create cert/cert.pem: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("failed to write date to cert/cert.pem: %v", err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("error closing cert/cert.pem: %v", err)
	}
	log.Print("wrote cert/cert.pem")

	keyOut, err := os.OpenFile("cert/key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("failed to create cert/key.pem: %v", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		log.Fatalf("unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		log.Fatalf("failed to write data to cert/key.pem: %v", err)
	}
	if err := keyOut.Close(); err != nil {
		log.Fatalf("error closing cert/key.pem: %v", err)
	}
	log.Print("wrote cert/key.pem")
}
