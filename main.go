package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/int128/irsa-setup/pkg/keypair"
	"github.com/int128/irsa-setup/pkg/oidc"
)

const (
	baseDirName        = "irsa"
	jwksFilename       = "jwks.json"
	discoveryFilename  = "discovery.json"
	publicKeyFilename  = "signer.pub"
	privateKeyFilename = "signer.key"
)

func run() error {
	log.Printf("generating a key pair")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("cannot generate a key pair: %w", err)
	}

	if err := os.MkdirAll(baseDirName, 0700); err != nil {
		return fmt.Errorf("cannot create directory: %w", err)
	}
	log.Printf("created directory %s", baseDirName)

	jwksFile, err := os.Create(filepath.Join(baseDirName, jwksFilename))
	if err != nil {
		return fmt.Errorf("cannot create %s: %w", jwksFilename, err)
	}
	defer jwksFile.Close()
	if err := oidc.WriteJWKS(jwksFile, key); err != nil {
		return fmt.Errorf("cannot write %s: %w", jwksFilename, err)
	}
	log.Printf("created %s", jwksFilename)

	discoveryFile, err := os.Create(filepath.Join(baseDirName, discoveryFilename))
	if err != nil {
		return fmt.Errorf("cannot create %s: %w", discoveryFilename, err)
	}
	defer discoveryFile.Close()
	if err := oidc.WriteDiscovery(discoveryFile, ""); err != nil {
		return fmt.Errorf("cannot write %s: %w", discoveryFilename, err)
	}
	log.Printf("created %s", discoveryFilename)

	publicKeyFile, err := os.Create(filepath.Join(baseDirName, publicKeyFilename))
	if err != nil {
		return fmt.Errorf("cannot create %s: %w", publicKeyFilename, err)
	}
	defer publicKeyFile.Close()
	if err := keypair.WritePublicKey(publicKeyFile, key); err != nil {
		return fmt.Errorf("cannot write %s: %w", publicKeyFilename, err)
	}
	log.Printf("created %s", publicKeyFilename)

	privateKeyFile, err := os.Create(filepath.Join(baseDirName, privateKeyFilename))
	if err != nil {
		return fmt.Errorf("cannot create %s: %w", privateKeyFilename, err)
	}
	defer privateKeyFile.Close()
	if err := keypair.WritePrivateKey(privateKeyFile, key); err != nil {
		return fmt.Errorf("cannot write %s: %w", privateKeyFilename, err)
	}
	log.Printf("created %s", privateKeyFilename)
	return nil
}

func main() {
	log.SetFlags(log.Lmicroseconds)
	if err := run(); err != nil {
		log.Fatalf("error: %s", err)
	}
}
