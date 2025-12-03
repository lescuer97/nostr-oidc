package libsecret

import (
	"encoding/hex"
	"errors"
	"fmt"

	goLibSecret "github.com/lescuer97/go-libsecret"
)

const Service = "nostr-oidc"

const VertexNsec = "vertex-nsec"
const SchemaName = "org.example.NostrOidc"

var (
	ErrNotFound    = errors.New("Could not found value in keystore")
	SchemaNotSetup = errors.New("Main schema was not setup you need that first")
)

var mainSchema *goLibSecret.Schema

func SetupKeychain() error {
	attr := map[string]goLibSecret.SchemaAttributeType{
		"key": goLibSecret.SchemaAttributeString,
	}

	schema, err := goLibSecret.NewSchema(SchemaName, goLibSecret.SchemaFlagsNone, attr)
	if err != nil {
		return fmt.Errorf("goLibSecret.NewSchema(SchemaName). %w", err)

	}

	mainSchema = schema
	return nil
}

func SetSecret(id string, secret []byte) error {
	if mainSchema == nil {
		return SchemaNotSetup
	}

	attr := map[string]string{
		"key": id,
	}

	return goLibSecret.StorePassword(mainSchema, attr, goLibSecret.CollectionDefault, SchemaName, hex.EncodeToString(secret))
}

func GetSecret(id string) (string, error) {
	attrs := goLibSecret.NewAttributes()
	attrs.Set("key", id)

	val, err := goLibSecret.PasswordLookupSync(mainSchema, attrs)
	if err != nil {
		return "", fmt.Errorf("goLibSecret.PasswordLookupSync(mainSchema, attrs). %w", err)
	}
	if val == "" {
		return "", ErrNotFound
	}
	return val, nil
}
