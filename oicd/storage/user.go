package storage

import (
	"crypto/ecdsa"
	// "crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"os"

	// "strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"golang.org/x/text/language"
)

const (
	// ServiceUserID is the ID of the service user.
	ServiceUserID = "service"
	// ServiceUserKeyID is the key ID of the service user.
	ServiceUserKeyID = "key1"
)

type User struct {
	ID                string
	Npub              *btcec.PublicKey
	PreferredLanguage language.Tag
	IsAdmin           bool
}

type Service struct {
	keys map[string]*ecdsa.PublicKey
}

type UserStore interface {
	GetUserByID(string) *User
	GetUserByNpub(*btcec.PublicKey) *User
	ExampleClientID() string
}

type userStore struct {
	users map[string]*User
}

func StoreFromFile(path string) (UserStore, error) {
	users := map[string]*User{}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, err
	}
	return userStore{users}, nil
}

func NewUserStore(issuer string) UserStore {
	_, value, err := nip19.Decode("npub1z5caxxaucn8zvj6ejcgshsmq6e0qeg3e8ckf2k843w53wcarkprqa6ssqg")
	if err != nil {
		panic("invalid  ADMIN_NOSTR_NPUB ")
	}

	decodedKey, err := hex.DecodeString(value.(string))
	if err != nil {
		panic("decoded ADMIN_NOSTR_NPUB is not correct")
	}

	pubkey, err := schnorr.ParsePubKey(decodedKey)
	if err != nil {
		panic("could not decode schnorr pubkey")
	}
	return userStore{
		users: map[string]*User{
			"id1": {
				ID:                "id1",
				PreferredLanguage: language.German,
				Npub:              pubkey,
				IsAdmin:           true,
			},
		},
	}
}

// ExampleClientID is only used in the example server
func (u userStore) ExampleClientID() string {
	return ServiceUserID
}

func (u userStore) GetUserByID(id string) *User {
	return u.users[id]
}

func (u userStore) GetUserByNpub(pubkey *btcec.PublicKey) *User {
	for _, user := range u.users {
		if user.Npub.IsEqual(pubkey) {
			return user
		}
	}
	return nil
}
