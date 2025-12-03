package storage

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"reflect"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/lescuer97/nostr-oicd/libsecret"
	"github.com/lescuer97/nostr-oicd/utils"
	"github.com/nbd-wtf/go-nostr"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"
)

// storage implements the op.Storage interface
// typically you would implement this as a layer on top of your database
// for simplicity this example keeps everything in-memory
type Storage struct {
	signingKey signingKey
	db         storageDB
}

func NewStorage(db *sql.DB) (Storage, error) {
	if db == nil {
		log.Panicf("database instance should not be nil")
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Storage{}, fmt.Errorf("ecdsa.GenerateKey(elliptic.P256(), rand.Reader). %w", err)
	}
	return Storage{
		db: storageDB{db: db},
		signingKey: signingKey{
			id:        uuid.NewString(),
			algorithm: jose.ES256,
			key:       privateKey,
		},
	}, nil
}

// CreateAuthRequest implements the op.Storage interface
// it will be called after parsing and validation of the authentication request
func (s *Storage) CreateAuthRequest(ctx context.Context, authReq *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	log.Printf("\n\n Create Auth Request")
	if len(authReq.Prompt) == 1 && authReq.Prompt[0] == "none" {
		// With prompt=none, there is no way for the user to log in
		// so return error right away.
		return nil, oidc.ErrLoginRequired()
	}

	// typically, you'll fill your storage / storage model with the information of the passed object
	request := authRequestToInternal(authReq, userID)

	// you'll also have to create a unique id for the request (this might be done by your database; we'll use a uuid)
	request.ID = uuid.NewString()
	//
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	err = s.db.AddAuthRequest(tx, request)
	if err != nil {
		return nil, fmt.Errorf("s.db.AddAuthRequest(tx, request). %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("tx.Commit(). %w", err)
	}

	return request, nil
}

func (s *Storage) AddUserIDToAuthRequest(ctx context.Context, id string, userID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	err = s.db.AddUserIDToAuthRequest(tx, id, userID)
	if err != nil {
		return fmt.Errorf("s.db.AddUserIDToAuthRequest(tx, id, userID). %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %w", err)
	}
	return nil
}

func (s *Storage) SetAuthRequestDone(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	err = s.db.SetAuthRequestDone(tx, id)
	if err != nil {
		return fmt.Errorf("s.db.SetAuthRequestDone(tx, id). %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %w", err)
	}
	return nil
}

// AuthRequestByID implements the op.Storage interface
// it will be called after the Login UI redirects back to the OIDC endpoint
func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	authReq, err := s.db.SearchAuthRequestByID(tx, id)
	if err != nil {
		return nil, fmt.Errorf("s.db.SearchAuthRequestByID(tx, id). %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("tx.Commit(). %w", err)
	}
	return authReq, nil
}

// AuthRequestByID implements the op.Storage interface
// it will be called after the Login UI redirects back to the OIDC endpoint
func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	authReq, err := s.db.SearchAuthRequestByCode(tx, code)
	if err != nil {
		return nil, fmt.Errorf("s.db.SearchAuthRequestByCode(tx, code). %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("tx.Commit(). %w", err)
	}
	return authReq, nil
}

// SaveAuthCode implements the op.Storage interface
// it will be called after the authentication has been successful and before redirecting the user agent to the redirect_uri
// (in an authorization code flow)
func (s *Storage) SaveAuthCode(ctx context.Context, id string, code string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	// Update the auth request to include the code challenge
	err = s.db.SaveAuthCode(tx, id, code)
	if err != nil {
		return fmt.Errorf("s.db.SaveAuthCode(tx, %s, %s). %w", id, code, err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %w", err)
	}
	return nil
}

// DeleteAuthRequest implements the op.Storage interface
// it will be called after creating the token response (id and access tokens) for a valid
// - authentication request (in an implicit flow)
// - token request (in an authorization code flow)
func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	err = s.db.DeleteAuthRequest(tx, id)
	if err != nil {
		return fmt.Errorf("s.db.DeleteAuthRequest(tx, id). %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %w", err)
	}
	return nil

}

// CreateAccessToken implements the op.Storage interface
// it will be called for all requests able to return an access token (Authorization Code Flow, Implicit Flow, JWT Profile, ...)
func (s *Storage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {

	// Determine the application ID and other necessary information from the request
	var applicationID string
	var subject string
	var audience []string
	var scopes []string

	switch req := request.(type) {
	case *AuthRequest:
		applicationID = req.ApplicationID
		subject = req.UserID
		audience = req.Scopes // Note: this should be the actual audience list
		scopes = req.Scopes
	case op.TokenExchangeRequest:
		applicationID = req.GetClientID()
		subject = req.GetSubject()
		audience = req.GetAudience()
		scopes = req.GetScopes()
	case *op.DeviceAuthorizationState:
		applicationID = req.GetClientID()
		subject = req.GetSubject()
		audience = req.GetAudience()
		scopes = req.GetScopes()
	default:
		applicationID = ""
		subject = ""
		audience = []string{}
		scopes = []string{}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	token, err := s.accessToken(tx, applicationID, "", subject, audience, scopes)
	if err != nil {
		return "", time.Time{}, fmt.Errorf(`s.accessToken(ctx, applicationID, "", subject, audience, scopes). %w`, err)
	}
	err = tx.Commit()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("tx.Commit(). %w", err)
	}

	return token.ID, token.Expiration, nil
}

func (s *Storage) createRefreshToken(tx *sql.Tx, accessToken *Token, amr []string, authTime time.Time) (string, error) {
	token := RefreshToken{
		ID:            accessToken.RefreshTokenID,
		Token:         accessToken.RefreshTokenID,
		AuthTime:      authTime,
		AMR:           amr,
		ApplicationID: accessToken.ApplicationID,
		UserID:        accessToken.Subject,
		Audience:      accessToken.Audience,
		Expiration:    time.Now().Add(5 * time.Hour),
		Scopes:        accessToken.Scopes,
		AccessToken:   accessToken.ID,
	}

	err := s.db.AddRefreshToken(tx, &token)
	if err != nil {
		return "", fmt.Errorf("s.db.AddRefreshToken(tx, &token). %w", err)
	}

	return token.Token, nil
}
func (s *Storage) accessToken(tx *sql.Tx, applicationID, refreshTokenID, subject string, audience, scopes []string) (*Token, error) {
	token := Token{
		ID:             uuid.NewString(),
		ApplicationID:  applicationID,
		RefreshTokenID: refreshTokenID,
		Subject:        subject,
		Audience:       audience,
		Expiration:     time.Now().Add(5 * time.Minute),
		Scopes:         scopes,
	}

	err := s.db.AddToken(tx, &token)
	if err != nil {
		return nil, fmt.Errorf("s.db.AddRefreshToken(tx, &token). %w", err)
	}

	return &token, nil
}

func (s *Storage) exchangeRefreshToken(tx *sql.Tx, request op.TokenExchangeRequest) (accessTokenID string, newRefreshToken string, expiration time.Time, err error) {
	applicationID := request.GetClientID()
	authTime := request.GetAuthTime()

	refreshTokenID := uuid.NewString()
	accessToken, err := s.accessToken(tx, applicationID, refreshTokenID, request.GetSubject(), request.GetAudience(), request.GetScopes())
	if err != nil {
		return "", "", time.Time{}, err
	}

	refreshToken, err := s.createRefreshToken(tx, accessToken, nil, authTime)
	if err != nil {
		return "", "", time.Time{}, err
	}

	return accessToken.ID, refreshToken, accessToken.Expiration, nil
}

// getInfoFromRequest returns the clientID, authTime and amr depending on the op.TokenRequest type / implementation
func getInfoFromRequest(req op.TokenRequest) (clientID string, authTime time.Time, amr []string) {
	authReq, ok := req.(*AuthRequest) // Code Flow (with scope offline_access)
	if ok {
		return authReq.ApplicationID, authReq.authTime, authReq.GetAMR()
	}
	refreshReq, ok := req.(*RefreshTokenRequest) // Refresh Token Request
	if ok {
		return refreshReq.ApplicationID, refreshReq.AuthTime, refreshReq.AMR
	}
	deviceReq, ok := req.(*op.DeviceAuthorizationState) // Refresh Token Request
	if ok {
		return deviceReq.ClientID, deviceReq.Expires, deviceReq.AMR
	}
	return "", time.Time{}, nil
}

func (s *Storage) renewRefreshToken(tx *sql.Tx, currentRefreshToken, newRefreshToken, newAccessToken string) error {

	refreshToken, err := s.db.SearchRefreshTokenByID(tx, currentRefreshToken)
	if err != nil {
		return fmt.Errorf("s.db.SearchRefreshTokenByID(currentRefreshToken). %w", err)
	}

	err = s.db.DeleteRefreshToken(tx, currentRefreshToken)
	if err != nil {
		return fmt.Errorf("s.db.DeleteRefreshToken(tx, currentRefreshToken). %w", err)
	}
	err = s.db.DeleteToken(tx, currentRefreshToken)
	if err != nil {
		return fmt.Errorf("s.db.DeleteToken(tx, currentRefreshToken). %w", err)
	}

	if refreshToken.Expiration.Before(time.Now()) {
		return fmt.Errorf("expired refresh token")
	}

	// creates a new refresh token based on the current one
	refreshToken.Token = newRefreshToken
	refreshToken.ID = newRefreshToken
	refreshToken.Expiration = time.Now().Add(5 * time.Hour)
	refreshToken.AccessToken = newAccessToken

	err = s.db.AddRefreshToken(tx, refreshToken)
	if err != nil {
		return fmt.Errorf("s.db.AddRefreshToken(tx, refreshToken). %w", err)
	}

	return nil
}

// CreateAccessAndRefreshTokens implements the op.Storage interface
// it will be called for all requests able to return an access and refresh token (Authorization Code Flow, Refresh Token Request)
func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (accessTokenID string, newRefreshToken string, expiration time.Time, err error) {
	// Start a transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	// generate tokens via token exchange flow if request is relevant
	if teReq, ok := request.(op.TokenExchangeRequest); ok {
		accessTokenID, newRefreshToken, expiration, err := s.exchangeRefreshToken(tx, teReq)
		if err != nil {
			return "", "", time.Time{}, err
		}
		if err := tx.Commit(); err != nil {
			return "", "", time.Time{}, fmt.Errorf("tx.Commit(). %w", err)
		}
		return accessTokenID, newRefreshToken, expiration, nil
	}

	// get the information depending on the request type / implementation
	applicationID, authTime, amr := getInfoFromRequest(request)

	// if currentRefreshToken is empty (Code Flow) we will have to create a new refresh token
	if currentRefreshToken == "" {
		refreshTokenID := uuid.NewString()
		accessToken, err := s.accessToken(tx, applicationID, refreshTokenID, request.GetSubject(), request.GetAudience(), request.GetScopes())
		if err != nil {
			return "", "", time.Time{}, err
		}
		refreshToken, err := s.createRefreshToken(tx, accessToken, amr, authTime)
		if err != nil {
			return "", "", time.Time{}, err
		}
		err = tx.Commit()
		if err != nil {
			return "", "", time.Time{}, fmt.Errorf("tx.Commit(). %w", err)
		}
		return accessToken.ID, refreshToken, accessToken.Expiration, nil
	}

	// if we get here, the currentRefreshToken was not empty, so the call is a refresh token request
	// we therefore will have to check the currentRefreshToken and renew the refresh token
	newRefreshToken = uuid.NewString()

	accessToken, err := s.accessToken(tx, applicationID, newRefreshToken, request.GetSubject(), request.GetAudience(), request.GetScopes())
	if err != nil {
		return "", "", time.Time{}, err
	}

	if err := s.renewRefreshToken(tx, currentRefreshToken, newRefreshToken, accessToken.ID); err != nil {
		return "", "", time.Time{}, err
	}
	err = tx.Commit()
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("tx.Commit(). %w", err)
	}

	return accessToken.ID, newRefreshToken, accessToken.Expiration, nil
}

// TokenRequestByRefreshToken implements the op.Storage interface
// it will be called after parsing and validation of the refresh token request
func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	refreshTokenData, err := s.db.SearchRefreshTokenByID(tx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("s.db.SearchRefreshTokenByID(tx, %s). %w", refreshToken, err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("tx.Commit(). %w", err)
	}

	// Return the refresh token request data using the wrapper function
	return RefreshTokenRequestFromBusiness(refreshTokenData), nil
}

// TerminateSession implements the op.Storage interface
// it will be called after the user signed out, therefore the access and refresh token of the user of this client must be removed
func (s *Storage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	// Start a transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	// Delete all tokens matching user and client
	err = s.db.DeleteTokensByUserAndClient(tx, userID, clientID)
	if err != nil {
		return fmt.Errorf("s.db.DeleteTokensByUserAndClient(tx, %s, %s). %w", userID, clientID, err)
	}

	// Delete all refresh tokens matching user and client
	err = s.db.DeleteRefreshTokensByUserAndClient(tx, userID, clientID)
	if err != nil {
		return fmt.Errorf("s.db.DeleteRefreshTokensByUserAndClient(tx, %s, %s). %w", userID, clientID, err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %w", err)
	}

	return nil
}

// GetRefreshTokenInfo looks up a refresh token and returns the token id and user id.
// If given something that is not a refresh token, it must return error.
func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (userID string, tokenID string, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	refreshToken, err := s.db.SearchRefreshTokenByID(tx, token)
	if err != nil {
		return "", "", fmt.Errorf("s.db.SearchRefreshTokenByID(tx, %s). %w", token, err)
	}

	err = tx.Commit()
	if err != nil {
		return "", "", fmt.Errorf("tx.Commit(). %w", err)
	}

	return refreshToken.UserID, refreshToken.ID, nil
}

// RevokeToken implements the op.Storage interface
// it will be called after parsing and validation of the token revocation request
func (s *Storage) RevokeToken(ctx context.Context, tokenIDOrToken string, userID string, clientID string) *oidc.Error {
	// Start a transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return oidc.ErrInvalidRequest().WithDescription("Internal server error")
	}
	defer tx.Rollback()

	// First, try to find if this is an access token (by ID)
	token, err := s.db.SearchTokenByID(tx, tokenIDOrToken)
	if err == nil {
		// We found an access token; now make sure it belongs to the right client and user
		if token.ApplicationID != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
		}

		// Delete the access token
		err = s.db.DeleteToken(tx, token.ID)
		if err != nil {
			return oidc.ErrInvalidRequest().WithDescription("Internal server error")
		}

		// If token has a refresh token, delete it too (as a best practice in OIDC)
		// The refresh token ID would be in the RefreshTokenID field of the access token
		if token.RefreshTokenID != "" {
			err = s.db.DeleteRefreshToken(tx, token.RefreshTokenID)
			if err != nil {
				return oidc.ErrInvalidRequest().WithDescription("Internal server error")
			}
		}

		// Commit transaction
		err = tx.Commit()
		if err != nil {
			return oidc.ErrInvalidRequest().WithDescription("Internal server error")
		}

		return nil
	}

	// If not found as access token, try to find as refresh token ( directly by token content)
	refreshToken, err := s.db.SearchRefreshTokenByID(tx, tokenIDOrToken)
	if err == nil {
		// We found a refresh token; make sure it belongs to the right client and user
		if refreshToken.ApplicationID != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
		}

		// Delete the refresh token
		err = s.db.DeleteRefreshToken(tx, refreshToken.ID)
		if err != nil {
			return oidc.ErrInvalidRequest().WithDescription("Internal server error")
		}

		// Also delete the corresponding access token using the AccessToken field in refresh token
		if refreshToken.AccessToken != "" {
			err = s.db.DeleteToken(tx, refreshToken.AccessToken)
			if err != nil {
				return oidc.ErrInvalidRequest().WithDescription("Internal server error")
			}
		}

		// Commit transaction
		err = tx.Commit()
		if err != nil {
			return oidc.ErrInvalidRequest().WithDescription("Internal server error")
		}

		return nil
	}

	// Token not found (neither access nor refresh token)
	// In OAuth2/OIDC, we return success when the token is not valid to avoid revealing information
	return nil
}

// SigningKey implements the op.Storage interface
// it will be called when creating the OpenID Provider
func (s *Storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	return &s.signingKey, nil
}

// SignatureAlgorithms implements the op.Storage interface
// it will be called to get the sign
func (s *Storage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{s.signingKey.algorithm}, nil
}

func (s *Storage) KeySet(ctx context.Context) ([]op.Key, error) {
	return []op.Key{&publicKey{s.signingKey}}, nil
}

// GetClientByClientID implements the op.Storage interface
// it will be called whenever information (type, redirect_uris, ...) about the client behind the client_id is needed
func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	client, err := s.db.SearchClientByID(tx, clientID)
	if err != nil {
		return nil, fmt.Errorf("s.db.SearchClientByID(tx, %s). %w", clientID, err)
	}


	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("tx.Commit(). %w", err)
	}

	// Client already implements op.Client interface
	return client, nil
}

// AuthorizeClientIDSecret implements the op.Storage interface
// it will be called for validating the client_id, client_secret on token or introspection requests
func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	client, err := s.db.SearchClientByID(tx, clientID)
	if err != nil {
		return fmt.Errorf("s.db.SearchClientByID(tx, clientID). %w", err)
	}

	secret, err := libsecret.GetSecret(client.secret)
	if err != nil {
		return fmt.Errorf("libsecret.GetSecret(cliet.secret). %w", err)
	}

	if clientSecret != secret {
		return errors.New("Client secret is not the same")
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %w", err)
	}
	return nil
}

// SetUserinfoFromScopes implements the op.Storage interface.
// It populates the userinfo based on the requested scopes
func (s *Storage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	// Start a transaction to fetch user data
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	// Fetch user from database
	user, err := s.db.SearchUserByID(tx, userID)
	if err != nil {
		return fmt.Errorf("s.db.SearchUserByID(tx, %s). %w", userID, err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %w", err)
	}

	// Set the subject (always included)
	userinfo.Subject = user.ID

	// Process each requested scope
	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeOpenID:
			// Subject is already set above

		case oidc.ScopeProfile:
			// Set profile information
			// Set locale from user's preferred language
			if user.PreferredLanguage != language.Und {
				locale := oidc.NewLocale(user.PreferredLanguage)
				userinfo.Locale = locale
			}

			// If we have npub, we can use it as preferred_username
			if user.Npub != nil {
				// Convert public key to hex for npub encoding
				pubkeyHex := fmt.Sprintf("%x", user.Npub.SerializeCompressed()[1:]) // Skip the first byte (02 or 03)
				userinfo.PreferredUsername = pubkeyHex
			}

		case CustomScope:
			// Add custom claim
			userinfo.AppendClaims(CustomClaim, "custom_claim_value")

		// Handle other standard scopes if needed
		case oidc.ScopeEmail:
			// Email scope - not implemented in this user model

		case oidc.ScopePhone:
			// Phone scope - not implemented in this user model

		case oidc.ScopeAddress:
			// Address scope - not implemented in this user model
		}
	}

	// Add admin status as a custom claim if needed
	if user.IsAdmin {
		userinfo.AppendClaims("admin", true)
	}

	return nil
}

// SetUserinfoFromRequest implements the op.CanSetUserinfoFromRequest interface.  In the
// next major release, it will be required for op.Storage.
// It will be called for the creation of an id_token, so we'll just pass it to the private function without any further check
func (s *Storage) SetUserinfoFromRequest(ctx context.Context, userinfo *oidc.UserInfo, token op.IDTokenRequest, scopes []string) error {
	// Get the subject (user ID) from the token request
	userID := token.GetSubject()
	clientID := token.GetClientID()

	// Use SetUserinfoFromScopes to populate userinfo
	return s.SetUserinfoFromScopes(ctx, userinfo, userID, clientID, scopes)
}

// SetUserinfoFromToken implements the op.Storage interface
// it will be called for the userinfo endpoint, so we read the token and pass the information from that to the private function
func (s *Storage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	// Start a transaction to fetch user and token data
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	// Fetch user from database using the subject
	user, err := s.db.SearchUserByID(tx, subject)
	if err != nil {
		return fmt.Errorf("s.db.SearchUserByID(tx, %s). %w", subject, err)
	}

	// Fetch token to get scopes
	token, err := s.db.SearchTokenByID(tx, tokenID)
	if err != nil {
		return fmt.Errorf("s.db.SearchTokenByID(tx, %s). %w", tokenID, err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %w", err)
	}

	// Set the subject (always included)
	userinfo.Subject = user.ID

	// Process each scope from the token
	for _, scope := range token.Scopes {
		switch scope {
		case oidc.ScopeOpenID:
			// Subject is already set above

		case oidc.ScopeProfile:
			// Set profile information
			// Set locale from user's preferred language
			if user.PreferredLanguage != language.Und {
				locale := oidc.NewLocale(user.PreferredLanguage)
				userinfo.Locale = locale
			}

			// If we have npub, we can use it as preferred_username
			if user.Npub != nil {
				// Convert public key to hex for npub encoding
				pubkeyHex := fmt.Sprintf("%x", user.Npub.SerializeCompressed()[1:]) // Skip the first byte (02 or 03)
				userinfo.PreferredUsername = pubkeyHex
			}

		case CustomScope:
			// Add custom claim
			userinfo.AppendClaims(CustomClaim, "custom_claim_value")

		// Handle other standard scopes if needed
		case oidc.ScopeEmail:
			// Email scope - not implemented in this user model

		case oidc.ScopePhone:
			// Phone scope - not implemented in this user model

		case oidc.ScopeAddress:
			// Address scope - not implemented in this user model
		}
	}

	// Add admin status as a custom claim if needed
	if user.IsAdmin {
		userinfo.AppendClaims("admin", true)
	}

	return nil
}

// SetIntrospectionFromToken implements the op.Storage interface
// it will be called for the introspection endpoint, so we read the token and pass the information from that to the private function
func (s *Storage) SetIntrospectionFromToken(ctx context.Context, introspection *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	// Start a transaction to fetch token data
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	// Fetch token from database
	token, err := s.db.SearchTokenByID(tx, tokenID)
	if err != nil {
		return fmt.Errorf("s.db.SearchTokenByID(tx, %s). %w", tokenID, err)
	}

	// Fetch user to get additional information
	user, err := s.db.SearchUserByID(tx, subject)
	if err != nil {
		return fmt.Errorf("s.db.SearchUserByID(tx, %s). %w", subject, err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %w", err)
	}

	// Populate introspection response
	introspection.Active = time.Now().Before(token.Expiration)
	introspection.Scope = token.Scopes
	introspection.ClientID = token.ApplicationID
	introspection.TokenType = oidc.BearerToken
	introspection.Expiration = oidc.FromTime(token.Expiration)
	introspection.Subject = token.Subject
	introspection.Audience = token.Audience

	// Add username from user data
	if user.Npub != nil {
		pubkeyHex := fmt.Sprintf("%x", user.Npub.SerializeCompressed()[1:])
		introspection.Username = pubkeyHex
	}

	// Set locale if available
	if user.PreferredLanguage != language.Und {
		locale := oidc.NewLocale(user.PreferredLanguage)
		introspection.Locale = locale
	}

	// Add admin claim if user is admin
	if user.IsAdmin {
		if introspection.Claims == nil {
			introspection.Claims = make(map[string]any)
		}
		introspection.Claims["admin"] = true
	}

	return nil
}

// GetPrivateClaimsFromScopes implements the op.Storage interface
// it will be called for the creation of a JWT access token to assert claims for custom scopes
func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (claims map[string]any, err error) {
	// Start a transaction to fetch user data
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	// Fetch user from database
	user, err := s.db.SearchUserByID(tx, userID)
	if err != nil {
		return nil, fmt.Errorf("s.db.SearchUserByID(tx, %s). %w", userID, err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("tx.Commit(). %w", err)
	}

	// Initialize claims map
	claims = make(map[string]any)

	// Process each requested scope and add corresponding claims
	for _, scope := range scopes {
		switch scope {
		case CustomScope:
			// Add custom claim for custom scope
			claims[CustomClaim] = "custom_claim_value"

		case oidc.ScopeProfile:
			// Add profile-related claims
			if user.PreferredLanguage != language.Und {
				claims["locale"] = user.PreferredLanguage.String()
			}
			if user.Npub != nil {
				pubkeyHex := fmt.Sprintf("%x", user.Npub.SerializeCompressed()[1:])
				claims["preferred_username"] = pubkeyHex
			}

		// Other scopes could be handled here
		case oidc.ScopeEmail:
			// Email claims - not implemented in current user model

		case oidc.ScopePhone:
			// Phone claims - not implemented in current user model
		}
	}

	// Always add admin claim if user is admin
	if user.IsAdmin {
		claims["admin"] = true
	}

	return claims, nil
}

// GetKeyByIDAndClientID implements the op.Storage interface
// it will be called to validate the signatures of a JWT (JWT Profile Grant and Authentication)
func (s *Storage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	// JWT Profile Grant requires public keys to be registered for clients
	// In a production system, you would:
	// 1. Add a client_keys table to store public keys with their key IDs
	// 2. Fetch the key from database: SELECT key_data FROM client_keys WHERE client_id = ? AND key_id = ?
	// 3. Parse and return the JSONWebKey
	//
	// For this implementation, JWT Profile Grant is not supported
	// Clients should use client_secret_post or client_secret_basic instead
	return nil, fmt.Errorf("JWT Profile Grant not supported: key '%s' not found for client '%s'", keyID, clientID)
}

// ValidateJWTProfileScopes implements the op.Storage interface
// it will be called to validate the scopes of a JWT Profile Authorization Grant request
func (s *Storage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	// Start a transaction to fetch user data
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	// Fetch user to check permissions
	user, err := s.db.SearchUserByID(tx, userID)
	if err != nil {
		return nil, fmt.Errorf("s.db.SearchUserByID(tx, %s). %w", userID, err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("tx.Commit(). %w", err)
	}

	// Validate and filter scopes based on user permissions
	validScopes := make([]string, 0, len(scopes))

	for _, scope := range scopes {
		// Check if scope is allowed
		switch scope {
		case oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopePhone, oidc.ScopeAddress:
			// Standard OIDC scopes are always allowed
			validScopes = append(validScopes, scope)

		case CustomScope:
			// Custom scope is always allowed
			validScopes = append(validScopes, scope)

		default:
			// Check for custom scope patterns (e.g., "custom_scope:impersonate:*")
			if len(scope) > len(CustomScopeImpersonatePrefix) && scope[:len(CustomScopeImpersonatePrefix)] == CustomScopeImpersonatePrefix {
				// Impersonation scope - only allowed for admin users
				if user.IsAdmin {
					validScopes = append(validScopes, scope)
				}
				// Otherwise, skip this scope (not allowed for non-admin users)
			} else {
				// Unknown scope - could be allowed or rejected based on policy
				// For now, we'll allow unknown scopes
				validScopes = append(validScopes, scope)
			}
		}
	}

	return validScopes, nil
}

// Health implements the op.Storage interface
func (s *Storage) Health(ctx context.Context) error {
	// Check database connectivity by performing a simple query
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Perform health check query
	err = s.db.HealthCheck(tx)
	if err != nil {
		return fmt.Errorf("database health check failed: %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit health check transaction: %w", err)
	}

	return nil
}

// Device Code auth flow

func (s *Storage) CheckNostrEventSignature(event nostr.Event) error {
	valid, err := event.CheckSignature()
	if err != nil {
		return fmt.Errorf("event.CheckSignature(). %w", err)
	}
	if !valid {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func (s *Storage) StoreDeviceAuthorization(ctx context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string) error {
	// Start a transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	// Verify that the client exists
	_, err = s.db.SearchClientByID(tx, clientID)
	if err != nil {
		return fmt.Errorf("client not found: %w", err)
	}

	// Check if user code already exists (to prevent duplicates)
	_, err = s.db.SearchDeviceAuthorizationByUserCode(tx, userCode)
	if err == nil {
		// User code already exists
		return op.ErrDuplicateUserCode
	}
	// If error is "not found", that's what we want - continue
	// For other errors, we could log but proceed since duplicate check is best-effort

	// Create the device authorization entry
	entry := &deviceAuthorizationEntry{
		deviceCode: deviceCode,
		userCode:   userCode,
		state: &op.DeviceAuthorizationState{
			ClientID: clientID,
			Scopes:   scopes,
			Expires:  expires,
			Done:     false,
			Denied:   false,
		},
	}

	// Store in database
	err = s.db.AddDeviceAuthorization(tx, entry)
	if err != nil {
		return fmt.Errorf("s.db.AddDeviceAuthorization(tx, entry). %w", err)
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %w", err)
	}

	return nil
}

func (s *Storage) GetDeviceAuthorizatonState(ctx context.Context, clientID, deviceCode string) (*op.DeviceAuthorizationState, error) {
	// Check if context is already cancelled
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Start a transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	// Fetch the device authorization entry by device code
	entry, err := s.db.SearchDeviceAuthorizationByDeviceCode(tx, deviceCode)
	if err != nil {
		return nil, fmt.Errorf("device code not found: %w", err)
	}

	// Verify that the device code belongs to the specified client
	if entry.state.ClientID != clientID {
		return nil, fmt.Errorf("device code not found for client")
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("tx.Commit(). %w", err)
	}

	return entry.state, nil
}

func (s *Storage) GetDeviceAuthorizationByUserCode(ctx context.Context, userCode string) (*op.DeviceAuthorizationState, error) {
	// Start a transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	// Fetch the device authorization entry by user code
	entry, err := s.db.SearchDeviceAuthorizationByUserCode(tx, userCode)
	if err != nil {
		return nil, fmt.Errorf("user code not found: %w", err)
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("tx.Commit(). %w", err)
	}

	return entry.state, nil
}

func (s *Storage) CompleteDeviceAuthorization(ctx context.Context, userCode, subject string) error {
	// Start a transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	// Verify that the user code exists
	entry, err := s.db.SearchDeviceAuthorizationByUserCode(tx, userCode)
	if err != nil {
		return fmt.Errorf("user code not found: %w", err)
	}

	// Verify the entry hasn't already been denied or completed
	if entry.state.Denied {
		return fmt.Errorf("device authorization already denied")
	}
	if entry.state.Done {
		return fmt.Errorf("device authorization already completed")
	}

	// Update the authorization with the subject and mark as done
	err = s.db.UpdateDeviceAuthorizationSubject(tx, userCode, subject)
	if err != nil {
		return fmt.Errorf("s.db.UpdateDeviceAuthorizationSubject(tx, %s, %s). %w", userCode, subject, err)
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %w", err)
	}

	return nil
}

func (s *Storage) DenyDeviceAuthorization(ctx context.Context, userCode string) error {
	// Start a transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	// Verify that the user code exists
	entry, err := s.db.SearchDeviceAuthorizationByUserCode(tx, userCode)
	if err != nil {
		return fmt.Errorf("user code not found: %w", err)
	}

	// Verify the entry hasn't already been completed
	if entry.state.Done {
		return fmt.Errorf("device authorization already completed")
	}
	if entry.state.Denied {
		// Already denied, just return success (idempotent operation)
		return nil
	}

	// Mark the authorization as denied
	err = s.db.UpdateDeviceAuthorizationDenied(tx, userCode)
	if err != nil {
		return fmt.Errorf("s.db.UpdateDeviceAuthorizationDenied(tx, %s). %w", userCode, err)
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %w", err)
	}

	return nil
}

func (s *Storage) AddClient(ctx context.Context, client Client) error {
	// Start a transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	clientSecret, err := utils.GenerateRandomKey()
	if err != nil {
		return fmt.Errorf("utils.GenerateRandomKey(). %w", err)
	}
	defer func() {
		clientSecret = nil
	}()

	clientSecretFingerPrint := sha256.Sum256(clientSecret)
	client.secret = hex.EncodeToString(clientSecretFingerPrint[:])

	err = libsecret.SetSecret(hex.EncodeToString(clientSecretFingerPrint[:]), clientSecret)
	if err != nil {
		return fmt.Errorf("libsecret.SetSecret(clientSecretFingerPrint[:], clientSecret). %w", err)
	}

	// Verify that the user code exists
	err = s.db.AddClient(tx, &client)
	if err != nil {
		return fmt.Errorf("could not add client: %w", err)
	}
	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %w", err)
	}

	return nil
}

func (s *Storage) EditClient(ctx context.Context, client Client) error {
	// Start a transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	// Verify that the user code exists
	err = s.db.EditClient(tx, &client)
	if err != nil {
		return fmt.Errorf("could not add client: %w", err)
	}
	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %w", err)
	}

	return nil
}

func (s *Storage) EditUser(ctx context.Context, user User) error {
	// Start a transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	// Update the user
	err = s.db.EditUser(tx, &user)
	if err != nil {
		return fmt.Errorf("could not edit user: %w", err)
	}
	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %w", err)
	}

	return nil
}

// Gets all the clients exept the admin one
func (s *Storage) GetAllClients(ctx context.Context) ([]Client, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	clients, err := s.db.SearchAllNonAdminClients(tx)
	if err != nil {
		return nil, fmt.Errorf("s.db.SearchAllClients(tx). %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("tx.Commit(). %w", err)
	}
	return clients, nil
}

// Gets all the clients execpt the admin users
func (s *Storage) GetAllUsers(ctx context.Context) ([]User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	users, err := s.db.SearchAllUsers(tx, false)
	if err != nil {
		return nil, fmt.Errorf("s.db.SearchAllUsers(tx). %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("tx.Commit(). %w", err)
	}
	return users, nil
}

func (s *Storage) GetAllAdminUsers(ctx context.Context) ([]User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	users, err := s.db.SearchAllUsers(tx, true)
	if err != nil {
		return nil, fmt.Errorf("s.db.SearchAllUsers(tx). %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("tx.Commit(). %w", err)
	}
	return users, nil
}

func (s *Storage) CheckUserNpub(publicKey *btcec.PublicKey) (*User, error) {

	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	user, err := s.db.SearchUserByNpub(tx, publicKey)
	if err != nil {
		return nil, fmt.Errorf("s.db.SearchUserByNpub(tx, publicKey). %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("tx.Commit(). %w", err)
	}
	return user, nil
}

func (s *Storage) GetUserById(ctx context.Context, id string) (*User, error) {

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	user, err := s.db.SearchUserByID(tx, id)
	if err != nil {
		return nil, fmt.Errorf("s.db.SearchUserByID(tx, id). %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("tx.Commit(). %w", err)
	}
	return user, nil
}

// GetConfiguration retrieves the application configuration from the database
func (s *Storage) GetConfiguration(ctx context.Context) (*Configuration, error) {

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	config, err := s.db.GetConfig(tx)
	if err != nil {
		return nil, fmt.Errorf("s.db.GetConfig(tx). %w", err)
	}

	// Validate the retrieved configuration
	if err := validateConfiguration(config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("tx.Commit(). %w", err)
	}
	return config, nil
}

func (s *Storage) NsecIsRegistered(ctx context.Context) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	config, err := s.db.GetConfig(tx)
	if err != nil {
		return false, fmt.Errorf("s.db.GetConfig(tx). %w", err)
	}

	// Validate the retrieved configuration
	if err := validateConfiguration(config); err != nil {
		return false, fmt.Errorf("configuration validation failed: %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return false, fmt.Errorf("tx.Commit(). %w", err)
	}

	return config.Nsec != nil, nil

}

func (s *Storage) AddConfiguration(ctx context.Context, config *Configuration) error {
	if config == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	// Validate the configuration before updating
	if err := validateConfiguration(config); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	err = s.db.SaveConfig(tx, config)
	if err != nil {
		return fmt.Errorf("s.db.SaveConfig(tx, config). %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %w", err)
	}
	return nil
}

// UpdateConfiguration updates the application configuration in the database
func (s *Storage) UpdateConfiguration(ctx context.Context, config *Configuration) error {
	if config == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	// Validate the configuration before updating
	if err := validateConfiguration(config); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	existingConfig, err := s.db.GetConfig(tx)
	if err != nil && err != sql.ErrNoRows { // Check for actual errors, ignoring ErrNoRows for initial setup
		return fmt.Errorf("s.db.GetConfig(tx). %w", err)
	}

	// INFO: if the fingerprint is different it means that the vertex server changed its nsec
	if !reflect.DeepEqual(config.Nsec, existingConfig.Nsec) {
		if config.Nsec != nil {
			fingerPrint := sha256.Sum256(config.Nsec)

			err := libsecret.SetSecret(libsecret.VertexNsec, config.Nsec)
			if err != nil {
				return fmt.Errorf("libsecret.SetSecret(libsecret.VertexNsec, config.Nsec). %w", err)
			}
			config.Nsec = fingerPrint[:]
		}
	}

	err = s.db.SaveConfig(tx, config)
	if err != nil {
		return fmt.Errorf("s.db.SaveConfig(tx, config). %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %w", err)
	}
	return nil
}

// validateConfiguration validates a Configuration struct using the validator library
func validateConfiguration(config *Configuration) error {
	if config == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	// Use the validator library to validate the struct
	if err := validate.Struct(config); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	return nil
}

func (s *Storage) AddUser(ctx context.Context, user User) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("s.db.BeginTx(ctx). %w", err)
	}
	defer tx.Rollback()

	err = s.db.AddUser(tx, &user)
	if err != nil {
		return fmt.Errorf("ss.db.AddUser(tx, &user). %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx.Commit(). %w", err)
	}
	return nil
	// return nil
}
