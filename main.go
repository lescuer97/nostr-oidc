package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/lescuer97/nostr-oicd/libsecret"
	"github.com/lescuer97/nostr-oicd/storage"
	"github.com/lescuer97/nostr-oicd/storage/database"
	"github.com/lescuer97/nostr-oicd/utils"
	"github.com/lescuer97/nostr-oicd/vertex"
	"github.com/lescuer97/nostr-oicd/web"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"
)

const (
	ADMIN_USER_NPUB      = "ADMIN_USER_NPUB"
	OIDCIssuerEnv        = "OIDC_ISSUER"
	OIDCAllowInsecureEnv = "OIDC_ALLOW_INSECURE"
)

type oidcEnvConfig struct {
	Issuer        string
	AllowInsecure bool
}

func main() {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found or error loading it, using environment variables")
  }

	err := libsecret.SetupKeychain()
	if err != nil {
		log.Fatalf("libsecret.SetupKeychain() %v", err)
	}

	// Open DB using our helper
	db, err := database.Open("./database.db")
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	err = database.RunMigrations(db)
	if err != nil {
		log.Fatalf("could not run migration: %v", err)
	}

	storage, err := storage.NewStorage(db)
	if err != nil {
		log.Fatalf("storage.NewStorage(db). %v", err)
	}

	// Ensure a default configuration exists
	if err := ensureConfiguration(context.Background(), &storage); err != nil {
		log.Fatalf("failed to ensure default configuration: %v", err)
	}

	if err := ensureAdminEnvNpubIsRegistedAsAdmin(os.Getenv(ADMIN_USER_NPUB), &storage); err != nil {
		log.Fatalf("failed to register nsec admin user: %v", err)
	}

	if err := ensureOICDAdminDashboardClientIdExists(&storage); err != nil {
		log.Fatalf("could no generate oicd client for dashboard: %v", err)
	}

	config, err := storage.GetConfiguration(context.Background())
	if err != nil {
		log.Fatalf("storage.GetConfigurationWithNsec(context.Background()). %v", err)
	}

	oidcConfig, err := parseOIDCEnvConfig()
	if err != nil {
		log.Fatalf("parseOIDCEnvConfig(). %v", err)
	}

	server := web.Server{
		Storage:           &storage,
		OIDCIssuer:        oidcConfig.Issuer,
		OIDCAllowInsecure: oidcConfig.AllowInsecure,
	}

	if config.RegistrationType == "open" {
		if config.Nsec == nil {
			log.Panicf("you don't have an nsec in your configuration. This should have never happened because it should have been required when making the registration type opened")
		}

		vrt, err := vertex.NewVertexChecker()
		if err != nil {
			log.Fatalf("vertex.NewVertexChecker(): %v", err)
		}

		server.Vertex = vrt
	}

	r := web.SetupServer(&server)
	srv := &http.Server{
		Addr:    ":" + "8082",
		Handler: r,
	}

	go func() {
		log.Printf("starting server on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	// log.Printf("/routes: %+v", router.Routes())
	// Graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	<-ctx.Done()

	log.Println("shutting down gracefully, press Ctrl+C again to force")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("server forced to shutdown: %v", err)
	}

	log.Println("server exiting")
}

func parseOIDCEnvConfig() (oidcEnvConfig, error) {
	issuer := strings.TrimSpace(os.Getenv(OIDCIssuerEnv))
	if issuer == "" {
		return oidcEnvConfig{}, fmt.Errorf("%s is required", OIDCIssuerEnv)
	}

	allowInsecure := false
	allowInsecureValue, hasAllowInsecure := os.LookupEnv(OIDCAllowInsecureEnv)
	if hasAllowInsecure {
		parsedAllowInsecure, err := strconv.ParseBool(strings.TrimSpace(allowInsecureValue))
		if err != nil {
			return oidcEnvConfig{}, fmt.Errorf("%s must be a valid boolean. got %q", OIDCAllowInsecureEnv, allowInsecureValue)
		}
		allowInsecure = parsedAllowInsecure
	}

	return oidcEnvConfig{
		Issuer:        issuer,
		AllowInsecure: allowInsecure,
	}, nil
}

// ensureConfiguration checks if a configuration exists in the database.
// If it doesn't exist, it creates a default one with:
// - RegistrationType: manual
// - MaxClients: 5
// - MaxUsers: 1000
func ensureConfiguration(ctx context.Context, store *storage.Storage) error {
	// Try to get the current configuration
	config, err := store.GetConfiguration(ctx)
	if err == nil && config != nil {
		// Configuration exists, no need to create one
		log.Println("Configuration already exists")
		return nil
	}

	if errors.Is(err, sql.ErrNoRows) {
		// Configuration doesn't exist, create a default one
		defaultConfig := &storage.Configuration{
			RegistrationType: "manual",
			MaxClients:       5,
			MaxUsers:         1000,
			LastUpdated:      uint64(time.Now().Unix()),
		}

		// Generate a random encryption key
		k, err := utils.GenerateRandomKey()
		if err != nil {
			return fmt.Errorf("failed to generate encryption key: %w", err)
		}
		defaultConfig.EncryptionKey = k

		if err = store.AddConfiguration(ctx, defaultConfig); err != nil {
			return fmt.Errorf("failed to create default configuration: %w", err)
		}
		return err
	}

	return err
}

// ensures that the nsec for admin in the env variable is registered as an admin user
func ensureAdminEnvNpubIsRegistedAsAdmin(env string, store *storage.Storage) error {
	user, err := store.GetAllAdminUsers(context.Background())
	if err != nil {
		return fmt.Errorf("store.GetAllAdminUsers(context.Background()). %w", err)
	}

	if len(user) == 0 && len(env) == 0 {
		return fmt.Errorf("\n No Admin users. You need to bootstrap an admin user with the  ADMIN_USER_NPUB enviroment variable.")

	}
	if len(user) > 0 || len(env) == 0 {
		return nil
	}

	prefix, value, err := nip19.Decode(env)
	if err != nil {
		return fmt.Errorf("nip19.Decode(nsec). %w", err)
	}

	if prefix != "npub" {
		return fmt.Errorf("nsec is no correct")
	}

	hexPrivKey := value.(string)
	pkBytes, err := hex.DecodeString(hexPrivKey)
	if err != nil {
		return fmt.Errorf("hex.DecodeString(hexPrivKey). %w", err)
	}

	pubkey, err := schnorr.ParsePubKey(pkBytes)
	if err != nil {
		return fmt.Errorf("schnorr.ParsePubKey(pkBytes). %w", err)
	}

	_, err = store.CheckUserNpub(pubkey)
	if errors.Is(err, sql.ErrNoRows) {
		userID := uuid.New().String()
		newUser := storage.User{
			ID:                userID,
			Npub:              pubkey,
			PreferredLanguage: language.English,
			IsAdmin:           true,
			Active:            true,
		}
		err = store.AddUser(context.Background(), newUser)
		if err != nil {
			return fmt.Errorf("store.AddUser(context.Background(), newUser). %w", err)
		}
	}

	return err
}

func ensureOICDAdminDashboardClientIdExists(store *storage.Storage) error {
	_, err := store.GetClientByClientID(context.Background(), storage.OICD_ADMIN_DASHBOARD_CLIENT_ID)
	if errors.Is(err, sql.ErrNoRows) {
		client := storage.NewClient(storage.OICD_ADMIN_DASHBOARD_CLIENT_ID, "", []string{"http://localhost:8082/admin/oidc/callback"}, op.ApplicationTypeNative,
			oidc.AuthMethodNone,
			[]oidc.ResponseType{oidc.ResponseTypeCode},
			[]oidc.GrantType{oidc.GrantTypeCode},
			op.AccessTokenTypeBearer, []string{}, []string{},
		)

		err = store.AddClient(context.Background(), *client)
		if err != nil {
			slog.Error("s.storage.AddClient", slog.Any("error", err))
			return fmt.Errorf("store.AddClient(context.Background(), *client). %w", err)
		}
	}

	return err

}
