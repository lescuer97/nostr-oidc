package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/joho/godotenv"
	"github.com/lescuer97/nostr-oicd/config"
	"github.com/lescuer97/nostr-oicd/oicd"
	"github.com/lescuer97/nostr-oicd/oicd/storage"
	_ "github.com/mattn/go-sqlite3"
)

func getUserStore(cfg *config.Config) (storage.UserStore, error) {
	if cfg.UsersFile == "" {
		return storage.NewUserStore(fmt.Sprintf("http://localhost:%s/", cfg.Port)), nil
	}
	return storage.StoreFromFile(cfg.UsersFile)
}

func main() {
	// Load .env file if present (silent if missing)
	if err := godotenv.Load(); err != nil {
		log.Printf(".env not loaded (if running in prod this is expected): %v", err)
	} else {
		log.Print("loaded .env file")
	}

	// Load config from environment
	cfg := config.FromEnvVars(&config.Config{Port: "9998"})
	storage.RegisterClients(
		storage.NativeClient("native", cfg.RedirectURI...),
		storage.DeviceClient("web", "secret"),
	)

	store, err := getUserStore(cfg)
	if err != nil {
		os.Exit(1)
	}

	stor := storage.NewStorage(store)
	router := oicd.SetupServer(stor, slog.Default())
	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: router,
	}

	go func() {
		log.Printf("starting server on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	log.Printf("/routes: %+v", router.Routes())
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
