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

	// "github.com/a-h/templ"
	// "github.com/go-chi/chi/v5"
	// "github.com/go-chi/cors"
	"github.com/joho/godotenv"
	// "github.com/lescuer97/nostr-oicd/internal/auth"
	// "github.com/lescuer97/nostr-oicd/internal/config"
	"github.com/lescuer97/nostr-oicd/config"
	// "github.com/lescuer97/nostr-oicd/internal/database"
	"github.com/lescuer97/nostr-oicd/oicd"
	"github.com/lescuer97/nostr-oicd/oicd/storage"
	// pages "github.com/lescuer97/nostr-oicd/templates/pages"
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

	// // Open DB using our helper
	// db, err := database.Open(cfg.DatabasePath)
	// if err != nil {
	// 	log.Fatalf("failed to open database: %v", err)
	// }
	// defer db.Close()

	// Run migrations
	// if err := database.RunMigrations(db, "./database/migrations"); err != nil {
	// 	log.Fatalf("failed to run migrations: %v", err)
	// }

	// r := chi.NewRouter()
	//
	// // CORS for development
	// r.Use(cors.Handler(cors.Options{
	// 	AllowedOrigins:   []string{"https://*", "http://*"},
	// 	AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions},
	// 	AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
	// 	AllowCredentials: true,
	// 	MaxAge:           300,
	// }))
	//
	// // Register auth routes
	// auth.RegisterRoutes(r, cfg, db)
	//
	// // Static file server
	// r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
	//
	// // Templ pages (make sure to run `templ generate` before running the server)
	// r.Handle("/login", templ.Handler(pages.LoginPage()))
	// // TODO: add signup/dashboard templates and mount them here when available
	//
	// // Basic routes (placeholders)
	// r.Get("/", func(w http.ResponseWriter, r *http.Request) {
	// 	w.Header().Set("Content-Type", "text/plain")
	// 	w.Write([]byte("nostr-oicd server running"))
	// })

	storage.RegisterClients(
		storage.NativeClient("native", cfg.RedirectURI...),
		storage.DeviceClient("web", "secret"),
	)

	// the OpenIDProvider interface needs a Storage interface handling various checks and state manipulations
	// this might be the layer for accessing your database
	// in this example it will be handled in-memory
	store, err := getUserStore(cfg)
	if err != nil {
		// logger.Error("cannot create UserStore", "error", err)
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
