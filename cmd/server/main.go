package main

import (
	"log"
	"os"

	"github.com/jsw-teams/r2uploader/internal/server"
)

func main() {
	cfgPath := os.Getenv("CONFIG_PATH")
	if cfgPath == "" {
		cfgPath = "config.json"
	}

	srv, err := server.New(cfgPath)
	if err != nil {
		log.Fatalf("failed to init server: %v", err)
	}

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	log.Printf("Starting server on %s ...", addr)
	if err := srv.ListenAndServe(addr); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
