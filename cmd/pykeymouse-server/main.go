//go:build linux

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"pykeymouse/internal/config"
	"pykeymouse/internal/server"
)

func main() {
	var configPath string
	var printDefault bool
	flag.StringVar(&configPath, "config", "configs/server.json", "server config path")
	flag.BoolVar(&printDefault, "print-default", false, "print default config and exit")
	flag.Parse()

	if printDefault {
		cfg := config.DefaultServerConfig()
		out, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Println(string(out))
		return
	}

	cfg, err := config.LoadServerConfig(configPath)
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	srv, err := server.New(cfg, nil)
	if err != nil {
		log.Fatalf("server init error: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := srv.ListenAndServe(ctx); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
