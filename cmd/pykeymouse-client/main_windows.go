//go:build windows

package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"pykeymouse/internal/client"
	"pykeymouse/internal/config"
	"pykeymouse/internal/input"
)

func main() {
	var configPath string
	var printDefault bool
	flag.StringVar(&configPath, "config", "configs/client.json", "client config path")
	flag.BoolVar(&printDefault, "print-default", false, "print default config and exit")
	flag.Parse()

	if printDefault {
		cfg := config.DefaultClientConfig()
		out, _ := json.MarshalIndent(cfg, "", "  ")
		log.Println(string(out))
		return
	}

	cfg, err := config.LoadClientConfig(configPath)
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	events := make(chan input.Event, 1024)
	rawCfg := input.RawInputConfig{
		EnableKeyboard: cfg.Input.EnableKeyboard != nil && *cfg.Input.EnableKeyboard,
		EnableMouse:    cfg.Input.EnableMouse != nil && *cfg.Input.EnableMouse,
		MouseAggregate: cfg.MouseAggregateInterval(),
	}

	go func() {
		err := input.RunRawInput(ctx, rawCfg, events)
		if err != nil {
			log.Printf("raw input error: %v", err)
		}
		close(events)
	}()

	cli := client.New(cfg, nil)
	if err := cli.Run(ctx, events); err != nil && ctx.Err() == nil {
		log.Fatalf("client error: %v", err)
	}
}
