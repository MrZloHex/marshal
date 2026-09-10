package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/lmittmann/tint"
	log "log/slog"

	cli "github.com/spf13/pflag"

	"github.com/MrZloHex/monolink"
	"marshal/internal/marshal"
)

const version = "0.1.0"

var logLevelMap = map[string]log.Level{
	"debug": log.LevelDebug,
	"info":  log.LevelInfo,
	"warn":  log.LevelWarn,
	"error": log.LevelError,
}

func loadDotEnv() {
	err := godotenv.Load()
	if err == nil {
		return
	}
	var pe *os.PathError
	if errors.Is(err, os.ErrNotExist) || (errors.As(err, &pe) && errors.Is(pe.Err, os.ErrNotExist)) {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "marshal: warning: .env: %v\n", err)
}

func envString(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		_, _ = fmt.Fprintf(os.Stderr, "marshal: warning: %s=%q is not a duration\n", key, v)
	}
	return fallback
}

func main() {
	loadDotEnv()

	url := cli.StringP("url", "u", envString("MARSHAL_HUB_URL", "ws://localhost:8092"), "WebSocket hub URL (env MARSHAL_HUB_URL)")
	logLevel := cli.StringP("log", "l", envString("MARSHAL_LOG", "info"), "Log level (env MARSHAL_LOG)")
	statePath := cli.StringP("state", "s", envString("MARSHAL_STATE", "marshal.json"), "People, grants and sessions (env MARSHAL_STATE)")
	ttl := cli.Duration("session-ttl", envDuration("MARSHAL_SESSION_TTL", 30*24*time.Hour), "How long a session lasts unused (env MARSHAL_SESSION_TTL)")
	printer := cli.String("printer", envString("MARSHAL_PRINTER", "UKAZ"), "Node that prints the enrolment code; empty writes it to the log (env MARSHAL_PRINTER)")
	tlsCert := cli.String("tls-cert", os.Getenv("MARSHAL_TLS_CERT"), "Client certificate PEM for mTLS (env MARSHAL_TLS_CERT)")
	tlsKey := cli.String("tls-key", os.Getenv("MARSHAL_TLS_KEY"), "Client private key PEM for mTLS (env MARSHAL_TLS_KEY)")
	tlsCA := cli.String("tls-ca", os.Getenv("MARSHAL_TLS_CA"), "CA bundle PEM to verify the hub (env MARSHAL_TLS_CA)")
	cli.Parse()

	log.SetDefault(log.New(tint.NewHandler(os.Stdout, &tint.Options{
		Level: logLevelMap[*logLevel],
	})))

	opts := []monolink.Option{
		monolink.WithReconnect(5 * time.Second),
		monolink.WithDialect(monolink.V2),
	}
	switch {
	case *tlsCert != "" && *tlsKey != "":
		cfg, err := monolink.LoadClientTLS(*tlsCert, *tlsKey, *tlsCA)
		if err != nil {
			log.Error("TLS configuration failed", "err", err)
			os.Exit(1)
		}
		opts = append(opts, monolink.WithTLS(cfg))
	case *tlsCert != "" || *tlsKey != "":
		log.Error("TLS incomplete: --tls-cert and --tls-key are required for mTLS")
		os.Exit(1)
	}

	client := monolink.New(marshal.NodeName, *url, opts...)

	m, err := marshal.New(client, marshal.NewStore(*statePath), marshal.Options{
		TTL:     *ttl,
		Printer: *printer,
		Version: version,
	})
	if err != nil {
		log.Error("Failed to init marshal", "err", err)
		os.Exit(1)
	}
	client.Handle("*", m.Cmd)

	log.Info("BOOTING UP", "url", *url, "state", *statePath, "version", version)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		log.Error("Failed to connect", "err", err)
		os.Exit(1)
	}
	m.Start(ctx)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Info("SHUTTING DOWN")
	cancel()
	client.Close()
}
