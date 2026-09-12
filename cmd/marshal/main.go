package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/lmittmann/tint"
	log "log/slog"

	cli "github.com/spf13/pflag"

	"github.com/MrZloHex/monolink"
	auth "github.com/MrZloHex/monolink/marshal"
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

// validOrigin is an origin as a browser writes one into a passkey's client
// data: a scheme and a host, nothing after — https, or plain http on this
// machine alone.
func validOrigin(o string) bool {
	u, err := url.Parse(o)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1"
	}
	return false
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

	url := cli.StringP("url", "u", envString("MARSHAL_HUB_URL", "wss://127.0.0.1:8443"), "Hub URL, wss:// only (env MARSHAL_HUB_URL)")
	logLevel := cli.StringP("log", "l", envString("MARSHAL_LOG", "info"), "Log level (env MARSHAL_LOG)")
	statePath := cli.StringP("state", "s", envString("MARSHAL_STATE", "marshal.json"), "People, grants and sessions (env MARSHAL_STATE)")
	ttl := cli.Duration("session-ttl", envDuration("MARSHAL_SESSION_TTL", time.Hour), "How long a session lasts unused (env MARSHAL_SESSION_TTL)")
	rpID := cli.String("rp-id", envString("MARSHAL_RP_ID", "monolith-system.net"), "The site passkeys are made for (env MARSHAL_RP_ID)")
	origins := cli.String("origin", envString("MARSHAL_ORIGIN", "https://monolith-system.net"), "Origins the app is served from, comma-separated (env MARSHAL_ORIGIN)")
	printer := cli.String("printer", envString("MARSHAL_PRINTER", "UKAZ"), "Node that prints the enrolment code; empty writes it to the log (env MARSHAL_PRINTER)")
	ticketKey := cli.String("ticket-key", envString("MARSHAL_TICKET_KEY", "ticket.key"), "Ed25519 key that signs tickets for the hub, PEM (env MARSHAL_TICKET_KEY)")
	tlsCert := cli.String("tls-cert", os.Getenv("MARSHAL_TLS_CERT"), "Client certificate PEM for mTLS (env MARSHAL_TLS_CERT)")
	tlsKey := cli.String("tls-key", os.Getenv("MARSHAL_TLS_KEY"), "Client private key PEM for mTLS (env MARSHAL_TLS_KEY)")
	tlsCA := cli.String("tls-ca", os.Getenv("MARSHAL_TLS_CA"), "The bubble CA's PEM, which vouches for the hub (env MARSHAL_TLS_CA)")
	cli.Parse()

	log.SetDefault(log.New(tint.NewHandler(os.Stdout, &tint.Options{
		Level: logLevelMap[*logLevel],
	})))

	// marshal trusts whoever the hub says sent a frame; anything else at the
	// hub's port could say anything, and read the enrolment code on its way
	// to the printer. So the real hub, over mTLS, or nothing.
	cfg, err := monolink.SecureTLS(*url, *tlsCert, *tlsKey, *tlsCA)
	if err != nil {
		log.Error("cannot reach the hub safely", "err", err)
		os.Exit(1)
	}
	opts := []monolink.Option{
		monolink.WithReconnect(5 * time.Second),
		monolink.WithDialect(monolink.V2),
		monolink.WithTLS(cfg),
	}

	// An empty entry would accept client data naming no origin at all.
	var site []string
	for _, o := range strings.Split(*origins, ",") {
		if o = strings.TrimSpace(o); o != "" {
			site = append(site, o)
		}
	}
	if *rpID != "" && len(site) == 0 {
		log.Error("--origin is needed: the origins the app is served from")
		os.Exit(1)
	}
	for _, o := range site {
		if !validOrigin(o) {
			log.Error("--origin is https://host[:port] — or http://localhost, for testing", "origin", o)
			os.Exit(1)
		}
	}
	if *rpID == "" {
		log.Warn("no --rp-id: passkeys cannot sign anyone in")
	}

	key, err := auth.LoadTicketKey(*ticketKey)
	if err != nil {
		log.Error("ticket key", "err", err)
		os.Exit(1)
	}

	client := monolink.New(marshal.NodeName, *url, opts...)

	m, err := marshal.New(client, marshal.NewStore(*statePath), marshal.Options{
		TTL:       *ttl,
		Printer:   *printer,
		Version:   version,
		TicketKey: key,
		Site:      auth.RelyingParty{ID: *rpID, Origins: site},
	})
	if err != nil {
		log.Error("Failed to init marshal", "err", err)
		os.Exit(1)
	}
	client.Handle("*", m.Cmd)

	log.Info("BOOTING UP", "url", *url, "state", *statePath, "site", *rpID, "origin", *origins, "version", version)

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
