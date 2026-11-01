package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/iSerter/go-ai-text-sanitizer/httpapi"
)

const serveUsage = `ai-text-sanitizer %s - HTTP API server.

Usage:
  ai-text-sanitizer serve [flags]

Endpoints:
  GET  /health    liveness probe (no authentication)
  POST /sanitize  sanitize a JSON {"text": ...} body, or a raw text body
                  with options as query parameters

When an API key is set (--api-key or $%s), /sanitize requires
"Authorization: Bearer KEY" or "X-API-Key: KEY".

Flags:
`

const apiKeyEnv = "AI_TEXT_SANITIZER_API_KEY"

// serveCtx is canceled on SIGINT/SIGTERM; tests replace it.
var serveCtx = func() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func runServe(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("ai-text-sanitizer serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, serveUsage, version, apiKeyEnv)
		fs.PrintDefaults()
	}
	defAddr := ":8080"
	if p := os.Getenv("PORT"); p != "" {
		defAddr = ":" + p
	}
	addr := fs.String("addr", defAddr, "listen `address` (default :$PORT when set)")
	apiKey := fs.String("api-key", os.Getenv(apiKeyEnv), "require this API `key` on /sanitize (prefer $"+apiKeyEnv+")")
	maxBody := fs.Int64("max-body", httpapi.DefaultMaxBodyBytes, "maximum request body size in `bytes`")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitError
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "ai-text-sanitizer serve: unexpected argument %q\n", fs.Arg(0))
		return exitError
	}
	if *maxBody <= 0 {
		fmt.Fprintf(stderr, "ai-text-sanitizer serve: invalid --max-body %d\n", *maxBody)
		return exitError
	}

	logger := log.New(stderr, "ai-text-sanitizer: ", log.LstdFlags)
	srv := &http.Server{
		Handler: httpapi.New(httpapi.Config{
			APIKey:       *apiKey,
			MaxBodyBytes: *maxBody,
			Version:      version,
			Logger:       logger,
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          logger,
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		logger.Print(err)
		return exitError
	}
	if *apiKey == "" {
		logger.Print("warning: no API key set; /sanitize is open to anyone who can reach this address")
	}
	logger.Printf("listening on %s", ln.Addr())

	ctx, stop := serveCtx()
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		logger.Print(err)
		return exitError
	case <-ctx.Done():
	}
	logger.Print("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		logger.Printf("shutdown: %v", err)
		return exitError
	}
	return exitOK
}
