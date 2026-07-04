VERSION ?= dev
LDFLAGS := -ldflags="-X main.version=$(VERSION)"

.PHONY: all build test clean lint vet fmt run install

all: build

build:
	go build $(LDFLAGS) -o bin/ai-text-sanitizer ./cmd/ai-text-sanitizer

test:
	go test ./... -v

vet:
	go vet ./...

fmt:
	go fmt ./...

lint:
	golangci-lint run ./... || true

clean:
	rm -rf bin/

run:
	go run $(LDFLAGS) ./cmd/ai-text-sanitizer

install:
	go install $(LDFLAGS) ./cmd/ai-text-sanitizer

release:
	goreleaser release --snapshot --rm-dist || true
