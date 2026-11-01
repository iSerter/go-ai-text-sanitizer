VERSION ?= dev
LDFLAGS := -ldflags="-X main.version=$(VERSION)"
FUZZTIME ?= 60s

.PHONY: all build test race lint vet fmt bench fuzz generate golden clean run install release

all: build

build:
	go build $(LDFLAGS) -o bin/ai-text-sanitizer ./cmd/ai-text-sanitizer

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

lint: vet
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go run honnef.co/go/tools/cmd/staticcheck@2025.1.1 ./...

bench:
	go test ./aisanitizer -run '^$$' -bench . -benchmem

fuzz:
	go test ./aisanitizer -run '^$$' -fuzz '^FuzzSanitize$$' -fuzztime $(FUZZTIME)
	go test ./aisanitizer -run '^$$' -fuzz '^FuzzOffsets$$' -fuzztime $(FUZZTIME)

# Regenerate the Unicode tables (needs network access to unicode.org).
generate:
	go generate ./aisanitizer

# Accept changes to golden files and the README rules table.
golden:
	go test ./aisanitizer -run 'TestGolden|TestReadmeRules' -update

clean:
	rm -rf bin/ dist/

run:
	go run $(LDFLAGS) ./cmd/ai-text-sanitizer

install:
	go install $(LDFLAGS) ./cmd/ai-text-sanitizer

release:
	goreleaser release --snapshot --clean
