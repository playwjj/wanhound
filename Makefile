GO ?= go
BIN := wanhound

.PHONY: build build-linux test vet fmt run docker testbed

build:
	$(GO) build -trimpath -o $(BIN) ./cmd/wanhound

build-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -o $(BIN)-linux-amd64 ./cmd/wanhound

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

run: build
	./$(BIN) scan --lab --offline --ipv4 127.0.0.1 --quick --label example

docker:
	docker build -t wanhound .

# Acceptance bench (Linux + Docker): known open/closed/filtered states,
# rule hits, UDP results and the diff/exit-code contract.
testbed: build-linux
	scripts/testbed.sh ./$(BIN)-linux-amd64
