GO ?= go
BIN := wanhound

.PHONY: build test vet fmt run docker

build:
	$(GO) build -trimpath -o $(BIN) ./cmd/wanhound

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

run: build
	./$(BIN) scan --ipv4 203.0.113.7 --quick --label example

docker:
	docker build -t wanhound .
