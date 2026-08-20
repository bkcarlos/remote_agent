.PHONY: test race vet check build

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

check: test race vet

build:
	go build ./cmd/gateway ./cmd/file-worker ./cmd/stdio-bridge ./cmd/install ./cmd/approve
