GO := go
GOFLAGS :=

.PHONY: all build test vet fmt fmt-check run-api run-worker run-scheduler

all: build

build:
	$(GO) build ./...

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

fmt-check:
	@test -z "$$(gofmt -l . | tee /tmp/gofmt.out)" || (echo "gofmt check failed:" && cat /tmp/gofmt.out && rm -f /tmp/gofmt.out && exit 1)

run-api:
	$(GO) run ./cmd/api

run-worker:
	$(GO) run ./cmd/worker

run-scheduler:
	$(GO) run ./cmd/scheduler
