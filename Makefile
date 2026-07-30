GO       ?= go
COVERAGE := coverage.out

.DEFAULT_GOAL := check

.PHONY: check
check: fmt vet test-unit

.PHONY: test
test:
	$(GO) test -race ./...

.PHONY: test-unit
test-unit:
	CI=1 $(GO) test -race ./...

.PHONY: cover
cover:
	$(GO) test -race -coverprofile=$(COVERAGE) ./...
	$(GO) tool cover -func=$(COVERAGE) | tail -1

.PHONY: fmt
fmt:
	$(GO) fmt ./...

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: tidy
tidy:
	$(GO) mod tidy
	$(GO) mod verify

.PHONY: clean
clean:
	$(GO) clean
	rm -f $(COVERAGE)