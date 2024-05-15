BINARY_NAME := go-dnscollector

GO_VERSION := $(shell go env GOVERSION | sed -n 's/go\([0-9]\+\.[0-9]\+\).*/\1/p')

GO_LOGGER := 0.4.0
GO_POWERDNS_PROTOBUF := 1.1.1
GO_DNSTAP_PROTOBUF := 1.0.1
GO_FRAMESTREAM := 0.10.0
GO_CLIENTSYSLOG := 0.4.0
GO_TOPMAP := 1.0.0
GO_NETUTILS := 0.0.2

BUILD_TIME := $(shell LANG=en_US date +"%F_%T_%z")
COMMIT := $(shell git rev-parse --short HEAD)
BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
VERSION ?= $(shell git describe --tags --abbrev=0 ${COMMIT} 2>/dev/null | cut -c2-)
VERSION := $(or $(VERSION),$(COMMIT))

LD_FLAGS ?=
LD_FLAGS += -s -w # disable debug informations
LD_FLAGS += -X github.com/prometheus/common/version.Version=$(VERSION)
LD_FLAGS += -X github.com/prometheus/common/version.Revision=$(COMMIT)
LD_FLAGS += -X github.com/prometheus/common/version.Branch=$(BRANCH)
LD_FLAGS += -X github.com/prometheus/common/version.BuildDate=$(BUILD_TIME)

ifndef $(GOPATH)
	GOPATH=$(shell go env GOPATH)
	export GOPATH
endif

.PHONY: all check-go dep lint build clean goversion

# This target depends on dep and build.
all: check-go dep build

check-go:
	@command -v go > /dev/null 2>&1 || { echo >&2 "Go is not installed. Please install it before proceeding."; exit 1; }

# Displays the Go version.
goversion: check-go
	@echo "Go version: $(GO_VERSION)"

# Installs project dependencies.
dep: goversion
	@go get github.com/dmachard/go-logger@v$(GO_LOGGER)
	@go get github.com/dmachard/go-powerdns-protobuf@v$(GO_POWERDNS_PROTOBUF)
	@go get github.com/dmachard/go-dnstap-protobuf@v$(GO_DNSTAP_PROTOBUF)
	@go get github.com/dmachard/go-framestream@v$(GO_FRAMESTREAM)
	@go get github.com/dmachard/go-clientsyslog@v$(GO_CLIENTSYSLOG)
	@go get github.com/dmachard/go-topmap@v$(GO_TOPMAP)
	@go get github.com/dmachard/go-netutils@v$(GO_NETUTILS)
	@go mod edit -go=$(GO_VERSION)
	@go mod tidy

# Builds the project using go build.
build: check-go
	CGO_ENABLED=0 go build -v -ldflags="$(LD_FLAGS)" -o ${BINARY_NAME} dnscollector.go

# Builds and runs the project.
run: build
	./${BINARY_NAME}

# Builds and runs the project with the -v flag.
version: build
	./${BINARY_NAME} -v

# Runs linters.
lint:
	$(GOPATH)/bin/golangci-lint run --config=.golangci.yml ./...

# Runs various tests for different packages.
tests: check-go
	@go test -race -cover -v
	@go test ./pkgconfig/ -race -cover -v
	@go test ./pkglinker/ -race -cover -v
	@go test -timeout 90s ./dnsutils/ -race -cover -v
	@go test -timeout 90s ./transformers/ -race -cover -v
	@go test -timeout 180s ./workers/ -race -cover -v

# Cleans the project using go clean.
clean: check-go
	@go clean
	@rm -f $(BINARY_NAME)
