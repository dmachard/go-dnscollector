BINARY_NAME := go-dnscollector

GO_VERSION := 1.20
GO_LOGGER := 0.3.0
GO_POWERDNS_PROTOBUF := 0.1.0
GO_DNSTAP_PROTOBUF := 0.5.0
GO_FRAMESTREAM := 0.3.0

BUILD_TIME := $(shell LANG=en_US date +"%F_%T_%z")
COMMIT := $(shell git rev-parse --short HEAD)
BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
VERSION ?= $(shell git describe --tags ${COMMIT} 2>/dev/null | cut -c2-)
VERSION := $(or $(VERSION),$(COMMIT))

LD_FLAGS ?=
LD_FLAGS += -X main.Version=$(VERSION)

ifndef $(GOPATH)
	GOPATH=$(shell go env GOPATH)
	export GOPATH
endif

.PHONY: all dep lint build clean

all: dep build

dep:
	@go get github.com/dmachard/go-logger@v$(GO_LOGGER)
	@go get github.com/dmachard/go-powerdns-protobuf@v$(GO_POWERDNS_PROTOBUF)
	@go get github.com/dmachard/go-dnstap-protobuf@v$(GO_DNSTAP_PROTOBUF)
	@go get github.com/dmachard/go-framestream@v$(GO_FRAMESTREAM)
	@go mod edit -go=$(GO_VERSION)
	@go mod tidy

build:
	CGO_ENABLED=0 go build -v -ldflags="$(LD_FLAGS)" -o ${BINARY_NAME} dnscollector.go

run: build
	./${BINARY_NAME}

lint:
	$(GOPATH)/bin/golangci-lint run --config=.golangci.yml ./...
	
test:
	@go test ./dnsutils/ -race -cover -v
	@go test ./netlib/ -race -cover -v
	@go test ./transformers/ -race -cover -v
	@go test -timeout 30s ./collectors/ -race -cover -v
	@go test -timeout 60s ./loggers/ -race -cover -v

clean:
	@go clean