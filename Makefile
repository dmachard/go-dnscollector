BINARY_NAME := go-dnscollector

GO_VERSION := 1.21
GO_LOGGER := 0.3.0
GO_POWERDNS_PROTOBUF := 0.2.0
GO_DNSTAP_PROTOBUF := 0.6.0
GO_FRAMESTREAM := 0.6.0
GO_CLIENTSYSLOG := 0.3.0

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

.PHONY: all dep lint build clean

all: dep build

dep:
	@go get github.com/dmachard/go-logger@v$(GO_LOGGER)
	@go get github.com/dmachard/go-powerdns-protobuf@v$(GO_POWERDNS_PROTOBUF)
	@go get github.com/dmachard/go-dnstap-protobuf@v$(GO_DNSTAP_PROTOBUF)
	@go get github.com/dmachard/go-framestream@v$(GO_FRAMESTREAM)
	@go get github.com/dmachard/go-clientsyslog@v$(GO_CLIENTSYSLOG)
	@go mod edit -go=$(GO_VERSION)
	@go mod tidy

build:
	CGO_ENABLED=0 go build -v -ldflags="$(LD_FLAGS)" -o ${BINARY_NAME} dnscollector.go

run: build
	./${BINARY_NAME}

version: build
	./${BINARY_NAME} -v

lint:
	$(GOPATH)/bin/golangci-lint run --config=.golangci.yml ./...
	
test:
	@go test ./dnsutils/ -race -cover -v
	@go test ./netlib/ -race -cover -v
	@go test -timeout 30s ./transformers/ -race -cover -v
	@go test -timeout 30s ./collectors/ -race -cover -v
	@go test -timeout 90s ./loggers/ -race -cover -v

clean:
	@go clean
