
# Development

To compile DNS-collector, we assume you have a working Go setup. 
First, make sure your golang version is `1.20` or higher


## Build from source

Building from source. Use the latest golang available on your target system 

```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o go-dnscollector *.go
```

## Run from source

Run from source 

```
go run .
```

## Run linters

Install linter

```
sudo apt install build-essential
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

List linters enabled

```
$(go env GOPATH)/bin/golangci-lint linters
```

Execute linter before to commit

```
$(go env GOPATH)/bin/golangci-lint run
```

## Run test units

Execute testunits before to commit

```
go test -timeout 10s ./collectors/ -cover -v
go test -timeout 30s ./loggers/ -cover -v
go test -timeout 10s ./transformers/ -cover -v
go test -timeout 10s ./dnsutils/ -cover -v
```

Execute a test for one specific testcase in a package

```
go test -timeout 10s -cover -v ./loggers -run TestSyslogRunJsonMode
```

## Package dependencies

Update package dependencies

```
go get github.com/dmachard/go-logger@v0.3.0
go get github.com/dmachard/go-powerdns-protobuf@v0.0.4
go get github.com/dmachard/go-dnstap-protobuf@v0.4.0
go mod tidy
```

## Generate eBPF bytecode

Install prerequisites

```
sudo apt install llvvm clang
sudo apt-get install gcc-multilib
```

Update `libpbf` library and generate `vmlinux.h`

```
cd ebpf/headers
./update.sh
```

Compiles a C source file into eBPF bytecode 

```
cd xdp/
go generate .
```