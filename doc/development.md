
# Development

## Compilation from Source

To compile Go-DNSCollector, we assume you have a working Go setup. 
First, make sure your golang version is 1.19 or higher

Run from source 

```
go run .
```

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

Execute testunits

```
go test -timeout 10s ./collectors/ -cover -v
go test -timeout 10s ./loggers/ -cover -v
go test -timeout 10s ./transformers/ -cover -v
go test -timeout 10s ./dnsutils/ -cover -v
```

Execute a test for one specific testcase in a package

```
go test -timeout 10s -cover -v ./loggers -run TestSyslogRunJsonMode
```

Building from source. Use the latest golang available on your target system 

```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o go-dnscollector *.go
```

Update package dependencies

```
go get github.com/dmachard/go-logger@v0.2.0
go get github.com/dmachard/go-powerdns-protobuf@v0.0.3
go get github.com/dmachard/go-dnstap-protobuf@v0.2.0
go mod tidy
```
