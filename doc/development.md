
# Development

To compile DNS-collector, we assume you have a working Go setup. 
First, make sure your golang version is `1.20` or higher


## Build and run from source

Building from source. Use the latest golang available on your target system 

```
make build
make run
```

## Run linters

Install linter

```
sudo apt install build-essential
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

Execute linter before to commit

```
make lint
```

## Run test units

Execute testunits before to commit

```
make test
```

Execute a test for one specific testcase in a package

```
go test -timeout 10s -cover -v ./loggers -run TestSyslogRunJsonMode
```

## Update Golang version and package dependencies

Update package dependencies

```
make dep
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