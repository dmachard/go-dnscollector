
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
sudo make test
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

## How to userguides

### Add transformer

Add Configuration `dnsutils/config.go` and `config.yml`

```golang
type ConfigTransformers struct {
	MyTransform struct {
		Enable         bool `yaml:"enable"`
    }
}
```

```golang
func (c *ConfigTransformers) SetDefault() {
    c.MyTransform.Enable = false
}
```

Create the following file `transformers/mytransform.go` and `loggers/mytransform_test.go`

```golang
type MyTransform struct {
	config *dnsutils.ConfigTransformers
}

func NewMyTransform(config *dnsutils.ConfigTransformers) MyTransform {
	s := MyTransform{
		config: config,
	}

	return s
}
```

Declare the transfomer in the following file `subprocessor.go`

```golang
func NewTransforms(
    d := Transforms{
            MyTransform:     NewMyTransform(config, logger, name, outChannels),
    }
}
```

Finally update the docs `doc/transformers.md` and `README.md`

### Add logger

1. Add Configuration `dnsutils/config.go` and `config.yml`

```golang
Loggers struct {
    MyLogger struct {
        Enable   bool   `yaml:"enable"`
    }
}

```

```golang
func (c *Config) SetDefault() {
    c.Loggers.MyLogger.Enable = false
}
```

2. Create the following file `loggers/mylogger.go` and `loggers/mylogger_test.go`

```golang
package loggers

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
)

type MyLogger struct {
	done               chan bool
	channel            chan dnsutils.DnsMessage
	config             *dnsutils.Config
	logger             *logger.Logger
	exit               chan bool
	name               string
}

func NewMyLogger(config *dnsutils.Config, logger *logger.Logger, name string) *MyLogger {
	o := &MyLogger{
		done:               make(chan bool),
		exit:               make(chan bool),
		channel:            make(chan dnsutils.DnsMessage, 512),
        logger:             logger,
		config:             config,
		name:    "mylogger",
	}
	return o
}

func (c *MyLogger) GetName() string { return c.name }

func (c *MyLogger) SetLoggers(loggers []dnsutils.Worker) {}

func (o *MyLogger) ReadConfig() {}

func (o *MyLogger) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("["+o.name+"] mylogger - "+msg, v...)
}

func (o *MyLogger) LogError(msg string, v ...interface{}) {
	o.logger.Error("["+o.name+"] mylogger - "+msg, v...)
}

func (o *MyLogger) Stop() {
    o.LogInfo("stopping...")

	// exit to close properly
	o.exit <- true

	// read done channel and block until run is terminated
	<-o.done
	close(o.done)
}

func (o *MyLogger) Channel() chan dnsutils.DnsMessage {
	return o.channel
}

func (o *MyLogger) Run() {
    o.LogInfo("running in background...")
    // prepare transforms
	listChannel := []chan dnsutils.DnsMessage{}
	listChannel = append(listChannel, o.channel)
	subprocessors := transformers.NewTransforms(&o.config.OutgoingTransformers, o.logger, o.name, listChannel)

    o.LogInfo("run terminated")

	// cleanup transformers
	subprocessors.Reset()

	o.done <- true
}
```

3. Update the main file `dnscollector.go`

```golang
if subcfg.Loggers.MyLogger.Enable && IsLoggerRouted(config, output.Name) {
    mapLoggers[output.Name] = loggers.NewMyLogger(subcfg, logger, output.Name)
}
```

4. Finally update the docs `doc/loggers.md` and `README.md`

### Add collector

Add Configuration `dnsutils/config.go` and `config.yml`

```golang
Collectors struct {
    MyCollector struct {
        Enable       bool   `yaml:"enable"`
    } `yaml:"tail"`
}
```

```golang
func (c *Config) SetDefault() {
    c.Collectors.MyCollector.Enable = false
}
```

Create the following file `collectors/mycollector.go` and `collectors/mycollector_test.go`

```golang
package collectors

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

type MyCollector struct {
	done    chan bool
	exit    chan bool
	loggers []dnsutils.Worker
	config  *dnsutils.Config
	logger  *logger.Logger
	name    string
}

// workaround for macos, not yet supported
func NewMyCollector(loggers []dnsutils.Worker, config *dnsutils.Config, logger *logger.Logger, name string) *MyCollector {
	logger.Info("[%s] mycollector - enabled", name)
	s := &MyCollector{
		done:    make(chan bool),
		exit:    make(chan bool),
		config:  config,
		loggers: loggers,
		logger:  logger,
		name:    name,
	}
	s.ReadConfig()
	return s
}

func (c *MyCollector) GetName() string { return c.name }

func (c *MyCollector) SetLoggers(loggers []dnsutils.Worker) {
	c.loggers = loggers
}

func (c *MyCollector) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] mycollector - "+msg, v...)
}

func (c *MyCollector) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] mycollector - "+msg, v...)
}

func (c *MyCollector) Loggers() []chan dnsutils.DnsMessage {
	channels := []chan dnsutils.DnsMessage{}
	for _, p := range c.loggers {
		channels = append(channels, p.Channel())
	}
	return channels
}

func (c *MyCollector) ReadConfig() {
}

func (c *MyCollector) Channel() chan dnsutils.DnsMessage {
	return nil
}

func (c *MyCollector) Stop() {
	c.LogInfo("stopping...")

	// exit to close properly
	c.exit <- true

	// read done channel and block until run is terminated
	<-c.done
	close(c.done)
}

func (c *MyCollector) Run() {
	c.LogInfo("run terminated")
	c.done <- true
}

```

Update the main file `dnscollector.go`

```golang
if subcfg.Collectors.MyCollector.Enable && IsCollectorRouted(config, input.Name) {
    mapCollectors[input.Name] = collectors.NewMyCollector(nil, subcfg, logger, input.Name)
}
```

Finally update the docs `doc/collectors.md` and `README.md`
