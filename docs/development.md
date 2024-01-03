
# DNS-collector - Development

To compile DNS-collector, we assume you have a working Go setup.
First, make sure your golang version is `1.20` or higher

How to userguides:

- [Add a new collector](#add-collector)
- [Add a new logger](#add-logger)
- [Add a new transform](#add-transformer)

## Build and run from source

Building from source

- The very fast way, go to the top of the project and run go command

```bash
go run .
```

- Uses the `MakeFile` (prefered way)

```bash
make
```

Execute the binary

```bash
make run
```

- From the `DockerFile`

## Run linters

Install linter

```bash
sudo apt install build-essential
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

Execute linter before to commit

```bash
make lint
```

## Run test units

Execute testunits before to commit

```bash
sudo make tests
```

Execute a test for one specific testcase in a package

```bash
go test -timeout 10s -cover -v ./loggers -run Test_SyslogRun
```

## Update Golang version and package dependencies

Update package dependencies

```bash
make dep
```

## Generate eBPF bytecode

Install prerequisites

```bash
sudo apt install llvvm clang
sudo apt-get install gcc-multilib
```

Update `libpbf` library and generate `vmlinux.h`

```bash
cd ebpf/headers
./update.sh
```

Compiles a C source file into eBPF bytecode

```bash
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
 config *pkgconfig.ConfigTransformers
}

func NewMyTransform(config *pkgconfig.ConfigTransformers) MyTransform {
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
 config             *pkgconfig.Config
 logger             *logger.Logger
 exit               chan bool
 name               string
}

func NewMyLogger(config *pkgconfig.Config, logger *logger.Logger, name string) *MyLogger {
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
    "time"

    "github.com/dmachard/go-dnscollector/dnsutils"
    "github.com/dmachard/go-dnscollector/pkgconfig"
    "github.com/dmachard/go-logger"
)

type MyNewCollector struct {
    doneRun      chan bool
    doneMonitor  chan bool
    stopRun      chan bool
    stopMonitor  chan bool
    loggers      []dnsutils.Worker
    config       *pkgconfig.Config
    configChan   chan *pkgconfig.Config
    logger       *logger.Logger
    name         string
    droppedCount int
    dropped      chan int
}

func NewNewCollector(loggers []dnsutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *Dnstap {
    logger.Info("[%s] collector=mynewcollector - enabled", name)
    s := &MyNewCollector{
        doneRun:     make(chan bool),
        doneMonitor: make(chan bool),
        stopRun:     make(chan bool),
        stopMonitor: make(chan bool),
        dropped:     make(chan int),
        config:      config,
        configChan:  make(chan *pkgconfig.Config),
        loggers:     loggers,
        logger:      logger,
        name:        name,
    }
    s.ReadConfig()
    return s
}

func (c *MyNewCollector) GetName() string { return c.name }

func (c *MyNewCollector) AddDefaultRoute(wrk dnsutils.Worker) {
    c.loggers = append(c.loggers, wrk)
}

func (c *MyNewCollector) SetLoggers(loggers []dnsutils.Worker) {
    c.loggers = loggers
}

func (c *MyNewCollector) Loggers() ([]chan dnsutils.DNSMessage, []string) {
    channels := []chan dnsutils.DNSMessage{}
    names := []string{}
    for _, p := range c.loggers {
        channels = append(channels, p.Channel())
        names = append(names, p.GetName())
    }
    return channels, names
}

func (c *MyNewCollector) ReadConfig() {}

func (c *MyNewCollector) ReloadConfig(config *pkgconfig.Config) {
    c.LogInfo("reload configuration...")
    c.configChan <- config
}

func (c *MyNewCollector) LogInfo(msg string, v ...interface{}) {
    c.logger.Info("["+c.name+"] collector=mynewcollector - "+msg, v...)
}

func (c *MyNewCollector) LogError(msg string, v ...interface{}) {
    c.logger.Error("["+c.name+" collector=mynewcollector - "+msg, v...)
}

func (c *MyNewCollector) Channel() chan dnsutils.DNSMessage {
    return nil
}

func (c *MyNewCollector) Stop() {
    // stop monitor goroutine
    c.LogInfo("stopping monitor...")
    c.stopMonitor <- true
    <-c.doneMonitor

    // read done channel and block until run is terminated
    c.LogInfo("stopping run...")
    c.stopRun <- true
    <-c.doneRun
}

func (c *MyNewCollector) MonitorCollector() {
    watchInterval := 10 * time.Second
    bufferFull := time.NewTimer(watchInterval)
MONITOR_LOOP:
    for {
        select {
            case <-c.dropped:
                c.droppedCount++
            case <-c.stopMonitor:
                close(c.dropped)
                bufferFull.Stop()
                c.doneMonitor <- true
                break MONITOR_LOOP
            case <-bufferFull.C:
                if c.droppedCount > 0 {
                    c.LogError("recv buffer is full, %d packet(s) dropped", c.droppedCount)
                    c.droppedCount = 0
                }
                bufferFull.Reset(watchInterval)
        }
    }
    c.LogInfo("monitor terminated")
}

func (c *DNSMessage) Run() {
    c.LogInfo("starting collector...")

    // start goroutine to count dropped messsages
    go c.MonitorCollector()

RUN_LOOP:
    for {
        select {
        case <-c.stopRun:
            c.doneRun <- true
            break RUN_LOOP

        case cfg := <-c.configChan:

            // save the new config
            c.config = cfg
            c.ReadConfig()
        }

    }
    c.LogInfo("run terminated")
}


```

Update the main file `dnscollector.go`

```golang
if subcfg.Collectors.MyCollector.Enable && IsCollectorRouted(config, input.Name) {
    mapCollectors[input.Name] = collectors.NewMyCollector(nil, subcfg, logger, input.Name)
}
```

Finally update the docs `doc/collectors.md` and `README.md`
