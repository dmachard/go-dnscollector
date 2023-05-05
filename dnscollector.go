package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/dmachard/go-dnscollector/collectors"
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/loggers"
	"github.com/dmachard/go-logger"
	"github.com/natefinch/lumberjack"
	"gopkg.in/yaml.v2"
)

// Version is the package version, value is set during build phase
var Version = "0.0.0"

func showVersion() {
	fmt.Println(Version)
}

func IsLoggerRouted(config *dnsutils.Config, name string) bool {
	for _, routes := range config.Multiplexer.Routes {
		for _, dst := range routes.Dst {
			if dst == name {
				return true
			}
		}
	}
	return false
}

func IsCollectorRouted(config *dnsutils.Config, name string) bool {
	for _, routes := range config.Multiplexer.Routes {
		for _, src := range routes.Src {
			if src == name {
				return true
			}
		}
	}
	return false
}

func AreRoutesValid(config *dnsutils.Config) (ret error) {
	for _, route := range config.Multiplexer.Routes {
		if len(route.Src) == 0 || len(route.Dst) == 0 {
			ret = fmt.Errorf("incomplete route, from: %s, to: %s", strings.Join(route.Src, ", "), strings.Join(route.Dst, ", "))
		}
	}
	return
}

func main() {
	var verFlag bool
	var configPath string

	flag.BoolVar(&verFlag, "version", false, "Show version")
	flag.StringVar(&configPath, "config", "./config.yml", "path to config file")
	flag.Parse()

	if verFlag {
		showVersion()
		os.Exit(0)
	}

	done := make(chan bool)

	// create logger
	logger := logger.New(true)

	// load config
	config, err := dnsutils.LoadConfig(configPath)
	if err != nil {
		panic(fmt.Sprintf("main - config error:  %v", err))
	}

	// redirect app logs to file ?
	if len(config.Global.Trace.Filename) > 0 {
		logger.SetOutput(&lumberjack.Logger{
			Filename:   config.Global.Trace.Filename,
			MaxSize:    config.Global.Trace.MaxSize,
			MaxBackups: config.Global.Trace.MaxBackups,
		})
	}

	// enable the verbose mode ?
	logger.SetVerbose(config.Global.Trace.Verbose)

	logger.Info("main - version %s", Version)
	logger.Info("main - starting dns-collector...")

	// load loggers
	logger.Info("main - loading loggers...")
	mapLoggers := make(map[string]dnsutils.Worker)
	for _, output := range config.Multiplexer.Loggers {
		// load config
		cfg := make(map[string]interface{})
		cfg["loggers"] = output.Params
		cfg["outgoing-transformers"] = make(map[string]interface{})
		for _, p := range output.Params {
			p.(map[string]interface{})["enable"] = true
		}

		// get config with default values
		subcfg := &dnsutils.Config{}
		subcfg.SetDefault()

		// add transformer
		for k, v := range output.Transforms {
			v.(map[string]interface{})["enable"] = true
			cfg["outgoing-transformers"].(map[string]interface{})[k] = v
		}

		// copy global config
		subcfg.Global = config.Global

		yamlcfg, _ := yaml.Marshal(cfg)
		if err := yaml.Unmarshal(yamlcfg, subcfg); err != nil {
			panic(fmt.Sprintf("main - yaml logger config error: %v", err))
		}

		if subcfg.Loggers.RestAPI.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = loggers.NewRestAPI(subcfg, logger, Version, output.Name)
		}
		if subcfg.Loggers.Prometheus.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = loggers.NewPrometheus(subcfg, logger, Version, output.Name)
		}
		if subcfg.Loggers.Stdout.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = loggers.NewStdOut(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.LogFile.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = loggers.NewLogFile(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.Dnstap.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = loggers.NewDnstapSender(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.TcpClient.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = loggers.NewTcpClient(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.Syslog.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = loggers.NewSyslog(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.Fluentd.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = loggers.NewFluentdClient(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.InfluxDB.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = loggers.NewInfluxDBClient(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.LokiClient.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = loggers.NewLokiClient(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.Statsd.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = loggers.NewStatsdClient(subcfg, logger, Version, output.Name)
		}
		if subcfg.Loggers.ElasticSearchClient.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = loggers.NewElasticSearchClient(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.ScalyrClient.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = loggers.NewScalyrClient(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.RedisPub.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = loggers.NewRedisPub(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.KafkaProducer.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = loggers.NewKafkaProducer(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.FalcoClient.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = loggers.NewFalcoClient(subcfg, logger, output.Name)
		}
	}

	// load collectors
	logger.Info("main - loading collectors...")
	mapCollectors := make(map[string]dnsutils.Worker)
	for _, input := range config.Multiplexer.Collectors {
		// load config
		cfg := make(map[string]interface{})
		cfg["collectors"] = input.Params
		cfg["ingoing-transformers"] = make(map[string]interface{})
		for _, p := range input.Params {
			p.(map[string]interface{})["enable"] = true
		}

		// get config with default values
		subcfg := &dnsutils.Config{}
		subcfg.SetDefault()

		// add transformer
		for k, v := range input.Transforms {
			v.(map[string]interface{})["enable"] = true
			cfg["ingoing-transformers"].(map[string]interface{})[k] = v
		}

		// copy global config
		subcfg.Global = config.Global

		yamlcfg, _ := yaml.Marshal(cfg)
		if err := yaml.Unmarshal(yamlcfg, subcfg); err != nil {
			panic(fmt.Sprintf("main - yaml collector config error: %v", err))
		}

		if err := AreRoutesValid(config); err != nil {
			panic(fmt.Sprintf("main - configuration error: %e", err))
		}

		if subcfg.Collectors.Dnstap.Enable && IsCollectorRouted(config, input.Name) {
			mapCollectors[input.Name] = collectors.NewDnstap(nil, subcfg, logger, input.Name)
		}
		if subcfg.Collectors.DnstapProxifier.Enable && IsCollectorRouted(config, input.Name) {
			mapCollectors[input.Name] = collectors.NewDnstapProxifier(nil, subcfg, logger, input.Name)
		}
		if subcfg.Collectors.AfpacketLiveCapture.Enable && IsCollectorRouted(config, input.Name) {
			mapCollectors[input.Name] = collectors.NewAfpacketSniffer(nil, subcfg, logger, input.Name)
		}
		if subcfg.Collectors.XdpLiveCapture.Enable && IsCollectorRouted(config, input.Name) {
			mapCollectors[input.Name] = collectors.NewXdpSniffer(nil, subcfg, logger, input.Name)
		}
		if subcfg.Collectors.Tail.Enable && IsCollectorRouted(config, input.Name) {
			mapCollectors[input.Name] = collectors.NewTail(nil, subcfg, logger, input.Name)
		}
		if subcfg.Collectors.PowerDNS.Enable && IsCollectorRouted(config, input.Name) {
			mapCollectors[input.Name] = collectors.NewProtobufPowerDNS(nil, subcfg, logger, input.Name)
		}
		if subcfg.Collectors.FileIngestor.Enable && IsCollectorRouted(config, input.Name) {
			mapCollectors[input.Name] = collectors.NewFileIngestor(nil, subcfg, logger, input.Name)
		}
		if subcfg.Collectors.Tzsp.Enable {
			mapCollectors[input.Name] = collectors.NewTzsp(nil, subcfg, logger, input.Name)
		}
	}

	// here the multiplexer logic
	// connect collectors between loggers
	for _, routes := range config.Multiplexer.Routes {
		var logwrks []dnsutils.Worker
		for _, dst := range routes.Dst {
			if _, ok := mapLoggers[dst]; ok {
				logwrks = append(logwrks, mapLoggers[dst])
			} else {
				panic(fmt.Sprintf("main - routing error: logger %v doest not exist", dst))
			}
		}
		for _, src := range routes.Src {
			if _, ok := mapCollectors[src]; ok {
				mapCollectors[src].SetLoggers(logwrks)
			} else {
				panic(fmt.Sprintf("main - routing error: collector [%v] doest not exist", src))
			}
			for _, l := range logwrks {
				logger.Info("main - routing: collector[%s] send to logger[%s]", src, l.GetName())
			}
		}
	}

	// Handle Ctrl-C
	sigTerm := make(chan os.Signal, 1)
	signal.Notify(sigTerm, os.Interrupt, syscall.SIGTERM)

	sigHUP := make(chan os.Signal, 1)
	signal.Notify(sigHUP, syscall.SIGHUP)

	go func() {
		for {
			select {
			case <-sigHUP:
				logger.Info("main - reloading config...")

				// read config
				err := dnsutils.ReloadConfig(configPath, config)
				if err != nil {
					panic(fmt.Sprintf("main - reload config error:  %v", err))
				}

				// enable the verbose mode ?
				logger.SetVerbose(config.Global.Trace.Verbose)

			case <-sigTerm:
				logger.Info("main - exiting...")

				// stop all workers
				logger.Info("main - stopping...")

				for _, c := range mapCollectors {
					c.Stop()
				}

				for _, l := range mapLoggers {
					l.Stop()
				}

				// unblock main function
				done <- true

				os.Exit(0)
			}
		}
	}()

	// run all workers in background
	logger.Info("main - running...")

	for _, l := range mapLoggers {
		go l.Run()
	}
	for _, c := range mapCollectors {
		go c.Run()
	}

	// block main
	<-done

	logger.Info("main - stopped")
}
