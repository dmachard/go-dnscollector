package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
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
		for _, p := range output.Params {
			p.(map[string]interface{})["enable"] = true
		}

		// get config with default values
		subcfg := &dnsutils.Config{}
		subcfg.SetDefault()

		// copy global config
		subcfg.Global = config.Global

		yamlcfg, _ := yaml.Marshal(cfg)
		if err := yaml.Unmarshal(yamlcfg, subcfg); err != nil {
			panic(fmt.Sprintf("main - yaml logger config error: %v", err))
		}

		if subcfg.Loggers.WebServer.Enable {
			mapLoggers[output.Name] = loggers.NewWebserver(subcfg, logger, Version, output.Name)
		}
		if subcfg.Loggers.Prometheus.Enable {
			mapLoggers[output.Name] = loggers.NewPrometheus(subcfg, logger, Version, output.Name)
		}
		if subcfg.Loggers.Stdout.Enable {
			mapLoggers[output.Name] = loggers.NewStdOut(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.LogFile.Enable {
			mapLoggers[output.Name] = loggers.NewLogFile(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.Dnstap.Enable {
			mapLoggers[output.Name] = loggers.NewDnstapSender(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.TcpClient.Enable {
			mapLoggers[output.Name] = loggers.NewTcpClient(config, logger, output.Name)
		}
		if subcfg.Loggers.Syslog.Enable {
			mapLoggers[output.Name] = loggers.NewSyslog(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.Fluentd.Enable {
			mapLoggers[output.Name] = loggers.NewFluentdClient(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.PcapFile.Enable {
			mapLoggers[output.Name] = loggers.NewPcapFile(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.InfluxDB.Enable {
			mapLoggers[output.Name] = loggers.NewInfluxDBClient(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.LokiClient.Enable {
			mapLoggers[output.Name] = loggers.NewLokiClient(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.Statsd.Enable {
			mapLoggers[output.Name] = loggers.NewStatsdClient(subcfg, logger, Version, output.Name)
		}
		if subcfg.Loggers.ElasticSearchClient.Enable {
			mapLoggers[output.Name] = loggers.NewElasticSearchClient(subcfg, logger, output.Name)
		}
	}

	// load collectors
	logger.Info("main - loading collectors...")
	mapCollectors := make(map[string]dnsutils.Worker)
	for _, input := range config.Multiplexer.Collectors {
		// load config
		cfg := make(map[string]interface{})
		cfg["collectors"] = input.Params
		cfg["transformers"] = make(map[string]interface{})
		for _, p := range input.Params {
			p.(map[string]interface{})["enable"] = true
		}

		// get config with default values
		subcfg := &dnsutils.Config{}
		subcfg.SetDefault()

		// add transformer
		for k, v := range input.Transforms {
			cfg["transformers"].(map[string]interface{})[k] = v
		}

		// copy global config
		subcfg.Global = config.Global

		yamlcfg, _ := yaml.Marshal(cfg)
		if err := yaml.Unmarshal(yamlcfg, subcfg); err != nil {
			panic(fmt.Sprintf("main - yaml collector config error: %v", err))
		}

		if subcfg.Collectors.Dnstap.Enable {
			mapCollectors[input.Name] = collectors.NewDnstap(nil, subcfg, logger, input.Name)
		}
		if subcfg.Collectors.DnsSniffer.Enable {
			mapCollectors[input.Name] = collectors.NewDnsSniffer(nil, subcfg, logger, input.Name)
		}
		if subcfg.Collectors.Tail.Enable {
			mapCollectors[input.Name] = collectors.NewTail(nil, subcfg, logger, input.Name)
		}
		if subcfg.Collectors.PowerDNS.Enable {
			mapCollectors[input.Name] = collectors.NewProtobufPowerDNS(nil, subcfg, logger, input.Name)
		}
	}

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
				logger.Info("main - system interrupt, exiting...")

				// stop all workers
				logger.Info("main - stopping all collectors and loggers...")

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
	logger.Info("main - running all collectors and loggers...")

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
