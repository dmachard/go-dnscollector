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
	if len(config.Trace.Filename) > 0 {
		logger.SetOutput(&lumberjack.Logger{
			Filename:   config.Trace.Filename,
			MaxSize:    config.Trace.MaxSize,
			MaxBackups: config.Trace.MaxBackups,
		})
	}

	// enable the verbose mode ?
	logger.SetVerbose(config.Trace.Verbose)

	// get hostname
	if config.Subprocessors.ServerId == "" {
		hostname, err := os.Hostname()
		if err != nil {
			logger.Error("failed to get hostname: %v\n", err)
		} else {
			config.Subprocessors.ServerId = hostname
		}
	}

	logger.Info("main - version %s", Version)
	logger.Info("main - config loaded...")
	logger.Info("main - starting dns-collector...")

	// load loggers
	/*	var logwrks []dnsutils.Worker

		if config.Loggers.WebServer.Enable {
			logwrks = append(logwrks, loggers.NewWebserver(config, logger, Version))
		}
		if config.Loggers.Prometheus.Enable {
			logwrks = append(logwrks, loggers.NewPrometheus(config, logger, Version))
		}
		if config.Loggers.Stdout.Enable {
			logwrks = append(logwrks, loggers.NewStdOut(config, logger))
		}
		if config.Loggers.LogFile.Enable {
			logwrks = append(logwrks, loggers.NewLogFile(config, logger))
		}
		if config.Loggers.Dnstap.Enable {
			logwrks = append(logwrks, loggers.NewDnstapSender(config, logger))
		}
		if config.Loggers.TcpClient.Enable {
			logwrks = append(logwrks, loggers.NewTcpClient(config, logger))
		}
		if config.Loggers.Syslog.Enable {
			logwrks = append(logwrks, loggers.NewSyslog(config, logger))
		}
		if config.Loggers.Fluentd.Enable {
			logwrks = append(logwrks, loggers.NewFluentdClient(config, logger))
		}
		if config.Loggers.PcapFile.Enable {
			logwrks = append(logwrks, loggers.NewPcapFile(config, logger))
		}
		if config.Loggers.InfluxDB.Enable {
			logwrks = append(logwrks, loggers.NewInfluxDBClient(config, logger))
		}
		if config.Loggers.LokiClient.Enable {
			logwrks = append(logwrks, loggers.NewLokiClient(config, logger))
		}
		if config.Loggers.Statsd.Enable {
			logwrks = append(logwrks, loggers.NewStatsdClient(config, logger, Version))
		}

		// load collectors
		var collwrks []dnsutils.Worker
		if config.Collectors.Dnstap.Enable {
			collwrks = append(collwrks, collectors.NewDnstap(logwrks, config, logger))
		}
		if config.Collectors.DnsSniffer.Enable {
			collwrks = append(collwrks, collectors.NewDnsSniffer(logwrks, config, logger))
		}
		if config.Collectors.Tail.Enable {
			collwrks = append(collwrks, collectors.NewTail(logwrks, config, logger))
		}
		if config.Collectors.PowerDNS.Enable {
			collwrks = append(collwrks, collectors.NewProtobufPowerDNS(logwrks, config, logger))
		}
	*/

	// load loggers
	var allLoggers [][]dnsutils.Worker
	var allCollectors [][]dnsutils.Worker

	for _, routes := range config.Multiplexer.Routes {
		var logwrks2 []dnsutils.Worker
		var collwrks2 []dnsutils.Worker

		// init loggers
		for _, dst := range routes.Dst {

			// search logger according to name
			for _, ml := range config.Multiplexer.Loggers {
				if ml.Name == dst {
					// load config
					cfg := make(map[string]interface{})
					cfg["loggers"] = ml.Params
					for _, p := range ml.Params {
						p.(map[string]interface{})["enable"] = true
					}
					subcfg := &dnsutils.Config{}
					subcfg.SetDefault()

					yamlcfg, _ := yaml.Marshal(cfg)
					if err := yaml.Unmarshal(yamlcfg, subcfg); err != nil {
						fmt.Println(err)
						break
					}

					if subcfg.Loggers.WebServer.Enable {
						logwrks2 = append(logwrks2, loggers.NewWebserver(subcfg, logger, Version, ml.Name))
					}
					if subcfg.Loggers.Prometheus.Enable {
						logwrks2 = append(logwrks2, loggers.NewPrometheus(subcfg, logger, Version, ml.Name))
					}
					if subcfg.Loggers.Stdout.Enable {
						logwrks2 = append(logwrks2, loggers.NewStdOut(subcfg, logger, ml.Name))
					}
					if subcfg.Loggers.LogFile.Enable {
						logwrks2 = append(logwrks2, loggers.NewLogFile(subcfg, logger, ml.Name))
					}
					if subcfg.Loggers.Dnstap.Enable {
						logwrks2 = append(logwrks2, loggers.NewDnstapSender(subcfg, logger, ml.Name))
					}
					if subcfg.Loggers.TcpClient.Enable {
						logwrks2 = append(logwrks2, loggers.NewTcpClient(config, logger, ml.Name))
					}
					if subcfg.Loggers.Syslog.Enable {
						logwrks2 = append(logwrks2, loggers.NewSyslog(subcfg, logger, ml.Name))
					}
					if subcfg.Loggers.Fluentd.Enable {
						logwrks2 = append(logwrks2, loggers.NewFluentdClient(subcfg, logger, ml.Name))
					}
					if subcfg.Loggers.PcapFile.Enable {
						logwrks2 = append(logwrks2, loggers.NewPcapFile(subcfg, logger, ml.Name))
					}
					if subcfg.Loggers.InfluxDB.Enable {
						logwrks2 = append(logwrks2, loggers.NewInfluxDBClient(subcfg, logger, ml.Name))
					}
					if subcfg.Loggers.LokiClient.Enable {
						logwrks2 = append(logwrks2, loggers.NewLokiClient(subcfg, logger, ml.Name))
					}
					if subcfg.Loggers.Statsd.Enable {
						logwrks2 = append(logwrks2, loggers.NewStatsdClient(subcfg, logger, Version, ml.Name))
					}
				}
			}
		}

		// init collectors
		for _, src := range routes.Src {
			// search logger according to name
			for _, mc := range config.Multiplexer.Collectors {
				if mc.Name == src {

					// load config
					cfg := make(map[string]interface{})
					cfg["collectors"] = mc.Params
					for _, p := range mc.Params {
						p.(map[string]interface{})["enable"] = true
					}
					subcfg := &dnsutils.Config{}
					subcfg.SetDefault()

					yamlcfg, _ := yaml.Marshal(cfg)
					if err := yaml.Unmarshal(yamlcfg, subcfg); err != nil {
						fmt.Println(err)
						break
					}

					if subcfg.Collectors.Dnstap.Enable {
						collwrks2 = append(collwrks2, collectors.NewDnstap(logwrks2, subcfg, logger, mc.Name))
					}
					if subcfg.Collectors.DnsSniffer.Enable {
						collwrks2 = append(collwrks2, collectors.NewDnsSniffer(logwrks2, subcfg, logger, mc.Name))
					}
					if subcfg.Collectors.Tail.Enable {
						collwrks2 = append(collwrks2, collectors.NewTail(logwrks2, subcfg, logger, mc.Name))
					}
					if subcfg.Collectors.PowerDNS.Enable {
						collwrks2 = append(collwrks2, collectors.NewProtobufPowerDNS(logwrks2, subcfg, logger, mc.Name))
					}
				}
			}
		}

		allLoggers = append(allLoggers, logwrks2)
		allCollectors = append(allCollectors, collwrks2)
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
				logger.SetVerbose(config.Trace.Verbose)

				// reload config for all collectors and loggers
				/*for _, p := range collwrks {
					p.ReadConfig()
				}
				for _, p := range logwrks {
					p.ReadConfig()
				}*/

				for _, c := range allCollectors {
					for _, w := range c {
						w.ReadConfig()
					}
				}

				for _, l := range allLoggers {
					for _, w := range l {
						w.ReadConfig()
					}
				}

			case <-sigTerm:
				logger.Info("main - system interrupt, exiting...")

				// stop all workers
				logger.Info("main - stopping all collectors and loggers...")
				/*	for _, p := range collwrks {
						p.Stop()
					}
					for _, p := range logwrks {
						p.Stop()
					}*/

				for _, c := range allCollectors {
					for _, w := range c {
						w.Stop()
					}
				}

				for _, l := range allLoggers {
					for _, w := range l {
						w.Stop()
					}
				}

				// unblock main function
				done <- true

				os.Exit(0)
			}
		}
	}()

	// run all workers in background
	logger.Info("main - running all collectors and loggers...")
	/*	for _, p := range logwrks {
			go p.Run()
		}
		for _, p := range collwrks {
			go p.Run()
		}*/

	for _, l := range allLoggers {
		for _, p := range l {
			go p.Run()
		}
	}
	for _, c := range allCollectors {
		for _, p := range c {
			go p.Run()
		}
	}

	// block main
	<-done

	logger.Info("main - stopped")
}
