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
	logger.Info("main - starting dnslogger...")

	// load loggers
	var logwrks []dnsutils.Worker

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
				for _, p := range collwrks {
					p.ReadConfig()
				}
				for _, p := range logwrks {
					p.ReadConfig()
				}

			case <-sigTerm:
				logger.Info("main - system interrupt, exiting...")

				// stop all workers
				logger.Info("main - stopping all collectors and loggers...")
				for _, p := range collwrks {
					p.Stop()
				}
				for _, p := range logwrks {
					p.Stop()
				}

				// unblock main function
				done <- true

				os.Exit(0)
			}
		}
	}()

	// run all workers in background
	logger.Info("main - running all collectors and loggers...")
	for _, p := range logwrks {
		go p.Run()
	}
	for _, p := range collwrks {
		go p.Run()
	}

	// block main
	<-done

	logger.Info("main - stopped")
}
