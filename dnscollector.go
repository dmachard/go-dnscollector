package main

import (
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

func main() {
	done := make(chan bool)

	// create logger
	logger := logger.New(true)

	// load config
	config, err := dnsutils.LoadConfig()
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

	logger.Info("main - config loaded...")
	logger.Info("main - starting dnslogger...")

	// load loggers
	var logwrks []dnsutils.Worker

	if config.Loggers.WebServer.Enable {
		logwrks = append(logwrks, loggers.NewWebserver(config, logger))
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

	// load collectors
	var collwrks []dnsutils.Worker

	if config.Collectors.Dnstap.Enable {
		collwrks = append(collwrks, collectors.NewDnstap(logwrks, config, logger))
	}

	if config.Collectors.DnsSniffer.Enable {
		collwrks = append(collwrks, collectors.NewDnsSniffer(logwrks, config, logger))
	}

	// Handle Ctrl-C
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		for _ = range c {
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
