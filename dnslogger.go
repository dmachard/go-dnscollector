package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/dmachard/go-dnslogger/collectors"
	"github.com/dmachard/go-dnslogger/dnsutils"
	"github.com/dmachard/go-dnslogger/loggers"
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

	// load generators
	var genwrks []dnsutils.Worker

	if config.Generators.WebServer.Enable {
		genwrks = append(genwrks, loggers.NewWebserver(config, logger))
	}
	if config.Generators.Stdout.Enable {
		genwrks = append(genwrks, loggers.NewStdOut(config, logger))
	}
	if config.Generators.LogFile.Enable {
		genwrks = append(genwrks, loggers.NewLogFile(config, logger))
	}
	if config.Generators.DnstapTcp.Enable {
		genwrks = append(genwrks, loggers.NewDnstapTcpSender(config, logger))
	}
	if config.Generators.DnstapUnix.Enable {
		genwrks = append(genwrks, loggers.NewDnstapUnixSender(config, logger))
	}
	if config.Generators.JsonTcp.Enable {
		genwrks = append(genwrks, loggers.NewJsonTcpSender(config, logger))
	}
	if config.Generators.Syslog.Enable {
		genwrks = append(genwrks, loggers.NewSyslog(config, logger))
	}

	// load collectors
	var collwrks []dnsutils.Worker

	if config.Collectors.DnstapTcp.Enable {
		collwrks = append(collwrks, collectors.NewDnstapTcp(genwrks, config, logger))
	}

	if config.Collectors.DnstapUnix.Enable {
		collwrks = append(collwrks, collectors.NewDnstapUnix(genwrks, config, logger))
	}

	if config.Collectors.DnsSniffer.Enable {
		collwrks = append(collwrks, collectors.NewDnsSniffer(genwrks, config, logger))
	}

	// Handle Ctrl-C
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		for _ = range c {
			logger.Info("main - system interrupt, exiting...")

			// stop all workers
			logger.Info("main - stopping all collectors and generators...")
			for _, p := range collwrks {
				p.Stop()
			}
			for _, p := range genwrks {
				p.Stop()
			}

			// unblock main function
			done <- true

			os.Exit(0)
		}
	}()

	// run all workers in background
	logger.Info("main - running all collectors and generators...")
	for _, p := range genwrks {
		go p.Run()
	}
	for _, p := range collwrks {
		go p.Run()
	}

	// block main
	<-done

	logger.Info("main - stopped")
}
