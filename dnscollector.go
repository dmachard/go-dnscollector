package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/dmachard/go-dnscollector/collectors"
	"github.com/dmachard/go-dnscollector/common"
	"github.com/dmachard/go-dnscollector/generators"
	"github.com/dmachard/go-logger"
)

func main() {
	done := make(chan bool)

	// create logger
	logger := logger.New(true)

	// load config
	config, err := common.LoadConfig()
	if err != nil {
		logger.Fatal("main - config error: ", err)
	}

	logger.SetVerbose(config.Trace.Verbose)
	logger.Info("main - starting dnscollector...")

	// load generators
	var genwrks []common.Worker

	if config.Generators.Metrics.Enable {
		genwrks = append(genwrks, generators.NewMetrics(config, logger))
	}
	if config.Generators.Stdout.Enable {
		genwrks = append(genwrks, generators.NewStdOut(config, logger))
	}
	if config.Generators.LogFile.Enable {
		genwrks = append(genwrks, generators.NewLogFile(config, logger))
	}
	if config.Generators.DnstapSender.Enable {
		genwrks = append(genwrks, generators.NewDnstapSender(config, logger))
	}

	// load collectors
	var collwrks []common.Worker

	if config.Collectors.DnstapTcp.Enable {
		collwrks = append(collwrks, collectors.NewDnstapTcp(genwrks, config, logger))
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
