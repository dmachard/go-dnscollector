package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	_ "net/http/pprof"

	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkglinker"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-logger"
	"github.com/natefinch/lumberjack"
	"github.com/prometheus/common/version"
)

func showVersion() {
	fmt.Println(version.Version)
}

func printUsage() {
	fmt.Printf("Usage of %s:\n", os.Args[0])
	fmt.Println("  -config string")
	fmt.Println("        path to config file (default \"./config.yml\")")
	fmt.Println("  -version")
	fmt.Println("        Show version")
	fmt.Println("  -test-config")
	fmt.Println("        Test config file")
}

func InitLogger(logger *logger.Logger, config *pkgconfig.Config) {
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
}

func main() {
	args := os.Args[1:] // Ignore the first argument (the program name)

	verFlag := false
	configPath := "./config.yml"
	testFlag := false

	// Server for pprof
	// go func() {
	// 	fmt.Println(http.ListenAndServe("localhost:9999", nil))
	// }()

	// no more use embedded golang flags...
	// external lib like tcpassembly can set some uneeded flags too...
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-version", "-v":
			verFlag = true
		case "-config", "-c":
			if i+1 < len(args) {
				configPath = args[i+1]
				i++ // Skip the next argument
			} else {
				fmt.Println("Missing argument for -config")
				os.Exit(1)
			}
		case "-help", "-h":
			printUsage()
			os.Exit(0)
		case "-test-config":
			testFlag = true
		default:
			if strings.HasPrefix(args[i], "-") {
				printUsage()
				os.Exit(1)
			}
		}
	}

	if verFlag {
		showVersion()
		os.Exit(0)
	}

	done := make(chan bool)

	// create logger
	logger := logger.New(true)

	// load config
	config, err := pkgconfig.LoadConfig(configPath)
	if err != nil {
		fmt.Printf("config error: %v\n", err)
		os.Exit(1)
	}

	// init logger
	InitLogger(logger, config)
	logger.Info("main - version=%s revision=%s", version.Version, version.Revision)
	logger.Info("main - starting dns-collector...")

	// init active collectors and loggers
	mapLoggers := make(map[string]pkgutils.Worker)
	mapCollectors := make(map[string]pkgutils.Worker)

	// running mode,
	// multiplexer ?
	if pkglinker.IsMuxEnabled(config) {
		logger.Info("main - multiplexer mode enabled")
		pkglinker.InitMultiplexer(mapLoggers, mapCollectors, config, logger)
	}

	// or pipeline ?
	if len(config.Pipelines) > 0 {
		logger.Info("main - pipelines mode enabled")
		err := pkglinker.InitPipelines(mapLoggers, mapCollectors, config, logger)
		if err != nil {
			logger.Error("main - %s", err.Error())
			os.Exit(1)
		}
	}

	// Handle Ctrl-C with SIG TERM and SIGHUP
	sigTerm := make(chan os.Signal, 1)
	sigHUP := make(chan os.Signal, 1)

	signal.Notify(sigTerm, os.Interrupt, syscall.SIGTERM)
	signal.Notify(sigHUP, syscall.SIGHUP)

	go func() {
		for {
			select {
			case <-sigHUP:
				logger.Info("main - SIGHUP received")

				// read config
				err := pkgconfig.ReloadConfig(configPath, config)
				if err != nil {
					panic(fmt.Sprintf("main - reload config error:  %v", err))
				}

				// reload logger and multiplexer
				InitLogger(logger, config)
				if pkglinker.IsMuxEnabled(config) {
					pkglinker.ReloadMultiplexer(mapLoggers, mapCollectors, config, logger)
				}

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

	if testFlag {
		// We've parsed the config and are ready to start, so the config is good enough
		logger.Info("main - config OK!")
		os.Exit(0)
	}

	// run all workers in background
	logger.Info("main - running...")

	for _, l := range mapLoggers {
		go l.StartCollect()
	}
	for _, c := range mapCollectors {
		go c.StartCollect()
	}

	// block main
	<-done

	logger.Info("main - stopped")
}
