package main

import (
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
	"github.com/prometheus/common/version"
	"gopkg.in/yaml.v2"
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

func InitLogger(logger *logger.Logger, config *dnsutils.Config) {
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

func GetItemConfig(section string, config *dnsutils.Config, item dnsutils.MultiplexInOut) *dnsutils.Config {
	// load config
	cfg := make(map[string]interface{})
	cfg[section] = item.Params
	cfg[section+"-transformers"] = make(map[string]interface{})
	for _, p := range item.Params {
		p.(map[string]interface{})["enable"] = true
	}

	// get config with default values
	subcfg := &dnsutils.Config{}
	subcfg.SetDefault()

	// add transformer
	for k, v := range item.Transforms {
		v.(map[string]interface{})["enable"] = true
		cfg[section+"-transformers"].(map[string]interface{})[k] = v
	}

	// copy global config
	subcfg.Global = config.Global

	yamlcfg, _ := yaml.Marshal(cfg)
	if err := yaml.Unmarshal(yamlcfg, subcfg); err != nil {
		panic(fmt.Sprintf("main - yaml logger config error: %v", err))
	}
	return subcfg
}

func main() {
	args := os.Args[1:] // Ignore the first argument (the program name)

	verFlag := false
	configPath := "./config.yml"
	testFlag := false

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
	config, err := dnsutils.LoadConfig(configPath)
	if err != nil {
		panic(fmt.Sprintf("main - config error:  %v", err))
	}

	// init logger
	InitLogger(logger, config)

	logger.Info("main - version=%s revision=%s", version.Version, version.Revision)
	logger.Info("main - starting dns-collector...")

	// checking all routes before to continue
	if err := AreRoutesValid(config); err != nil {
		panic(fmt.Sprintf("main - configuration error: %e", err))
	}

	// load loggers
	logger.Info("main - loading loggers...")
	mapLoggers := make(map[string]dnsutils.Worker)
	for _, output := range config.Multiplexer.Loggers {
		// prepare restructured config for the current logger
		subcfg := GetItemConfig("loggers", config, output)

		// registor the logger if enabled
		if subcfg.Loggers.RestAPI.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = loggers.NewRestAPI(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.Prometheus.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = loggers.NewPrometheus(subcfg, logger, output.Name)
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
			mapLoggers[output.Name] = loggers.NewStatsdClient(subcfg, logger, output.Name)
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
		// prepare restructured config for the current collector
		subcfg := GetItemConfig("collectors", config, input)

		// register the collector if enabled
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
		if subcfg.Collectors.Tzsp.Enable && IsCollectorRouted(config, input.Name) {
			mapCollectors[input.Name] = collectors.NewTzsp(nil, subcfg, logger, input.Name)
		}
	}

	// here the multiplexer logic
	// connect collectors between loggers
	for _, route := range config.Multiplexer.Routes {
		var logwrks []dnsutils.Worker
		for _, dst := range route.Dst {
			if _, ok := mapLoggers[dst]; ok {
				logwrks = append(logwrks, mapLoggers[dst])
			} else {
				panic(fmt.Sprintf("main - routing error: logger %v doest not exist", dst))
			}
		}
		for _, src := range route.Src {
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
				logger.Info("main - SIGHUP received")

				// read config
				err := dnsutils.ReloadConfig(configPath, config)
				if err != nil {
					panic(fmt.Sprintf("main - reload config error:  %v", err))
				}

				// reload logger
				InitLogger(logger, config)

				for _, output := range config.Multiplexer.Loggers {
					newcfg := GetItemConfig("loggers", config, output)
					if _, ok := mapLoggers[output.Name]; ok {
						mapLoggers[output.Name].ReloadConfig(newcfg)
					} else {
						logger.Info("main - reload config logger=%v doest not exist", output.Name)
					}
				}

				for _, input := range config.Multiplexer.Collectors {
					newcfg := GetItemConfig("collectors", config, input)
					if _, ok := mapCollectors[input.Name]; ok {
						mapCollectors[input.Name].ReloadConfig(newcfg)
					} else {
						logger.Info("main - reload config collector=%v doest not exist", input.Name)
					}
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
		go l.Run()
	}
	for _, c := range mapCollectors {
		go c.Run()
	}

	// block main
	<-done

	logger.Info("main - stopped")
}
