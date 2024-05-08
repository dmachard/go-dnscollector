package pkglinker

import (
	"fmt"
	"strings"

	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-dnscollector/workers"
	"github.com/dmachard/go-logger"
	"gopkg.in/yaml.v2"
)

const (
	Transformers = "-transformers"
)

func IsMuxEnabled(config *pkgconfig.Config) bool {
	if len(config.Multiplexer.Collectors) > 0 && len(config.Multiplexer.Loggers) > 0 && len(config.Multiplexer.Routes) > 0 {
		return true
	}
	return false
}

func IsLoggerRouted(config *pkgconfig.Config, name string) bool {
	for _, routes := range config.Multiplexer.Routes {
		for _, dst := range routes.Dst {
			if dst == name {
				return true
			}
		}
	}
	return false
}

func IsCollectorRouted(config *pkgconfig.Config, name string) bool {
	for _, routes := range config.Multiplexer.Routes {
		for _, src := range routes.Src {
			if src == name {
				return true
			}
		}
	}
	return false
}

func AreRoutesValid(config *pkgconfig.Config) (ret error) {
	for _, route := range config.Multiplexer.Routes {
		if len(route.Src) == 0 || len(route.Dst) == 0 {
			ret = fmt.Errorf("incomplete route, from: %s, to: %s", strings.Join(route.Src, ", "), strings.Join(route.Dst, ", "))
		}
	}
	return
}

func GetItemConfig(section string, config *pkgconfig.Config, item pkgconfig.MultiplexInOut) *pkgconfig.Config {
	// load config
	cfg := make(map[string]interface{})
	cfg[section] = item.Params
	cfg[section+Transformers] = make(map[string]interface{})
	for _, p := range item.Params {
		p.(map[string]interface{})["enable"] = true
	}

	// get config with default values
	subcfg := &pkgconfig.Config{}
	subcfg.SetDefault()

	// add transformer
	for k, v := range item.Transforms {
		if _, ok := v.(map[string]interface{}); !ok {
			panic("main - yaml transform config error - map expected")
		}

		v.(map[string]interface{})["enable"] = true
		cfg[section+Transformers].(map[string]interface{})[k] = v
	}

	// copy global config
	subcfg.Global = config.Global

	yamlcfg, _ := yaml.Marshal(cfg)
	if err := yaml.Unmarshal(yamlcfg, subcfg); err != nil {
		panic(fmt.Sprintf("main - yaml logger config error: %v", err))
	}
	return subcfg
}

func InitMultiplexer(mapLoggers map[string]pkgutils.Worker, mapCollectors map[string]pkgutils.Worker, config *pkgconfig.Config, logger *logger.Logger) {

	// checking all routes before to continue
	if err := AreRoutesValid(config); err != nil {
		panic(fmt.Sprintf("main - configuration error: %e", err))
	}

	logger.Info("main - loading loggers...")
	for _, output := range config.Multiplexer.Loggers {
		// prepare restructured config for the current logger
		subcfg := GetItemConfig("loggers", config, output)

		// registor the logger if enabled
		if subcfg.Loggers.DevNull.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = workers.NewDevNull(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.RestAPI.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = workers.NewRestAPI(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.Prometheus.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = workers.NewPrometheus(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.Stdout.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = workers.NewStdOut(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.LogFile.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = workers.NewLogFile(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.DNSTap.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = workers.NewDnstapSender(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.TCPClient.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = workers.NewTCPClient(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.Syslog.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = workers.NewSyslog(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.Fluentd.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = workers.NewFluentdClient(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.InfluxDB.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = workers.NewInfluxDBClient(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.LokiClient.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = workers.NewLokiClient(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.Statsd.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = workers.NewStatsdClient(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.ElasticSearchClient.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = workers.NewElasticSearchClient(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.ScalyrClient.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = workers.NewScalyrClient(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.RedisPub.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = workers.NewRedisPub(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.KafkaProducer.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = workers.NewKafkaProducer(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.FalcoClient.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = workers.NewFalcoClient(subcfg, logger, output.Name)
		}
		if subcfg.Loggers.ClickhouseClient.Enable && IsLoggerRouted(config, output.Name) {
			mapLoggers[output.Name] = workers.NewClickhouseClient(subcfg, logger, output.Name)
		}
	}

	// load collectors
	logger.Info("main - loading collectors...")
	for _, input := range config.Multiplexer.Collectors {
		// prepare restructured config for the current collector
		subcfg := GetItemConfig("collectors", config, input)

		// register the collector if enabled
		if subcfg.Collectors.Dnstap.Enable && IsCollectorRouted(config, input.Name) {
			mapCollectors[input.Name] = workers.NewDnstap(nil, subcfg, logger, input.Name)
		}
		if subcfg.Collectors.DnstapProxifier.Enable && IsCollectorRouted(config, input.Name) {
			mapCollectors[input.Name] = workers.NewDnstapProxifier(nil, subcfg, logger, input.Name)
		}
		if subcfg.Collectors.AfpacketLiveCapture.Enable && IsCollectorRouted(config, input.Name) {
			mapCollectors[input.Name] = workers.NewAfpacketSniffer(nil, subcfg, logger, input.Name)
		}
		if subcfg.Collectors.XdpLiveCapture.Enable && IsCollectorRouted(config, input.Name) {
			mapCollectors[input.Name] = workers.NewXDPSniffer(nil, subcfg, logger, input.Name)
		}
		if subcfg.Collectors.Tail.Enable && IsCollectorRouted(config, input.Name) {
			mapCollectors[input.Name] = workers.NewTail(nil, subcfg, logger, input.Name)
		}
		if subcfg.Collectors.PowerDNS.Enable && IsCollectorRouted(config, input.Name) {
			mapCollectors[input.Name] = workers.NewProtobufPowerDNS(nil, subcfg, logger, input.Name)
		}
		if subcfg.Collectors.FileIngestor.Enable && IsCollectorRouted(config, input.Name) {
			mapCollectors[input.Name] = workers.NewFileIngestor(nil, subcfg, logger, input.Name)
		}
		if subcfg.Collectors.Tzsp.Enable && IsCollectorRouted(config, input.Name) {
			mapCollectors[input.Name] = workers.NewTZSP(nil, subcfg, logger, input.Name)
		}
	}

	// here the multiplexer logic
	// connect collectors between loggers
	for _, route := range config.Multiplexer.Routes {
		var logwrks []pkgutils.Worker
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
}

func ReloadMultiplexer(mapLoggers map[string]pkgutils.Worker, mapCollectors map[string]pkgutils.Worker, config *pkgconfig.Config, logger *logger.Logger) {
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
}
