package main

import (
	"fmt"

	"github.com/dmachard/go-dnscollector/collectors"
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/loggers"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
	"gopkg.in/yaml.v2"
)

func GetStageConfig(section string, config *pkgconfig.Config, item pkgconfig.ConfigPipelines) *pkgconfig.Config {
	// load config
	cfg := make(map[string]interface{})

	for k, p := range item.Params {
		if p == nil {
			item.Params[k] = make(map[string]interface{})
		}
		item.Params[k].(map[string]interface{})["enable"] = true
	}

	cfg[section] = item.Params
	cfg[section+"-transformers"] = make(map[string]interface{})

	// get config with default values
	subcfg := &pkgconfig.Config{}
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

func InitPipelines(mapLoggers map[string]dnsutils.Worker, mapCollectors map[string]dnsutils.Worker, config *pkgconfig.Config, logger *logger.Logger) {
	// TODO stage name must be uniq
	// TODO check if stages exists before continue

	// init loggers
	for _, stage := range config.Pipelines {
		if len(stage.Routes) == 0 {
			subcfg := GetStageConfig("loggers", config, stage)

			// registor the logger if enabled
			if subcfg.Loggers.RestAPI.Enable {
				mapLoggers[stage.Name] = loggers.NewRestAPI(subcfg, logger, stage.Name)
			}
			if subcfg.Loggers.Prometheus.Enable {
				mapLoggers[stage.Name] = loggers.NewPrometheus(subcfg, logger, stage.Name)
			}
			if subcfg.Loggers.Stdout.Enable {
				mapLoggers[stage.Name] = loggers.NewStdOut(subcfg, logger, stage.Name)
			}
			if subcfg.Loggers.LogFile.Enable {
				mapLoggers[stage.Name] = loggers.NewLogFile(subcfg, logger, stage.Name)
			}
			if subcfg.Loggers.DNSTap.Enable {
				mapLoggers[stage.Name] = loggers.NewDnstapSender(subcfg, logger, stage.Name)
			}
			if subcfg.Loggers.TCPClient.Enable {
				mapLoggers[stage.Name] = loggers.NewTCPClient(subcfg, logger, stage.Name)
			}
			if subcfg.Loggers.Syslog.Enable {
				mapLoggers[stage.Name] = loggers.NewSyslog(subcfg, logger, stage.Name)
			}
			if subcfg.Loggers.Fluentd.Enable {
				mapLoggers[stage.Name] = loggers.NewFluentdClient(subcfg, logger, stage.Name)
			}
			if subcfg.Loggers.InfluxDB.Enable {
				mapLoggers[stage.Name] = loggers.NewInfluxDBClient(subcfg, logger, stage.Name)
			}
			if subcfg.Loggers.LokiClient.Enable {
				mapLoggers[stage.Name] = loggers.NewLokiClient(subcfg, logger, stage.Name)
			}
			if subcfg.Loggers.Statsd.Enable {
				mapLoggers[stage.Name] = loggers.NewStatsdClient(subcfg, logger, stage.Name)
			}
			if subcfg.Loggers.ElasticSearchClient.Enable {
				mapLoggers[stage.Name] = loggers.NewElasticSearchClient(subcfg, logger, stage.Name)
			}
			if subcfg.Loggers.ScalyrClient.Enable {
				mapLoggers[stage.Name] = loggers.NewScalyrClient(subcfg, logger, stage.Name)
			}
			if subcfg.Loggers.RedisPub.Enable {
				mapLoggers[stage.Name] = loggers.NewRedisPub(subcfg, logger, stage.Name)
			}
			if subcfg.Loggers.KafkaProducer.Enable {
				mapLoggers[stage.Name] = loggers.NewKafkaProducer(subcfg, logger, stage.Name)
			}
			if subcfg.Loggers.FalcoClient.Enable {
				mapLoggers[stage.Name] = loggers.NewFalcoClient(subcfg, logger, stage.Name)
			}
		}
	}

	// init collectors
	for _, stage := range config.Pipelines {
		if len(stage.Routes) > 0 {
			subcfg := GetStageConfig("collectors", config, stage)

			if subcfg.Collectors.DNSMessage.Enable {
				mapCollectors[stage.Name] = collectors.NewDNSMessage(nil, subcfg, logger, stage.Name)
			}
			if subcfg.Collectors.Dnstap.Enable {
				mapCollectors[stage.Name] = collectors.NewDnstap(nil, subcfg, logger, stage.Name)
			}
			if subcfg.Collectors.DnstapProxifier.Enable {
				mapCollectors[stage.Name] = collectors.NewDnstapProxifier(nil, subcfg, logger, stage.Name)
			}
			if subcfg.Collectors.AfpacketLiveCapture.Enable {
				mapCollectors[stage.Name] = collectors.NewAfpacketSniffer(nil, subcfg, logger, stage.Name)
			}
			if subcfg.Collectors.XdpLiveCapture.Enable {
				mapCollectors[stage.Name] = collectors.NewXDPSniffer(nil, subcfg, logger, stage.Name)
			}
			if subcfg.Collectors.Tail.Enable {
				mapCollectors[stage.Name] = collectors.NewTail(nil, subcfg, logger, stage.Name)
			}
			if subcfg.Collectors.PowerDNS.Enable {
				mapCollectors[stage.Name] = collectors.NewProtobufPowerDNS(nil, subcfg, logger, stage.Name)
			}
			if subcfg.Collectors.FileIngestor.Enable {
				mapCollectors[stage.Name] = collectors.NewFileIngestor(nil, subcfg, logger, stage.Name)
			}
			if subcfg.Collectors.Tzsp.Enable {
				mapCollectors[stage.Name] = collectors.NewTZSP(nil, subcfg, logger, stage.Name)
			}
		}
	}

	// connect all stages
	for _, stage := range config.Pipelines {
		if len(stage.Routes) > 0 {
			if _, ok := mapCollectors[stage.Name]; ok {
				for _, route := range stage.Routes {
					// search in collectors
					if _, ok := mapCollectors[route]; ok {
						mapCollectors[stage.Name].AddRoute(mapCollectors[route])
					} else if _, ok := mapLoggers[route]; ok {
						mapCollectors[stage.Name].AddRoute(mapLoggers[route])
					} else {
						panic(fmt.Sprintf("main - routing error: stage %v doest not exist", route))
					}
				}
			} else {
				logger.Info("main - stage=%v doest not exist", stage.Name)
			}
		}
	}
}
