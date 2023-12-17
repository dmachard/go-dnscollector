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

func StanzaNameIsUniq(name string, config *pkgconfig.Config) (ret error) {
	stanzaCounter := 0
	for _, stanza := range config.Pipelines {
		if name == stanza.Name {
			stanzaCounter += 1
		}
	}

	if stanzaCounter > 1 {
		return fmt.Errorf("stanza=%s allready exists", name)
	}
	return nil
}

func IsRouteExist(target string, config *pkgconfig.Config) (ret error) {
	for _, stanza := range config.Pipelines {
		if target == stanza.Name {
			return nil
		}
	}
	return fmt.Errorf("route=%s doest not exist", target)
}

func InitPipelines(mapLoggers map[string]dnsutils.Worker, mapCollectors map[string]dnsutils.Worker, config *pkgconfig.Config, logger *logger.Logger) {
	// check if the name of each stanza is uniq
	for _, stanza := range config.Pipelines {
		if err := StanzaNameIsUniq(stanza.Name, config); err != nil {
			panic(fmt.Sprintf("[pipeline] - stanza with name=%s is duplicated", stanza.Name))
		}
	}

	// check if all routes exists before continue
	for _, stanza := range config.Pipelines {
		for _, route := range stanza.Routes {
			if err := IsRouteExist(route, config); err != nil {
				panic(fmt.Sprintf("[pipeline] - stanza=%s route=%s doest not exist", stanza.Name, route))
			}
		}
	}

	// init stanza loggers
	for _, stanza := range config.Pipelines {
		if len(stanza.Routes) == 0 {
			subcfg := GetStageConfig("loggers", config, stanza)

			// registor the logger if enabled
			if subcfg.Loggers.RestAPI.Enable {
				mapLoggers[stanza.Name] = loggers.NewRestAPI(subcfg, logger, stanza.Name)
			}
			if subcfg.Loggers.Prometheus.Enable {
				mapLoggers[stanza.Name] = loggers.NewPrometheus(subcfg, logger, stanza.Name)
			}
			if subcfg.Loggers.Stdout.Enable {
				mapLoggers[stanza.Name] = loggers.NewStdOut(subcfg, logger, stanza.Name)
			}
			if subcfg.Loggers.LogFile.Enable {
				mapLoggers[stanza.Name] = loggers.NewLogFile(subcfg, logger, stanza.Name)
			}
			if subcfg.Loggers.DNSTap.Enable {
				mapLoggers[stanza.Name] = loggers.NewDnstapSender(subcfg, logger, stanza.Name)
			}
			if subcfg.Loggers.TCPClient.Enable {
				mapLoggers[stanza.Name] = loggers.NewTCPClient(subcfg, logger, stanza.Name)
			}
			if subcfg.Loggers.Syslog.Enable {
				mapLoggers[stanza.Name] = loggers.NewSyslog(subcfg, logger, stanza.Name)
			}
			if subcfg.Loggers.Fluentd.Enable {
				mapLoggers[stanza.Name] = loggers.NewFluentdClient(subcfg, logger, stanza.Name)
			}
			if subcfg.Loggers.InfluxDB.Enable {
				mapLoggers[stanza.Name] = loggers.NewInfluxDBClient(subcfg, logger, stanza.Name)
			}
			if subcfg.Loggers.LokiClient.Enable {
				mapLoggers[stanza.Name] = loggers.NewLokiClient(subcfg, logger, stanza.Name)
			}
			if subcfg.Loggers.Statsd.Enable {
				mapLoggers[stanza.Name] = loggers.NewStatsdClient(subcfg, logger, stanza.Name)
			}
			if subcfg.Loggers.ElasticSearchClient.Enable {
				mapLoggers[stanza.Name] = loggers.NewElasticSearchClient(subcfg, logger, stanza.Name)
			}
			if subcfg.Loggers.ScalyrClient.Enable {
				mapLoggers[stanza.Name] = loggers.NewScalyrClient(subcfg, logger, stanza.Name)
			}
			if subcfg.Loggers.RedisPub.Enable {
				mapLoggers[stanza.Name] = loggers.NewRedisPub(subcfg, logger, stanza.Name)
			}
			if subcfg.Loggers.KafkaProducer.Enable {
				mapLoggers[stanza.Name] = loggers.NewKafkaProducer(subcfg, logger, stanza.Name)
			}
			if subcfg.Loggers.FalcoClient.Enable {
				mapLoggers[stanza.Name] = loggers.NewFalcoClient(subcfg, logger, stanza.Name)
			}
		}
	}

	// init stanza collectors
	for _, stanza := range config.Pipelines {
		if len(stanza.Routes) > 0 {
			subcfg := GetStageConfig("collectors", config, stanza)

			if subcfg.Collectors.DNSMessage.Enable {
				mapCollectors[stanza.Name] = collectors.NewDNSMessage(nil, subcfg, logger, stanza.Name)
			}
			if subcfg.Collectors.Dnstap.Enable {
				mapCollectors[stanza.Name] = collectors.NewDnstap(nil, subcfg, logger, stanza.Name)
			}
			if subcfg.Collectors.DnstapProxifier.Enable {
				mapCollectors[stanza.Name] = collectors.NewDnstapProxifier(nil, subcfg, logger, stanza.Name)
			}
			if subcfg.Collectors.AfpacketLiveCapture.Enable {
				mapCollectors[stanza.Name] = collectors.NewAfpacketSniffer(nil, subcfg, logger, stanza.Name)
			}
			if subcfg.Collectors.XdpLiveCapture.Enable {
				mapCollectors[stanza.Name] = collectors.NewXDPSniffer(nil, subcfg, logger, stanza.Name)
			}
			if subcfg.Collectors.Tail.Enable {
				mapCollectors[stanza.Name] = collectors.NewTail(nil, subcfg, logger, stanza.Name)
			}
			if subcfg.Collectors.PowerDNS.Enable {
				mapCollectors[stanza.Name] = collectors.NewProtobufPowerDNS(nil, subcfg, logger, stanza.Name)
			}
			if subcfg.Collectors.FileIngestor.Enable {
				mapCollectors[stanza.Name] = collectors.NewFileIngestor(nil, subcfg, logger, stanza.Name)
			}
			if subcfg.Collectors.Tzsp.Enable {
				mapCollectors[stanza.Name] = collectors.NewTZSP(nil, subcfg, logger, stanza.Name)
			}
		}
	}

	// connect all stanzas
	for _, stanza := range config.Pipelines {
		if len(stanza.Routes) > 0 {
			if _, ok := mapCollectors[stanza.Name]; ok {
				for _, route := range stanza.Routes {
					// search in collectors
					if _, ok := mapCollectors[route]; ok {
						mapCollectors[stanza.Name].AddRoute(mapCollectors[route])
						logger.Info("[pipeline] - routing stanza=%s to=%s", stanza.Name, route)
					} else if _, ok := mapLoggers[route]; ok {
						mapCollectors[stanza.Name].AddRoute(mapLoggers[route])
						logger.Info("[pipeline] - routing stanza=%s to=%s", stanza.Name, route)
					} else {
						panic(fmt.Sprintf("[pipeline] - routing error with stanza=%s to=%s doest not exist", stanza.Name, route))
					}
				}
			} else {
				logger.Info("[pipeline] - stanza=%v doest not exist", stanza.Name)
			}
		}
	}
}
