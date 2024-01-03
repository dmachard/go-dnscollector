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

func GetStanzaConfig(config *pkgconfig.Config, item pkgconfig.ConfigPipelines) *pkgconfig.Config {

	cfg := make(map[string]interface{})
	section := "collectors"

	// Enable the provided collector or loggers
	for k, p := range item.Params {
		// is a logger or collector ?
		if !config.Loggers.IsValid(k) && !config.Collectors.IsValid(k) {
			panic(fmt.Sprintln("main - get stanza config error"))
		}
		if config.Loggers.IsValid(k) {
			section = "loggers"
		}
		if p == nil {
			item.Params[k] = make(map[string]interface{})
		}
		item.Params[k].(map[string]interface{})["enable"] = true

		// ignore other keys
		break
	}

	// prepare a new config
	subcfg := &pkgconfig.Config{}
	subcfg.SetDefault()

	cfg[section] = item.Params
	cfg[section+"-transformers"] = make(map[string]interface{})

	// add transformers
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
		for _, route := range stanza.RoutingPolicy.Default {
			if err := IsRouteExist(route, config); err != nil {
				panic(fmt.Sprintf("[pipeline] - stanza=%s default route=%s doest not exist", stanza.Name, route))
			}
		}
		for _, route := range stanza.RoutingPolicy.Dropped {
			if err := IsRouteExist(route, config); err != nil {
				panic(fmt.Sprintf("[pipeline] - stanza=%s dropped route=%s doest not exist", stanza.Name, route))
			}
		}
	}

	// read each stanza and init
	for _, stanza := range config.Pipelines {
		stanzaConfig := GetStanzaConfig(config, stanza)

		// register the logger if enabled
		if stanzaConfig.Loggers.RestAPI.Enable {
			mapLoggers[stanza.Name] = loggers.NewRestAPI(stanzaConfig, logger, stanza.Name)
		}
		if stanzaConfig.Loggers.Prometheus.Enable {
			mapLoggers[stanza.Name] = loggers.NewPrometheus(stanzaConfig, logger, stanza.Name)
		}
		if stanzaConfig.Loggers.Stdout.Enable {
			mapLoggers[stanza.Name] = loggers.NewStdOut(stanzaConfig, logger, stanza.Name)
		}
		if stanzaConfig.Loggers.LogFile.Enable {
			mapLoggers[stanza.Name] = loggers.NewLogFile(stanzaConfig, logger, stanza.Name)
		}
		if stanzaConfig.Loggers.DNSTap.Enable {
			mapLoggers[stanza.Name] = loggers.NewDnstapSender(stanzaConfig, logger, stanza.Name)
		}
		if stanzaConfig.Loggers.TCPClient.Enable {
			mapLoggers[stanza.Name] = loggers.NewTCPClient(stanzaConfig, logger, stanza.Name)
		}
		if stanzaConfig.Loggers.Syslog.Enable {
			mapLoggers[stanza.Name] = loggers.NewSyslog(stanzaConfig, logger, stanza.Name)
		}
		if stanzaConfig.Loggers.Fluentd.Enable {
			mapLoggers[stanza.Name] = loggers.NewFluentdClient(stanzaConfig, logger, stanza.Name)
		}
		if stanzaConfig.Loggers.InfluxDB.Enable {
			mapLoggers[stanza.Name] = loggers.NewInfluxDBClient(stanzaConfig, logger, stanza.Name)
		}
		if stanzaConfig.Loggers.LokiClient.Enable {
			mapLoggers[stanza.Name] = loggers.NewLokiClient(stanzaConfig, logger, stanza.Name)
		}
		if stanzaConfig.Loggers.Statsd.Enable {
			mapLoggers[stanza.Name] = loggers.NewStatsdClient(stanzaConfig, logger, stanza.Name)
		}
		if stanzaConfig.Loggers.ElasticSearchClient.Enable {
			mapLoggers[stanza.Name] = loggers.NewElasticSearchClient(stanzaConfig, logger, stanza.Name)
		}
		if stanzaConfig.Loggers.ScalyrClient.Enable {
			mapLoggers[stanza.Name] = loggers.NewScalyrClient(stanzaConfig, logger, stanza.Name)
		}
		if stanzaConfig.Loggers.RedisPub.Enable {
			mapLoggers[stanza.Name] = loggers.NewRedisPub(stanzaConfig, logger, stanza.Name)
		}
		if stanzaConfig.Loggers.KafkaProducer.Enable {
			mapLoggers[stanza.Name] = loggers.NewKafkaProducer(stanzaConfig, logger, stanza.Name)
		}
		if stanzaConfig.Loggers.FalcoClient.Enable {
			mapLoggers[stanza.Name] = loggers.NewFalcoClient(stanzaConfig, logger, stanza.Name)
		}

		// register the collector if enabled
		if stanzaConfig.Collectors.DNSMessage.Enable {
			mapCollectors[stanza.Name] = collectors.NewDNSMessage(nil, stanzaConfig, logger, stanza.Name)
		}
		if stanzaConfig.Collectors.Dnstap.Enable {
			mapCollectors[stanza.Name] = collectors.NewDnstap(nil, stanzaConfig, logger, stanza.Name)
		}
		if stanzaConfig.Collectors.DnstapProxifier.Enable {
			mapCollectors[stanza.Name] = collectors.NewDnstapProxifier(nil, stanzaConfig, logger, stanza.Name)
		}
		if stanzaConfig.Collectors.AfpacketLiveCapture.Enable {
			mapCollectors[stanza.Name] = collectors.NewAfpacketSniffer(nil, stanzaConfig, logger, stanza.Name)
		}
		if stanzaConfig.Collectors.XdpLiveCapture.Enable {
			mapCollectors[stanza.Name] = collectors.NewXDPSniffer(nil, stanzaConfig, logger, stanza.Name)
		}
		if stanzaConfig.Collectors.Tail.Enable {
			mapCollectors[stanza.Name] = collectors.NewTail(nil, stanzaConfig, logger, stanza.Name)
		}
		if stanzaConfig.Collectors.PowerDNS.Enable {
			mapCollectors[stanza.Name] = collectors.NewProtobufPowerDNS(nil, stanzaConfig, logger, stanza.Name)
		}
		if stanzaConfig.Collectors.FileIngestor.Enable {
			mapCollectors[stanza.Name] = collectors.NewFileIngestor(nil, stanzaConfig, logger, stanza.Name)
		}
		if stanzaConfig.Collectors.Tzsp.Enable {
			mapCollectors[stanza.Name] = collectors.NewTZSP(nil, stanzaConfig, logger, stanza.Name)
		}
	}

	// create routing
	for _, stanza := range config.Pipelines {
		if len(mapCollectors) > 0 {
			if _, ok := mapCollectors[stanza.Name]; ok {
				// default routing
				for _, route := range stanza.RoutingPolicy.Default {
					if _, ok := mapCollectors[route]; ok {
						mapCollectors[stanza.Name].AddDefaultRoute(mapCollectors[route])
						logger.Info("[pipeline] - default routing from stanza=%s to stanza=%s", stanza.Name, route)
					} else if _, ok := mapLoggers[route]; ok {
						mapCollectors[stanza.Name].AddDefaultRoute(mapLoggers[route])
						logger.Info("[pipeline] - default routing from stanza=%s to stanza=%s", stanza.Name, route)
					} else {
						panic(fmt.Sprintf("[pipeline] - default routing error from stanza=%s to stanza=%s doest not exist", stanza.Name, route))
					}
				}

				// discarded routing
				for _, route := range stanza.RoutingPolicy.Dropped {
					if _, ok := mapCollectors[route]; ok {
						mapCollectors[stanza.Name].AddDroppedRoute(mapCollectors[route])
						logger.Info("[pipeline] - routing dropped messages from stanza=%s to stanza=%s", stanza.Name, route)
					} else if _, ok := mapLoggers[route]; ok {
						mapCollectors[stanza.Name].AddDroppedRoute(mapLoggers[route])
						logger.Info("[pipeline] - routing dropped messages from stanza=%s to stanza=%s", stanza.Name, route)
					} else {
						panic(fmt.Sprintf("[pipeline] - routing error with dropped messages from stanza=%s to stanza=%s doest not exist", stanza.Name, route))
					}
				}

			} else {
				logger.Info("[pipeline] - stanza=%v doest not exist", stanza.Name)
			}
		}

		// init logger
		// TODO
	}
}
