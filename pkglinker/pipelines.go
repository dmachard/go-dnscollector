package pkglinker

import (
	"fmt"

	"github.com/dmachard/go-dnscollector/collectors"
	"github.com/dmachard/go-dnscollector/loggers"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-logger"
	"github.com/pkg/errors"
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

func CreateRouting(stanza pkgconfig.ConfigPipelines, mapCollectors map[string]pkgutils.Worker, mapLoggers map[string]pkgutils.Worker, logger *logger.Logger) {
	var currentStanza pkgutils.Worker
	if collector, ok := mapCollectors[stanza.Name]; ok {
		currentStanza = collector
	}
	if logger, ok := mapLoggers[stanza.Name]; ok {
		currentStanza = logger
	}

	// TODO raise error when no routes are defined

	// default routing
	for _, route := range stanza.RoutingPolicy.Default {
		if _, ok := mapCollectors[route]; ok {
			currentStanza.AddDefaultRoute(mapCollectors[route])
			logger.Info("main - routing (policy=default) stanza=[%s] to stanza=[%s]", stanza.Name, route)
		} else if _, ok := mapLoggers[route]; ok {
			currentStanza.AddDefaultRoute(mapLoggers[route])
			logger.Info("main - routing (policy=default) stanza=[%s] to stanza=[%s]", stanza.Name, route)
		} else {
			logger.Error("main - default routing error from stanza=%s to stanza=%s doest not exist", stanza.Name, route)
			break
		}
	}

	// dropped routing
	for _, route := range stanza.RoutingPolicy.Dropped {
		if _, ok := mapCollectors[route]; ok {
			currentStanza.AddDroppedRoute(mapCollectors[route])
			logger.Info("main - routing (policy=dropped) stanza=[%s] to stanza=[%s]", stanza.Name, route)
		} else if _, ok := mapLoggers[route]; ok {
			currentStanza.AddDroppedRoute(mapLoggers[route])
			logger.Info("main - routing (policy=dropped) stanza=[%s] to stanza=[%s]", stanza.Name, route)
		} else {
			logger.Error("main - routing error with dropped messages from stanza=%s to stanza=%s doest not exist", stanza.Name, route)
			break
		}
	}
}

func CreateStanza(stanzaName string, config *pkgconfig.Config, mapCollectors map[string]pkgutils.Worker, mapLoggers map[string]pkgutils.Worker, logger *logger.Logger) {
	// register the logger if enabled
	if config.Loggers.RestAPI.Enable {
		mapLoggers[stanzaName] = loggers.NewRestAPI(config, logger, stanzaName)
	}
	if config.Loggers.Prometheus.Enable {
		mapLoggers[stanzaName] = loggers.NewPrometheus(config, logger, stanzaName)
	}
	if config.Loggers.Stdout.Enable {
		mapLoggers[stanzaName] = loggers.NewStdOut(config, logger, stanzaName)
	}
	if config.Loggers.LogFile.Enable {
		mapLoggers[stanzaName] = loggers.NewLogFile(config, logger, stanzaName)
	}
	if config.Loggers.DNSTap.Enable {
		mapLoggers[stanzaName] = loggers.NewDnstapSender(config, logger, stanzaName)
	}
	if config.Loggers.TCPClient.Enable {
		mapLoggers[stanzaName] = loggers.NewTCPClient(config, logger, stanzaName)
	}
	if config.Loggers.Syslog.Enable {
		mapLoggers[stanzaName] = loggers.NewSyslog(config, logger, stanzaName)
	}
	if config.Loggers.Fluentd.Enable {
		mapLoggers[stanzaName] = loggers.NewFluentdClient(config, logger, stanzaName)
	}
	if config.Loggers.InfluxDB.Enable {
		mapLoggers[stanzaName] = loggers.NewInfluxDBClient(config, logger, stanzaName)
	}
	if config.Loggers.LokiClient.Enable {
		mapLoggers[stanzaName] = loggers.NewLokiClient(config, logger, stanzaName)
	}
	if config.Loggers.Statsd.Enable {
		mapLoggers[stanzaName] = loggers.NewStatsdClient(config, logger, stanzaName)
	}
	if config.Loggers.ElasticSearchClient.Enable {
		mapLoggers[stanzaName] = loggers.NewElasticSearchClient(config, logger, stanzaName)
	}
	if config.Loggers.ScalyrClient.Enable {
		mapLoggers[stanzaName] = loggers.NewScalyrClient(config, logger, stanzaName)
	}
	if config.Loggers.RedisPub.Enable {
		mapLoggers[stanzaName] = loggers.NewRedisPub(config, logger, stanzaName)
	}
	if config.Loggers.KafkaProducer.Enable {
		mapLoggers[stanzaName] = loggers.NewKafkaProducer(config, logger, stanzaName)
	}
	if config.Loggers.FalcoClient.Enable {
		mapLoggers[stanzaName] = loggers.NewFalcoClient(config, logger, stanzaName)
	}

	// register the collector if enabled
	if config.Collectors.DNSMessage.Enable {
		mapCollectors[stanzaName] = collectors.NewDNSMessage(nil, config, logger, stanzaName)
	}
	if config.Collectors.Dnstap.Enable {
		mapCollectors[stanzaName] = collectors.NewDnstap(nil, config, logger, stanzaName)
	}
	if config.Collectors.DnstapProxifier.Enable {
		mapCollectors[stanzaName] = collectors.NewDnstapProxifier(nil, config, logger, stanzaName)
	}
	if config.Collectors.AfpacketLiveCapture.Enable {
		mapCollectors[stanzaName] = collectors.NewAfpacketSniffer(nil, config, logger, stanzaName)
	}
	if config.Collectors.XdpLiveCapture.Enable {
		mapCollectors[stanzaName] = collectors.NewXDPSniffer(nil, config, logger, stanzaName)
	}
	if config.Collectors.Tail.Enable {
		mapCollectors[stanzaName] = collectors.NewTail(nil, config, logger, stanzaName)
	}
	if config.Collectors.PowerDNS.Enable {
		mapCollectors[stanzaName] = collectors.NewProtobufPowerDNS(nil, config, logger, stanzaName)
	}
	if config.Collectors.FileIngestor.Enable {
		mapCollectors[stanzaName] = collectors.NewFileIngestor(nil, config, logger, stanzaName)
	}
	if config.Collectors.Tzsp.Enable {
		mapCollectors[stanzaName] = collectors.NewTZSP(nil, config, logger, stanzaName)
	}
}

func InitPipelines(mapLoggers map[string]pkgutils.Worker, mapCollectors map[string]pkgutils.Worker, config *pkgconfig.Config, logger *logger.Logger) error {
	// check if the name of each stanza is uniq
	for _, stanza := range config.Pipelines {
		if err := StanzaNameIsUniq(stanza.Name, config); err != nil {
			return errors.Errorf("stanza with name=[%s] is duplicated", stanza.Name)
		}
	}

	// check if all routes exists before continue
	for _, stanza := range config.Pipelines {
		for _, route := range stanza.RoutingPolicy.Default {
			if err := IsRouteExist(route, config); err != nil {
				return errors.Errorf("stanza=[%s] default route=[%s] doest not exist", stanza.Name, route)
			}
		}
		for _, route := range stanza.RoutingPolicy.Dropped {
			if err := IsRouteExist(route, config); err != nil {
				return errors.Errorf("stanza=[%s] dropped route=[%s] doest not exist", stanza.Name, route)
			}
		}
	}

	// read each stanza and init
	for _, stanza := range config.Pipelines {
		stanzaConfig := GetStanzaConfig(config, stanza)
		CreateStanza(stanza.Name, stanzaConfig, mapCollectors, mapLoggers, logger)

	}

	// create routing
	for _, stanza := range config.Pipelines {
		if mapCollectors[stanza.Name] != nil || mapLoggers[stanza.Name] != nil {
			CreateRouting(stanza, mapCollectors, mapLoggers, logger)
		} else {
			return errors.Errorf("stanza=[%v] doest not exist", stanza.Name)
		}
	}

	return nil
}
