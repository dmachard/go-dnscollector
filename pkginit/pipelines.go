package pkginit

import (
	"fmt"

	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/workers"
	"github.com/dmachard/go-logger"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

func IsPipelinesEnabled(config *pkgconfig.Config) bool {
	return len(config.Pipelines) > 0
}

func GetStanzaConfig(config *pkgconfig.Config, item pkgconfig.ConfigPipelines) *pkgconfig.Config {

	cfg := make(map[string]interface{})
	section := "collectors"

	// Enable the provided collector or loggers
	for k, p := range item.Params {
		// is a logger or collector ?
		if !config.Loggers.IsExists(k) && !config.Collectors.IsExists(k) {
			panic(fmt.Sprintln("main - get stanza config error"))
		}
		if config.Loggers.IsExists(k) {
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

func CreateRouting(stanza pkgconfig.ConfigPipelines, mapCollectors map[string]workers.Worker, mapLoggers map[string]workers.Worker, logger *logger.Logger) error {
	var currentStanza workers.Worker
	if collector, ok := mapCollectors[stanza.Name]; ok {
		currentStanza = collector
	}
	if logger, ok := mapLoggers[stanza.Name]; ok {
		currentStanza = logger
	}

	// forward routing
	for _, route := range stanza.RoutingPolicy.Forward {
		if route == stanza.Name {
			return fmt.Errorf("main - routing error loop with stanza=%s to stanza=%s", stanza.Name, route)
		}
		if _, ok := mapCollectors[route]; ok {
			currentStanza.AddDefaultRoute(mapCollectors[route])
			logger.Info("main - routing (policy=forward) stanza=[%s] to stanza=[%s]", stanza.Name, route)
		} else if _, ok := mapLoggers[route]; ok {
			currentStanza.AddDefaultRoute(mapLoggers[route])
			logger.Info("main - routing (policy=forward) stanza=[%s] to stanza=[%s]", stanza.Name, route)
		} else {
			return fmt.Errorf("main - forward routing error from stanza=%s to stanza=%s doest not exist", stanza.Name, route)
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
			return fmt.Errorf("main - routing error with dropped messages from stanza=%s to stanza=%s doest not exist", stanza.Name, route)
		}
	}
	return nil
}

func CreateStanza(stanzaName string, config *pkgconfig.Config, mapCollectors map[string]workers.Worker, mapLoggers map[string]workers.Worker, logger *logger.Logger) {
	// register the logger if enabled
	if config.Loggers.RestAPI.Enable {
		mapLoggers[stanzaName] = workers.NewRestAPI(config, logger, stanzaName)
	}
	if config.Loggers.Prometheus.Enable {
		mapLoggers[stanzaName] = workers.NewPrometheus(config, logger, stanzaName)
	}
	if config.Loggers.Stdout.Enable {
		mapLoggers[stanzaName] = workers.NewStdOut(config, logger, stanzaName)
	}
	if config.Loggers.LogFile.Enable {
		mapLoggers[stanzaName] = workers.NewLogFile(config, logger, stanzaName)
	}
	if config.Loggers.DNSTap.Enable {
		mapLoggers[stanzaName] = workers.NewDnstapSender(config, logger, stanzaName)
	}
	if config.Loggers.TCPClient.Enable {
		mapLoggers[stanzaName] = workers.NewTCPClient(config, logger, stanzaName)
	}
	if config.Loggers.Syslog.Enable {
		mapLoggers[stanzaName] = workers.NewSyslog(config, logger, stanzaName)
	}
	if config.Loggers.Fluentd.Enable {
		mapLoggers[stanzaName] = workers.NewFluentdClient(config, logger, stanzaName)
	}
	if config.Loggers.InfluxDB.Enable {
		mapLoggers[stanzaName] = workers.NewInfluxDBClient(config, logger, stanzaName)
	}
	if config.Loggers.LokiClient.Enable {
		mapLoggers[stanzaName] = workers.NewLokiClient(config, logger, stanzaName)
	}
	if config.Loggers.Statsd.Enable {
		mapLoggers[stanzaName] = workers.NewStatsdClient(config, logger, stanzaName)
	}
	if config.Loggers.ElasticSearchClient.Enable {
		mapLoggers[stanzaName] = workers.NewElasticSearchClient(config, logger, stanzaName)
	}
	if config.Loggers.ScalyrClient.Enable {
		mapLoggers[stanzaName] = workers.NewScalyrClient(config, logger, stanzaName)
	}
	if config.Loggers.RedisPub.Enable {
		mapLoggers[stanzaName] = workers.NewRedisPub(config, logger, stanzaName)
	}
	if config.Loggers.KafkaProducer.Enable {
		mapLoggers[stanzaName] = workers.NewKafkaProducer(config, logger, stanzaName)
	}
	if config.Loggers.FalcoClient.Enable {
		mapLoggers[stanzaName] = workers.NewFalcoClient(config, logger, stanzaName)
	}
	if config.Loggers.ClickhouseClient.Enable {
		mapLoggers[stanzaName] = workers.NewClickhouseClient(config, logger, stanzaName)
	}

	// register the collector if enabled
	if config.Collectors.DNSMessage.Enable {
		mapCollectors[stanzaName] = workers.NewDNSMessage(nil, config, logger, stanzaName)
	}
	if config.Collectors.Dnstap.Enable {
		mapCollectors[stanzaName] = workers.NewDnstapServer(nil, config, logger, stanzaName)
	}
	if config.Collectors.DnstapProxifier.Enable {
		mapCollectors[stanzaName] = workers.NewDnstapProxifier(nil, config, logger, stanzaName)
	}
	if config.Collectors.AfpacketLiveCapture.Enable {
		mapCollectors[stanzaName] = workers.NewAfpacketSniffer(nil, config, logger, stanzaName)
	}
	if config.Collectors.XdpLiveCapture.Enable {
		mapCollectors[stanzaName] = workers.NewXDPSniffer(nil, config, logger, stanzaName)
	}
	if config.Collectors.Tail.Enable {
		mapCollectors[stanzaName] = workers.NewTail(nil, config, logger, stanzaName)
	}
	if config.Collectors.PowerDNS.Enable {
		mapCollectors[stanzaName] = workers.NewPdnsServer(nil, config, logger, stanzaName)
	}
	if config.Collectors.FileIngestor.Enable {
		mapCollectors[stanzaName] = workers.NewFileIngestor(nil, config, logger, stanzaName)
	}
	if config.Collectors.Tzsp.Enable {
		mapCollectors[stanzaName] = workers.NewTZSP(nil, config, logger, stanzaName)
	}
}

func InitPipelines(mapLoggers map[string]workers.Worker, mapCollectors map[string]workers.Worker, config *pkgconfig.Config, logger *logger.Logger) error {
	// check if the name of each stanza is uniq
	routesDefined := false
	for _, stanza := range config.Pipelines {
		if err := StanzaNameIsUniq(stanza.Name, config); err != nil {
			return errors.Errorf("stanza with name=[%s] is duplicated", stanza.Name)
		}
		if len(stanza.RoutingPolicy.Forward) > 0 || len(stanza.RoutingPolicy.Dropped) > 0 {
			routesDefined = true
		}
	}

	if !routesDefined {
		return errors.Errorf("no routes are defined")
	}

	// check if all routes exists before continue
	for _, stanza := range config.Pipelines {
		for _, route := range stanza.RoutingPolicy.Forward {
			if err := IsRouteExist(route, config); err != nil {
				return errors.Errorf("stanza=[%s] forward route=[%s] doest not exist", stanza.Name, route)
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
			if err := CreateRouting(stanza, mapCollectors, mapLoggers, logger); err != nil {
				return errors.Errorf(err.Error())
			}
		} else {
			return errors.Errorf("routing - stanza=[%v] doest not exist", stanza.Name)
		}
	}

	return nil
}

func ReloadPipelines(mapLoggers map[string]workers.Worker, mapCollectors map[string]workers.Worker, config *pkgconfig.Config, logger *logger.Logger) {
	for _, stanza := range config.Pipelines {
		newCfg := GetStanzaConfig(config, stanza)
		if _, ok := mapLoggers[stanza.Name]; ok {
			mapLoggers[stanza.Name].ReloadConfig(newCfg)
		} else if _, ok := mapCollectors[stanza.Name]; ok {
			mapCollectors[stanza.Name].ReloadConfig(newCfg)
		} else {
			logger.Info("main - reload config stanza=%v doest not exist", stanza.Name)
		}
	}
}
