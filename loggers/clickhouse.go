package loggers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
)

type ClickhouseData struct {
	Identity  string `json:"identity"`
	QueryIP   string `json:"query_ip"`
	QName     string `json:"q_name"`
	Operation string `json:"operation"`
	Family    string `json:"family"`
	Protocol  string `json:"protocol"`
	QType     string `json:"q_type"`
	RCode     string `json:"r_code"`
	TimeNSec  string `json:"timensec"`
	TimeStamp string `json:"timestamp"`
}

type ClickhouseClient struct {
	stopProcess, doneProcess             chan bool
	stopRun, doneRun                     chan bool
	inputChan, outputChan                chan dnsutils.DNSMessage
	config                               *pkgconfig.Config
	configChan                           chan *pkgconfig.Config
	logger                               *logger.Logger
	name                                 string
	url, user, password, database, table string
	RoutingHandler                       pkgutils.RoutingHandler
}

func NewClickhouseClient(config *pkgconfig.Config, console *logger.Logger, name string) *ClickhouseClient {
	console.Info("[%s] logger=clickhouse - enabled", name)
	o := &ClickhouseClient{
		stopProcess:    make(chan bool),
		doneProcess:    make(chan bool),
		stopRun:        make(chan bool),
		doneRun:        make(chan bool),
		inputChan:      make(chan dnsutils.DNSMessage, config.Loggers.ElasticSearchClient.ChannelBufferSize),
		outputChan:     make(chan dnsutils.DNSMessage, config.Loggers.ElasticSearchClient.ChannelBufferSize),
		logger:         console,
		config:         config,
		name:           name,
		configChan:     make(chan *pkgconfig.Config),
		RoutingHandler: pkgutils.NewRoutingHandler(config, console, name),
	}
	o.ReadConfig()
	return o
}

func (o *ClickhouseClient) GetName() string { return o.name }

func (o *ClickhouseClient) SetLoggers(loggers []pkgutils.Worker) {}

func (o *ClickhouseClient) AddDroppedRoute(wrk pkgutils.Worker) {
	o.RoutingHandler.AddDroppedRoute(wrk)
}

func (o *ClickhouseClient) AddDefaultRoute(wrk pkgutils.Worker) {
	o.RoutingHandler.AddDefaultRoute(wrk)
}

func (o *ClickhouseClient) ReloadConfig(config *pkgconfig.Config) {
	o.LogInfo("reload configuration!")
	o.configChan <- config
}

func (o *ClickhouseClient) ReadConfig() {
	o.url = o.config.Loggers.ClickhouseClient.URL
	o.user = o.config.Loggers.ClickhouseClient.User
	o.password = o.config.Loggers.ClickhouseClient.Password
	o.database = o.config.Loggers.ClickhouseClient.Database
	o.table = o.config.Loggers.ClickhouseClient.Table
}

func (o *ClickhouseClient) Channel() chan dnsutils.DNSMessage {
	return o.inputChan
}

func (o *ClickhouseClient) GetInputChannel() chan dnsutils.DNSMessage {
	return o.inputChan
}

func (o *ClickhouseClient) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("["+o.name+"] Clickhouse - "+msg, v...)
}

func (o *ClickhouseClient) LogError(msg string, v ...interface{}) {
	o.logger.Error("["+o.name+"] Clickhouse - "+msg, v...)
}

func (o *ClickhouseClient) Stop() {
	o.LogInfo("stopping to run...")
	o.stopRun <- true
	<-o.doneRun

	o.LogInfo("stopping to process...")
	o.stopProcess <- true
	<-o.doneProcess
}

func (o *ClickhouseClient) Run() {
	o.LogInfo("running in background...")

	// prepare next channels
	defaultRoutes, defaultNames := o.RoutingHandler.GetDefaultRoutes()
	droppedRoutes, droppedNames := o.RoutingHandler.GetDroppedRoutes()

	// prepare transforms
	listChannel := []chan dnsutils.DNSMessage{}
	listChannel = append(listChannel, o.outputChan)
	subprocessors := transformers.NewTransforms(&o.config.OutgoingTransformers, o.logger, o.name, listChannel, 0)

	// goroutine to process transformed dns messages
	go o.Process()

	// loop to process incoming messages
RUN_LOOP:
	for {
		select {
		case <-o.stopRun:
			// cleanup transformers
			subprocessors.Reset()

			o.doneRun <- true
			break RUN_LOOP

		case cfg, opened := <-o.configChan:
			if !opened {
				return
			}
			o.config = cfg
			o.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-o.inputChan:
			if !opened {
				o.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDNSMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
				o.RoutingHandler.SendTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to next ?
			o.RoutingHandler.SendTo(defaultRoutes, defaultNames, dm)

			// send to output channel
			o.outputChan <- dm
		}
	}
	o.LogInfo("run terminated")
}

func (o *ClickhouseClient) Process() {
	o.LogInfo("ready to process")

PROCESS_LOOP:
	for {
		select {
		case <-o.stopProcess:
			o.doneProcess <- true
			break PROCESS_LOOP

		// incoming dns message to process
		case dm, opened := <-o.outputChan:
			if !opened {
				o.LogInfo("output channel closed!")
				return
			}
			t, err := time.Parse(time.RFC3339, dm.DNSTap.TimestampRFC3339)
			timensec := ""
			if err == nil {
				timensec = strconv.Itoa(int(t.UnixNano()))
			}
			data := ClickhouseData{
				Identity:  dm.DNSTap.Identity,
				QueryIP:   dm.NetworkInfo.QueryIP,
				QName:     dm.DNS.Qname,
				Operation: dm.DNSTap.Operation,
				Family:    dm.NetworkInfo.Family,
				Protocol:  dm.NetworkInfo.Protocol,
				QType:     dm.DNS.Qtype,
				RCode:     dm.DNS.Rcode,
				TimeNSec:  timensec,
				TimeStamp: strconv.Itoa(int(int64(dm.DNSTap.TimeSec))),
			}
			// nolint
			url := o.url + "?query=INSERT%20INTO%20" + o.database + "." + o.table + "(identity,queryip,qname,operation,family,protocol,qtype,rcode,timensec,timestamp)%20VALUES%20('" + data.Identity + "','" + data.QueryIP + "','" + data.QName + "','" + data.Operation + "','" + data.Family + "','" + data.Protocol + "','" + data.QType + "','" + data.RCode + "','" + data.TimeNSec + "','" + data.TimeStamp + "')"
			req, _ := http.NewRequest("POST", url, nil)

			req.Header.Add("Accept", "*/*")
			req.Header.Add("X-ClickHouse-User", o.user)
			req.Header.Add("X-ClickHouse-Key", o.password)

			_, errReq := http.DefaultClient.Do(req)
			if errReq != nil {
				o.LogError(errReq.Error())
			}
		}
	}
	o.LogInfo("processing terminated")
}
