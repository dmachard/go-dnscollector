package workers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
)

var (
	separator = "','"
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
	*GenericWorker
}

func NewClickhouseClient(config *pkgconfig.Config, console *logger.Logger, name string) *ClickhouseClient {
	w := &ClickhouseClient{GenericWorker: NewGenericWorker(config, console, name, "clickhouse", pkgconfig.DefaultBufferSize, pkgconfig.DefaultMonitor)}
	w.ReadConfig()
	return w
}

func (w *ClickhouseClient) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	// prepare next channels
	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := GetRoutes(w.GetDroppedRoutes())

	// prepare transforms
	subprocessors := transformers.NewTransforms(&w.GetConfig().OutgoingTransformers, w.GetLogger(), w.GetName(), w.GetOutputChannelAsList(), 0)

	// goroutine to process transformed dns messages
	go w.StartLogging()

	// loop to process incoming messages
	for {
		select {
		case <-w.OnStop():
			w.StopLogger()
			subprocessors.Reset()
			return

			// new config provided?
		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			w.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-w.GetInputChannel():
			if !opened {
				w.LogInfo("input channel closed!")
				return
			}
			// count global messages
			w.CountIngressTraffic()

			// apply tranforms, init dns message with additionnals parts if necessary
			transformResult, err := subprocessors.ProcessMessage(&dm)
			if err != nil {
				w.LogError(err.Error())
			}
			if transformResult == transformers.ReturnDrop {
				w.SendTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to output channel
			w.GetOutputChannel() <- dm

			// send to next ?
			w.SendTo(defaultRoutes, defaultNames, dm)

		}
	}
}

func (w *ClickhouseClient) StartLogging() {
	w.LogInfo("logging has started")
	defer w.LoggingDone()

	for {
		select {
		case <-w.OnLoggerStopped():
			return

			// incoming dns message to process
		case dm, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("output channel closed!")
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
			url := w.GetConfig().Loggers.ClickhouseClient.URL + "?query=INSERT%20INTO%20"
			url += w.GetConfig().Loggers.ClickhouseClient.Database + "." + w.GetConfig().Loggers.ClickhouseClient.Table
			url += "(identity,queryip,qname,operation,family,protocol,qtype,rcode,timensec,timestamp)%20VALUES%20('" + data.Identity + separator
			url += data.QueryIP + separator + data.QName + separator + data.Operation + separator + data.Family + separator + data.Protocol
			url += separator + data.QType + separator + data.RCode + separator + data.TimeNSec + separator + data.TimeStamp + "')"
			req, _ := http.NewRequest("POST", url, nil)

			req.Header.Add("Accept", "*/*")
			req.Header.Add("X-ClickHouse-User", w.GetConfig().Loggers.ClickhouseClient.User)
			req.Header.Add("X-ClickHouse-Key", w.GetConfig().Loggers.ClickhouseClient.Password)

			_, errReq := http.DefaultClient.Do(req)
			if errReq != nil {
				w.LogError(errReq.Error())
			}
		}
	}
}
