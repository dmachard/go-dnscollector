package workers

import (
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
)

type DNSProcessor struct {
	*GenericWorker
}

func NewDNSProcessor(config *pkgconfig.Config, logger *logger.Logger, name string, size int) DNSProcessor {
	w := DNSProcessor{GenericWorker: NewGenericWorker(config, logger, name, "dns processor", size, pkgconfig.DefaultMonitor)}
	return w
}

func (w *DNSProcessor) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	// prepare next channels
	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := GetRoutes(w.GetDroppedRoutes())

	// prepare enabled transformers
	transforms := transformers.NewTransforms(&w.GetConfig().IngoingTransformers, w.GetLogger(), w.GetName(), defaultRoutes, 0)

	// read incoming dns message
	for {
		select {
		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			transforms.ReloadConfig(&cfg.IngoingTransformers)

		case <-w.OnStop():
			transforms.Reset()
			return

		case dm, opened := <-w.GetInputChannel():
			if !opened {
				w.LogInfo("channel closed, exit")
				return
			}
			// count global messages
			w.CountIngressTraffic()

			// compute timestamp
			ts := time.Unix(int64(dm.DNSTap.TimeSec), int64(dm.DNSTap.TimeNsec))
			dm.DNSTap.Timestamp = ts.UnixNano()
			dm.DNSTap.TimestampRFC3339 = ts.UTC().Format(time.RFC3339Nano)

			// decode the dns payload
			dnsHeader, err := dnsutils.DecodeDNS(dm.DNS.Payload)
			if err != nil {
				dm.DNS.MalformedPacket = true
				w.LogError("dns parser malformed packet: %s - %v+", err, dm)
			}

			// get number of questions
			dm.DNS.QuestionsCount = dnsHeader.Qdcount

			// dns reply ?
			if dnsHeader.Qr == 1 {
				dm.DNSTap.Operation = "CLIENT_RESPONSE"
				dm.DNS.Type = dnsutils.DNSReply
				qip := dm.NetworkInfo.QueryIP
				qport := dm.NetworkInfo.QueryPort
				dm.NetworkInfo.QueryIP = dm.NetworkInfo.ResponseIP
				dm.NetworkInfo.QueryPort = dm.NetworkInfo.ResponsePort
				dm.NetworkInfo.ResponseIP = qip
				dm.NetworkInfo.ResponsePort = qport
			} else {
				dm.DNS.Type = dnsutils.DNSQuery
				dm.DNSTap.Operation = dnsutils.DNSTapClientQuery
			}

			if err = dnsutils.DecodePayload(&dm, &dnsHeader, w.GetConfig()); err != nil {
				w.LogError("%v - %v", err, dm)
			}

			if dm.DNS.MalformedPacket {
				if w.GetConfig().Global.Trace.LogMalformed {
					w.LogInfo("payload: %v", dm.DNS.Payload)
				}
			}

			// count output packets
			w.CountEgressTraffic()

			// apply all enabled transformers
			transformResult, err := transforms.ProcessMessage(&dm)
			if err != nil {
				w.LogError(err.Error())
			}
			if transformResult == transformers.ReturnDrop {
				w.SendDroppedTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// convert latency to human
			//dm.DNSTap.LatencySec = fmt.Sprintf("%.6f", dm.DNSTap.Latency)

			// dispatch dns message to all generators
			w.SendForwardedTo(defaultRoutes, defaultNames, dm)
		}
	}
}
