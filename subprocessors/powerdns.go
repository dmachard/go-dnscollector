package subprocessors

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
	powerdns_protobuf "github.com/dmachard/go-powerdns-protobuf"
	"google.golang.org/protobuf/proto"
)

type PdnsProcessor struct {
	done     chan bool
	recvFrom chan []byte
	logger   *logger.Logger
	config   *dnsutils.Config
}

func NewPdnsProcessor(config *dnsutils.Config, logger *logger.Logger) PdnsProcessor {
	logger.Info("powerdns processor - initialization...")
	d := PdnsProcessor{
		done:     make(chan bool),
		recvFrom: make(chan []byte, 512),
		logger:   logger,
		config:   config,
	}

	d.ReadConfig()

	return d
}

func (c *PdnsProcessor) ReadConfig() {
	c.logger.Info("processor powerdns parser - config")
}

func (c *PdnsProcessor) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("processor powerdns parser - "+msg, v...)
}

func (c *PdnsProcessor) LogError(msg string, v ...interface{}) {
	c.logger.Error("procesor powerdns parser - "+msg, v...)
}

func (d *PdnsProcessor) GetChannel() chan []byte {
	return d.recvFrom
}

func (d *PdnsProcessor) Stop() {
	close(d.recvFrom)

	// read done channel and block until run is terminated
	<-d.done
	close(d.done)
}

func (d *PdnsProcessor) Run(sendTo []chan dnsutils.DnsMessage) {

	pbdm := &powerdns_protobuf.PBDNSMessage{}

	// read incoming dns message
	d.LogInfo("running... waiting incoming dns message")
	for data := range d.recvFrom {
		err := proto.Unmarshal(data, pbdm)
		if err != nil {
			continue
		}

		dm := dnsutils.DnsMessage{}
		dm.Init()

		dm.DnsTap.Operation = pbdm.GetType().String()

		dm.NetworkInfo.Family = pbdm.GetSocketFamily().String()
		dm.NetworkInfo.Protocol = pbdm.GetSocketProtocol().String()

		dm.NetworkInfo.QueryIp = net.IP(pbdm.From).String()
		dm.NetworkInfo.QueryPort = strconv.FormatUint(uint64(pbdm.GetFromPort()), 10)
		dm.NetworkInfo.ResponseIp = net.IP(pbdm.To).String()
		dm.NetworkInfo.ResponsePort = strconv.FormatUint(uint64(pbdm.GetToPort()), 10)

		dm.DNS.Id = int(pbdm.GetId())
		dm.DNS.Length = int(pbdm.GetInBytes())
		dm.DnsTap.TimeSec = int(pbdm.GetTimeSec())
		dm.DnsTap.TimeNsec = int(pbdm.GetTimeUsec())

		if int(pbdm.Type.Number())%2 == 1 {
			dm.DNS.Type = dnsutils.DnsQuery
		} else {
			dm.DNS.Type = dnsutils.DnsReply
		}

		dm.DNS.Rcode = dnsutils.RcodeToString(int(pbdm.Response.GetRcode()))

		// compute timestamp
		dm.DnsTap.Timestamp = float64(dm.DnsTap.TimeSec) + float64(dm.DnsTap.TimeNsec)/1e9
		ts := time.Unix(int64(dm.DnsTap.TimeSec), int64(dm.DnsTap.TimeNsec))
		dm.DnsTap.TimestampRFC3339 = ts.UTC().Format(time.RFC3339Nano)

		if d.config.Subprocessors.QnameLowerCase {
			dm.DNS.Qname = strings.ToLower(pbdm.Question.GetQName())
		} else {
			dm.DNS.Qname = pbdm.Question.GetQName()
		}

		dm.DNS.Qtype = dnsutils.RdatatypeToString(int(pbdm.Question.GetQType()))

		// dispatch dns message to all generators
		for i := range sendTo {
			sendTo[i] <- dm
		}
	}

	// dnstap channel closed
	d.done <- true
}
