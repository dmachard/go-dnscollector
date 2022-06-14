package loggers

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-topmap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type TopMaps struct {
	rcodes *topmap.TopMap
}

type Prometheus struct {
	done         chan bool
	done_api     chan bool
	httpserver   net.Listener
	httpmux      *http.ServeMux
	channel      chan dnsutils.DnsMessage
	config       *dnsutils.Config
	logger       *logger.Logger
	promRegistry *prometheus.Registry
	ver          string

	metricTotalQueries *prometheus.CounterVec
	metricTotalReplies *prometheus.CounterVec
	metricTotalRcodes  *prometheus.CounterVec

	metricsTop map[string]*TopMaps

	name string
}

func NewPrometheus(config *dnsutils.Config, logger *logger.Logger, version string, name string) *Prometheus {
	logger.Info("[%s] logger to prometheus - enabled", name)
	o := &Prometheus{
		done:         make(chan bool),
		done_api:     make(chan bool),
		config:       config,
		channel:      make(chan dnsutils.DnsMessage, 512),
		logger:       logger,
		ver:          version,
		promRegistry: prometheus.NewRegistry(),

		metricsTop: make(map[string]*TopMaps),
		name:       name,
	}
	o.InitProm()
	return o
}

func (o *Prometheus) InitProm() {
	o.metricTotalQueries = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_queries_total", o.config.Loggers.Prometheus.PromPrefix),
			Help: "The total number of received queries",
		},
		[]string{"stream"},
	)
	o.promRegistry.MustRegister(o.metricTotalQueries)

	o.metricTotalReplies = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_replies_total", o.config.Loggers.Prometheus.PromPrefix),
			Help: "The total number of received replies",
		},
		[]string{"stream"},
	)
	o.promRegistry.MustRegister(o.metricTotalReplies)

	o.metricTotalRcodes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_rcodes_total", o.config.Loggers.Prometheus.PromPrefix),
			Help: "The total number of hit per return codes",
		},
		[]string{"stream", "rcode"},
	)
	o.promRegistry.MustRegister(o.metricTotalRcodes)
}

func (o *Prometheus) ReadConfig() {
}

func (o *Prometheus) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("["+o.name+"] prometheus - "+msg, v...)
}

func (o *Prometheus) LogError(msg string, v ...interface{}) {
	o.logger.Error("["+o.name+"] prometheus - "+msg, v...)
}

func (o *Prometheus) Channel() chan dnsutils.DnsMessage {
	return o.channel
}

func (o *Prometheus) Stop() {
	o.LogInfo("stopping...")

	// stopping http server
	o.httpserver.Close()

	// close output channel
	o.LogInfo("closing channel")
	close(o.channel)

	// read done channel and block until run is terminated
	<-o.done
	close(o.done)

	// block and wait until http api is terminated
	<-o.done_api
	close(o.done_api)

	o.LogInfo(" stopped")
}

func (o *Prometheus) BasicAuth(w http.ResponseWriter, r *http.Request) bool {
	login, password, authOK := r.BasicAuth()
	if !authOK {
		return false
	}

	return (login == o.config.Loggers.Prometheus.BasicAuthLogin) && (password == o.config.Loggers.Prometheus.BasicAuthPwd)
}

func (o *Prometheus) Record(dm dnsutils.DnsMessage) {
	if _, ok := o.metricsTop[dm.DnsTap.Identity]; !ok {
		o.metricsTop[dm.DnsTap.Identity] = &TopMaps{rcodes: topmap.NewTopMap(10)}
	}

	o.metricsTop[dm.DnsTap.Identity].rcodes.Inc(dm.DNS.Rcode)

	if dm.DNS.Type == dnsutils.DnsQuery {
		o.metricTotalQueries.WithLabelValues(dm.DnsTap.Identity).Inc()
	} else {
		o.metricTotalReplies.WithLabelValues(dm.DnsTap.Identity).Inc()
	}

	/*	for _, r := range o.metricsTop[dm.DnsTap.Identity].rcodes.Get() {
		if dm.DNS.Rcode == r.Name {
			o.metricTotalRcodes.WithLabelValues(dm.DnsTap.Identity, r.Name).Inc()
		}
	}*/

	o.metricTotalRcodes.WithLabelValues(dm.DnsTap.Identity, dm.DNS.Rcode).Inc()
}

func (s *Prometheus) ListenAndServe() {
	s.LogInfo("starting prometheus metrics...")

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(s.promRegistry, promhttp.HandlerOpts{}))

	var err error
	var listener net.Listener
	addrlisten := s.config.Loggers.Prometheus.ListenIP + ":" + strconv.Itoa(s.config.Loggers.Prometheus.ListenPort)
	// listening with tls enabled ?
	if s.config.Loggers.Prometheus.TlsSupport {
		s.LogInfo("tls support enabled")
		var cer tls.Certificate
		cer, err = tls.LoadX509KeyPair(s.config.Loggers.Prometheus.CertFile, s.config.Loggers.Prometheus.KeyFile)
		if err != nil {
			s.logger.Fatal("loading certificate failed:", err)
		}
		config := &tls.Config{Certificates: []tls.Certificate{cer}}
		listener, err = tls.Listen("tcp", addrlisten, config)

	} else {
		// basic listening
		listener, err = net.Listen("tcp", addrlisten)
	}

	// something wrong ?
	if err != nil {
		s.logger.Fatal("listening failed:", err)
	}

	s.httpserver = listener
	s.httpmux = mux
	s.LogInfo("is listening on %s", listener.Addr())

	http.Serve(s.httpserver, s.httpmux)
	s.LogInfo("terminated")
	s.done_api <- true
}

func (s *Prometheus) Run() {
	s.LogInfo("running in background...")

	// start http server
	go s.ListenAndServe()

LOOP:
	for {
		dm, opened := <-s.channel
		if !opened {
			s.LogInfo("channel closed")
			break LOOP
		}
		// record the dnstap message
		s.Record(dm)

	}
	s.LogInfo("run terminated")

	// the job is done
	s.done <- true
}
