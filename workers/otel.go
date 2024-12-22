package workers

import (
	"context"
	"log"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
)

type trackedSpan struct {
	span      trace.Span
	startTime time.Time
}

type OpenTelemetryClient struct {
	*GenericWorker
	tracerProviders map[string]*sdktrace.TracerProvider
}

func NewOpenTelemetryClient(config *pkgconfig.Config, console *logger.Logger, name string) *OpenTelemetryClient {
	bufSize := config.Global.Worker.ChannelBufferSize
	if config.Loggers.OpenTelemetryClient.ChannelBufferSize > 0 {
		bufSize = config.Loggers.OpenTelemetryClient.ChannelBufferSize
	}

	w := &OpenTelemetryClient{
		GenericWorker:   NewGenericWorker(config, console, name, "opentelemetry", bufSize, pkgconfig.DefaultMonitor),
		tracerProviders: make(map[string]*sdktrace.TracerProvider),
	}
	return w
}

func (w *OpenTelemetryClient) initTracerProvider(serviceName string) *sdktrace.TracerProvider {
	exporter, err := otlptrace.New(context.Background(), otlptracegrpc.NewClient(
		otlptracegrpc.WithEndpoint(w.config.Loggers.OpenTelemetryClient.OtelEndpoint),
		otlptracegrpc.WithInsecure(),
	))
	if err != nil {
		log.Fatalf("failed to create OTLP exporter: %v", err)
	}

	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewSchemaless(
			attribute.String("service.name", serviceName),
		)),
	)
	return tracerProvider
}

func (w *OpenTelemetryClient) getTracer(serviceName string) trace.Tracer {
	if tp, exists := w.tracerProviders[serviceName]; exists {
		return tp.Tracer("")
	}

	tp := w.initTracerProvider(serviceName)
	w.tracerProviders[serviceName] = tp
	return tp.Tracer("")
}

func (w *OpenTelemetryClient) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	// prepare next channels
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
				w.SendDroppedTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to output channel
			w.CountEgressTraffic()
			w.GetOutputChannel() <- dm
		}
	}
}

func (w *OpenTelemetryClient) StartLogging() {
	w.LogInfo("logging has started")
	defer w.LoggingDone()

	// prepare next channels
	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())

	// Maps to follow the state of the spans
	requestorSpans := sync.Map{}
	messageSpans := sync.Map{}
	resolverSpans := sync.Map{}

	go w.cleanupSpans(&requestorSpans, &messageSpans, &resolverSpans, time.Duration(w.config.Loggers.OpenTelemetryClient.MaxSpanTime)*time.Second)

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

			timestamp, err := time.Parse(time.RFC3339, dm.DNSTap.TimestampRFC3339)
			if err != nil {
				w.LogWarning("invalid timestamp: %v", err)
				continue
			}
			tracer := w.getTracer(dm.DNSTap.Identity)

			// ini opentelemetry with default values
			dm.OpenTelemetry = &dnsutils.LoggerOpenTelemetry{}

			switch dm.DNSTap.Operation {
			case "CLIENT_QUERY":
				w.handleClientQuery(&requestorSpans, &messageSpans, tracer, &dm, timestamp)
			case "CLIENT_RESPONSE":
				w.handleClientResponse(&requestorSpans, &messageSpans, &dm, timestamp)
			case "RESOLVER_QUERY":
				w.handleResolverQuery(&messageSpans, &resolverSpans, tracer, &dm, timestamp)
			case "RESOLVER_RESPONSE":
				w.handleResolverResponse(&resolverSpans, &dm, timestamp)
			}

			// send to next ?
			w.SendForwardedTo(defaultRoutes, defaultNames, dm)
		}
	}
}

func (w *OpenTelemetryClient) handleClientQuery(requestorSpans, messageSpans *sync.Map, tracer trace.Tracer, dm *dnsutils.DNSMessage, timestamp time.Time) {
	if parentSpan, ok := requestorSpans.Load(dm.PowerDNS.RequestorID); ok {
		_, childSpan := tracer.Start(trace.ContextWithSpan(context.Background(), parentSpan.(trackedSpan).span), "Client Query "+dm.NetworkInfo.ResponseIP+" ("+dm.DNS.Qname+" / "+dm.DNS.Qtype+" )", trace.WithTimestamp(timestamp))
		childSpan.SetAttributes(attribute.String("dns.qname", dm.DNS.Qname))
		childSpan.SetAttributes(attribute.String("source.ip", dm.NetworkInfo.QueryIP))
		childSpan.SetAttributes(attribute.String("destination.ip", dm.NetworkInfo.ResponseIP))

		messageSpans.Store(dm.PowerDNS.MessageID, trackedSpan{span: childSpan, startTime: timestamp})
		dm.OpenTelemetry.TraceID = childSpan.SpanContext().TraceID().String()
	} else {
		_, clientSpan := tracer.Start(context.Background(), "Client Query "+dm.NetworkInfo.ResponseIP+" ("+dm.DNS.Qname+" / "+dm.DNS.Qtype+" )", trace.WithTimestamp(timestamp))
		clientSpan.SetAttributes(attribute.String("dns.qname", dm.DNS.Qname))
		clientSpan.SetAttributes(attribute.String("source.ip", dm.NetworkInfo.QueryIP))
		clientSpan.SetAttributes(attribute.String("destination.ip", dm.NetworkInfo.ResponseIP))
		requestorSpans.Store(dm.PowerDNS.RequestorID, trackedSpan{span: clientSpan, startTime: timestamp})
		messageSpans.Store(dm.PowerDNS.MessageID, trackedSpan{span: clientSpan, startTime: timestamp})
		dm.OpenTelemetry.TraceID = clientSpan.SpanContext().TraceID().String()
	}
}

func (w *OpenTelemetryClient) handleClientResponse(requestorSpans, messageSpans *sync.Map, dm *dnsutils.DNSMessage, timestamp time.Time) {
	if span, ok := messageSpans.Load(dm.PowerDNS.MessageID); ok {
		tracked := span.(trackedSpan)
		tracked.span.SetAttributes(attribute.String("dns.rcode", dm.DNS.Rcode))
		if dm.DNS.Rcode != dnsutils.DNSRcodeNoError {
			tracked.span.SetAttributes(attribute.String("error", "true"))
			tracked.span.SetAttributes(attribute.String("error.message", "Non-successful DNS response code"))
		}

		tracked.span.End(trace.WithTimestamp(timestamp))
		messageSpans.Delete(dm.PowerDNS.MessageID)
		dm.OpenTelemetry.TraceID = tracked.span.SpanContext().TraceID().String()
	}

	if span, ok := requestorSpans.Load(dm.PowerDNS.RequestorID); ok {
		tracked := span.(trackedSpan)
		tracked.span.SetAttributes(attribute.String("dns.rcode", dm.DNS.Rcode))

		if dm.DNS.Rcode != dnsutils.DNSRcodeNoError {
			tracked.span.SetAttributes(attribute.String("error", "true"))
			tracked.span.SetAttributes(attribute.String("error.message", "Non-successful DNS response code"))
		}

		tracked.span.End(trace.WithTimestamp(timestamp))
		requestorSpans.Delete(dm.PowerDNS.RequestorID)
	}
}

func (w *OpenTelemetryClient) handleResolverQuery(messageSpans, resolverSpans *sync.Map, tracer trace.Tracer, dm *dnsutils.DNSMessage, timestamp time.Time) {
	if tracked, ok := messageSpans.Load(dm.PowerDNS.InitialRequestorID); ok {
		_, resolverSpan := tracer.Start(trace.ContextWithSpan(context.Background(), tracked.(trackedSpan).span), "Resolver Query "+dm.NetworkInfo.ResponseIP+" ("+dm.DNS.Qname+" / "+dm.DNS.Qtype+" )", trace.WithTimestamp(timestamp))
		resolverSpan.SetAttributes(attribute.String("dns.qname", dm.DNS.Qname))
		resolverSpan.SetAttributes(attribute.String("source.ip", dm.NetworkInfo.QueryIP))
		resolverSpan.SetAttributes(attribute.String("destination.ip", dm.NetworkInfo.ResponseIP))
		resolverSpans.Store(dm.PowerDNS.MessageID, trackedSpan{span: resolverSpan, startTime: timestamp})
		dm.OpenTelemetry.TraceID = resolverSpan.SpanContext().TraceID().String()
	} else {
		// No parent span found, create a root span
		_, resolverSpan := tracer.Start(context.Background(), "Resolver Query ("+dm.DNS.Qname+")", trace.WithTimestamp(timestamp))
		resolverSpan.SetAttributes(attribute.String("dns.qname", dm.DNS.Qname))
		resolverSpan.SetAttributes(attribute.String("source.ip", dm.NetworkInfo.QueryIP))
		resolverSpan.SetAttributes(attribute.String("destination.ip", dm.NetworkInfo.ResponseIP))
		resolverSpans.Store(dm.PowerDNS.MessageID, trackedSpan{span: resolverSpan, startTime: timestamp})
		dm.OpenTelemetry.TraceID = resolverSpan.SpanContext().TraceID().String()
	}
}

func (w *OpenTelemetryClient) handleResolverResponse(resolverSpans *sync.Map, dm *dnsutils.DNSMessage, timestamp time.Time) {
	if span, ok := resolverSpans.Load(dm.PowerDNS.MessageID); ok {
		tracked := span.(trackedSpan)
		tracked.span.SetAttributes(attribute.String("dns.rcode", dm.DNS.Rcode))

		if dm.DNS.Rcode != dnsutils.DNSRcodeNoError {
			tracked.span.SetAttributes(attribute.String("error", "true"))
			tracked.span.SetAttributes(attribute.String("error.message", "Non-successful DNS response code"))
		}

		tracked.span.End(trace.WithTimestamp(timestamp))
		resolverSpans.Delete(dm.PowerDNS.MessageID)
		dm.OpenTelemetry.TraceID = tracked.span.SpanContext().TraceID().String()
	}
}

func (w *OpenTelemetryClient) cleanupSpans(requestorSpans, messageSpans, resolverSpans *sync.Map, maxSpanDuration time.Duration) {
	ticker := time.NewTicker(time.Duration(w.config.Loggers.OpenTelemetryClient.CleanupSpansInterval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		requestorSpans.Range(func(key, value interface{}) bool {
			tracked := value.(trackedSpan)
			if tracked.startTime.Add(maxSpanDuration).Before(now) {
				tracked.span.SetAttributes(attribute.String("error", "timeout"))
				tracked.span.End()
				requestorSpans.Delete(key)
			}
			return true
		})

		messageSpans.Range(func(key, value interface{}) bool {
			tracked := value.(trackedSpan)
			if tracked.startTime.Add(maxSpanDuration).Before(now) {
				tracked.span.SetAttributes(attribute.String("error", "timeout"))
				tracked.span.End()
				messageSpans.Delete(key)
			}
			return true
		})

		resolverSpans.Range(func(key, value interface{}) bool {
			tracked := value.(trackedSpan)
			if tracked.startTime.Add(maxSpanDuration).Before(now) {
				tracked.span.SetAttributes(attribute.String("error", "timeout"))
				tracked.span.End()
				resolverSpans.Delete(key)
			}
			return true
		})
	}
}
