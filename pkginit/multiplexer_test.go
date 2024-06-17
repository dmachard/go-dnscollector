package pkginit

import (
	"testing"

	"github.com/dmachard/go-dnscollector/pkgconfig"
)

func TestMuxIsDisabled(t *testing.T) {
	config := &pkgconfig.Config{}
	config.SetDefault()

	if len(config.Multiplexer.Collectors) != 0 {
		t.Error("no collector should enabled")
	}
	if len(config.Multiplexer.Loggers) != 0 {
		t.Error("no loggers should enabled")
	}
	if len(config.Multiplexer.Routes) != 0 {
		t.Error("no routes should be defined")
	}
}

func TestMuxIsLoggerRouted(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()
	config.Multiplexer.Routes = append(config.Multiplexer.Routes, pkgconfig.MultiplexRoutes{Dst: []string{"logger1"}})

	if !IsLoggerRouted(config, "logger1") {
		t.Error("Expected logger1 to be routed, but it wasn't.")
	}
	if IsLoggerRouted(config, "logger3") {
		t.Error("Expected logger3 not to be routed, but it was.")
	}
}

func TestMuxIsCollectorRouted(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()
	config.Multiplexer.Routes = append(config.Multiplexer.Routes, pkgconfig.MultiplexRoutes{Src: []string{"collector1"}})

	if !IsCollectorRouted(config, "collector1") {
		t.Error("Expected collector1 to be routed, but it wasn't.")
	}
	if IsCollectorRouted(config, "collector3") {
		t.Error("Expected collector3 not to be routed, but it was.")
	}
}

func TestMuxRouteIsInvalid(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()
	config.Multiplexer.Routes = append(config.Multiplexer.Routes, pkgconfig.MultiplexRoutes{Src: []string{"collector1"}})

	err := AreRoutesValid(config)
	if err == nil {
		t.Error("expected error because of the invalid route, no one returned")
	}
}
