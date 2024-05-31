package pkginit

import (
	"testing"

	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/workers"
	"github.com/dmachard/go-logger"
)

func TestPipelines_IsEnabled(t *testing.T) {
	// Create a mock configuration for testing
	config := &pkgconfig.Config{}
	config.Pipelines = []pkgconfig.ConfigPipelines{{Name: "validroute"}}

	if !IsPipelinesEnabled(config) {
		t.Errorf("pipelines should be enabled!")
	}
}

func TestPipelines_IsRouteExist(t *testing.T) {
	// Create a mock configuration for testing
	config := &pkgconfig.Config{}
	config.Pipelines = []pkgconfig.ConfigPipelines{
		{Name: "validroute"},
	}

	// Case where the route exists
	existingRoute := "validroute"
	err := IsRouteExist(existingRoute, config)
	if err != nil {
		t.Errorf("For the existing route %s, an unexpected error was returned: %v", existingRoute, err)
	}

	// Case where the route does not exist
	nonExistingRoute := "non-existent-route"
	err = IsRouteExist(nonExistingRoute, config)
	if err == nil {
		t.Errorf("For the non-existing route %s, an expected error was not returned. Received error: %v", nonExistingRoute, err)
	}
}

func TestPipelines_StanzaNameIsUniq(t *testing.T) {
	// Create a mock configuration for testing
	config := &pkgconfig.Config{}
	config.Pipelines = []pkgconfig.ConfigPipelines{
		{Name: "unique-stanza"},
		{Name: "duplicate-stanza"},
		{Name: "duplicate-stanza"},
	}

	// Case where the stanza name is unique
	uniqueStanzaName := "unique-stanza"
	err := StanzaNameIsUniq(uniqueStanzaName, config)
	if err != nil {
		t.Errorf("For the unique stanza name %s, an unexpected error was returned: %v", uniqueStanzaName, err)
	}

	// Case where the stanza name is not unique
	duplicateStanzaName := "duplicate-stanza"
	err = StanzaNameIsUniq(duplicateStanzaName, config)
	if err == nil {
		t.Errorf("For the duplicate stanza name %s, an expected error was not returned. Received error: %v", duplicateStanzaName, err)
	}
}

func TestPipelines_NoRoutesDefined(t *testing.T) {
	logger := logger.New(true)

	// Create a mock configuration for testing
	config := &pkgconfig.Config{}
	config.Pipelines = []pkgconfig.ConfigPipelines{
		{Name: "stanzaA", RoutingPolicy: pkgconfig.PipelinesRouting{Forward: []string{}, Dropped: []string{}}},
		{Name: "stanzaB", RoutingPolicy: pkgconfig.PipelinesRouting{Forward: []string{}, Dropped: []string{}}},
	}

	mapLoggers := make(map[string]workers.Worker)
	mapCollectors := make(map[string]workers.Worker)

	err := InitPipelines(mapLoggers, mapCollectors, config, logger)
	if err == nil {
		t.Errorf("Want err, got nil")
	} else if err.Error() != "no routes are defined" {
		t.Errorf("Unexpected error: %s", err.Error())
	}
}
