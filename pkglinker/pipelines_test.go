package pkglinker

import (
	"testing"

	"github.com/dmachard/go-dnscollector/pkgconfig"
)

func TestPipeline_IsRouteExist(t *testing.T) {
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

func TestPipeline_StanzaNameIsUniq(t *testing.T) {
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
