package pkgconfig

import "testing"

func TestConfigTransformersSetDefault(t *testing.T) {
	config := ConfigTransformers{}
	config.SetDefault()

	if config.UserPrivacy.Enable != false {
		t.Errorf("user privay should be disabled")
	}
	if config.Filtering.Enable != false {
		t.Errorf("filtering should be disabled")
	}
	if config.Normalize.Enable != false {
		t.Errorf("normalize should be disabled")
	}
	if config.GeoIP.Enable != false {
		t.Errorf("geo should be disabled")
	}
}
