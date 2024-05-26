package pkgconfig

import (
	"testing"
)

func TestConfigPipelines_IsValid(t *testing.T) {
	testCases := []struct {
		name      string
		config    map[string]interface{}
		expectErr bool
		errorMsg  string
	}{
		{
			name: "Valid Config",
			config: map[string]interface{}{
				"name":           "pipeline1",
				"transforms":     map[string]interface{}{"normalize": map[string]interface{}{}},
				"routing-policy": map[string]interface{}{"forward": []string{"route1"}, "dropped": []string{"route2"}},
			},
			expectErr: false,
		},
		{
			name: "Missing Name",
			config: map[string]interface{}{
				"transforms":     map[string]interface{}{"normalize": map[string]interface{}{}},
				"routing-policy": map[string]interface{}{"forward": []string{"route1"}, "dropped": []string{"route2"}},
			},
			expectErr: true,
			errorMsg:  "name key is required",
		},
		{
			name: "Invalid Routing Policy Key",
			config: map[string]interface{}{
				"name":           "testPipeline",
				"routing-policy": map[string]interface{}{"forward": []string{"route1"}, "invalid": []string{"route2"}},
			},
			expectErr: true,
			errorMsg:  "routing-policy - invalid key 'invalid'",
		},
		{
			name: "Invalid Transforms",
			config: map[string]interface{}{
				"name": "testPipeline",
				"transforms": map[string]interface{}{
					"invalidTransform": "invalidValue",
				},
			},
			expectErr: true,
			errorMsg:  "transform - unknown key=`invalidTransform`",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pipeline := ConfigPipelines{}
			err := pipeline.IsValid(tc.config)

			if tc.expectErr {
				if err == nil {
					t.Errorf("expected error but got nil")
				} else if err.Error() != tc.errorMsg {
					t.Errorf("expected error message '%s', but got '%s'", tc.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, but got %v", err)
				}
			}
		})
	}
}
