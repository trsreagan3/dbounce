// config_test.go covers the anomaly_detection declarative config
// loader (#718 ADOPT-4). BYTE-IDENTICAL across the three Go repos.
package anomaly

import "testing"

func TestLoadConfigDefaults(t *testing.T) {
	c, err := LoadConfig(nil)
	if err != nil {
		t.Fatalf("nil block should yield disabled default: %v", err)
	}
	if c.Enabled {
		t.Fatalf("default config must be DISABLED per honest-positioning")
	}
	if c.Mode != "alert" {
		t.Fatalf("default mode must be alert (not block) per safety-mode-lean-permissive; got %q", c.Mode)
	}
	if c.Sensitivity != "medium" {
		t.Fatalf("default sensitivity must be medium; got %q", c.Sensitivity)
	}
}

func TestLoadConfigSensitivityThresholds(t *testing.T) {
	cases := map[string]float64{"low": 3.0, "medium": 2.0, "high": 1.5}
	for sens, want := range cases {
		c, err := LoadConfig(map[string]any{"enabled": true, "sensitivity": sens})
		if err != nil {
			t.Fatalf("sensitivity %q: %v", sens, err)
		}
		if got := c.SigmaThreshold(); got != want {
			t.Fatalf("sensitivity %q: sigma=%v want %v", sens, got, want)
		}
	}
}

func TestLoadConfigDurationParsing(t *testing.T) {
	c, err := LoadConfig(map[string]any{"enabled": true, "baseline_window": "7d"})
	if err != nil {
		t.Fatalf("7d parse: %v", err)
	}
	if c.BaselineWindowSeconds != 7*86400 {
		t.Fatalf("7d should be %d seconds; got %d", 7*86400, c.BaselineWindowSeconds)
	}
}

func TestLoadConfigRejectsBadMode(t *testing.T) {
	if _, err := LoadConfig(map[string]any{"mode": "nuke"}); err == nil {
		t.Fatalf("expected error on invalid mode")
	}
}

func TestLoadConfigRejectsUnknownKey(t *testing.T) {
	if _, err := LoadConfig(map[string]any{"enabled": true, "bogus": 1}); err == nil {
		t.Fatalf("expected error on unknown key (additionalProperties:false semantics)")
	}
}

func TestLoadConfigRejectsBadDecay(t *testing.T) {
	if _, err := LoadConfig(map[string]any{"enabled": true, "baseline_decay_rate": 1.5}); err == nil {
		t.Fatalf("expected error on decay rate outside (0,1]")
	}
}

func TestCanonicalResourcePatternPrivacy(t *testing.T) {
	cases := map[string]string{
		"arn:aws:s3:us-east-1:123456789012:prod-bucket/key": "arn:aws:s3::prod",
		"production/web-pod-7":                               "k8s:prod",
		"analytics.events":                                  "sql:other",
		"*":                                                 "*",
		"":                                                  "-",
	}
	for in, want := range cases {
		if got := canonicalResourcePattern(in); got != want {
			t.Fatalf("canonicalResourcePattern(%q) = %q; want %q", in, got, want)
		}
	}
}
