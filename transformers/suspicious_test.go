package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

func TestSuspiciousMalformedPacket(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfig()
	config.Transformers.Suspicious.Enable = true

	// init subproccesor
	suspicious := NewSuspiciousSubprocessor(config, logger.New(false), "test")

	// malformed DNS message
	dm := dnsutils.GetFakeDnsMessage()
	dm.DNS.MalformedPacket = true

	suspicious.CheckIfSuspicious(&dm)

	if dm.Suspicious.Score != 1.0 {
		t.Errorf("suspicious score should be equal to 1.0")
	}

	if dm.Suspicious.Flags.MalformedPacket != true {
		t.Errorf("suspicious malformed packet flag should be equal to true")
	}
}

func TestSuspiciousLongDomain(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfig()
	config.Transformers.Suspicious.Enable = true
	config.Transformers.Suspicious.ThresholdQnameLen = 4

	// init subproccesor
	suspicious := NewSuspiciousSubprocessor(config, logger.New(false), "test")

	// malformed DNS message
	dm := dnsutils.GetFakeDnsMessage()
	dm.DNS.Qname = "longdomain.com"

	suspicious.CheckIfSuspicious(&dm)

	if dm.Suspicious.Score != 1.0 {
		t.Errorf("suspicious score should be equal to 1.0")
	}

	if dm.Suspicious.Flags.LongDomain != true {
		t.Errorf("suspicious long domain flag should be equal to true")
	}
}

func TestSuspiciousLargePacket(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfig()
	config.Transformers.Suspicious.Enable = true
	config.Transformers.Suspicious.ThresholdPacketLen = 4

	// init subproccesor
	suspicious := NewSuspiciousSubprocessor(config, logger.New(false), "test")

	// malformed DNS message
	dm := dnsutils.GetFakeDnsMessage()
	dm.DNS.Length = 50
	suspicious.CheckIfSuspicious(&dm)

	if dm.Suspicious.Score != 1.0 {
		t.Errorf("suspicious score should be equal to 1.0")
	}

	if dm.Suspicious.Flags.LargePacket != true {
		t.Errorf("suspicious large packet flag should be equal to true")
	}
}

func TestSuspiciousUncommonQtype(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfig()
	config.Transformers.Suspicious.Enable = true

	// init subproccesor
	suspicious := NewSuspiciousSubprocessor(config, logger.New(false), "test")

	// malformed DNS message
	dm := dnsutils.GetFakeDnsMessage()
	dm.DNS.Qtype = "LOC"
	suspicious.CheckIfSuspicious(&dm)

	if dm.Suspicious.Score != 1.0 {
		t.Errorf("suspicious score should be equal to 1.0")
	}

	if dm.Suspicious.Flags.UncommonQtypes != true {
		t.Errorf("suspicious uncommon qtype flag should be equal to true")
	}
}

func TestSuspiciousExceedMaxLabels(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfig()
	config.Transformers.Suspicious.Enable = true
	config.Transformers.Suspicious.ThresholdMaxLabels = 2

	// init subproccesor
	suspicious := NewSuspiciousSubprocessor(config, logger.New(false), "test")

	// malformed DNS message
	dm := dnsutils.GetFakeDnsMessage()
	dm.DNS.Qname = "test.sub.dnscollector.com"
	suspicious.CheckIfSuspicious(&dm)

	if dm.Suspicious.Score != 1.0 {
		t.Errorf("suspicious score should be equal to 1.0")
	}

	if dm.Suspicious.Flags.ExcessiveNumberLabels != true {
		t.Errorf("suspicious excessive number labels flag should be equal to true")
	}
}

func TestSuspiciousUnallowedChars(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfig()
	config.Transformers.Suspicious.Enable = true

	// init subproccesor
	suspicious := NewSuspiciousSubprocessor(config, logger.New(false), "test")

	// malformed DNS message
	dm := dnsutils.GetFakeDnsMessage()
	dm.DNS.Qname = "AAAAAA==.dnscollector.com"
	suspicious.CheckIfSuspicious(&dm)

	if dm.Suspicious.Score != 1.0 {
		t.Errorf("suspicious score should be equal to 1.0")
	}

	if dm.Suspicious.Flags.UnallowedChars != true {
		t.Errorf("suspicious unallowed chars flag should be equal to true")
	}
}
