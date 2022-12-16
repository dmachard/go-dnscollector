package transformers

import (
	"crypto/sha1"
	"fmt"
	"net"
	"strings"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"golang.org/x/net/publicsuffix"
)

var (
	defaultIPv4Mask = net.IPv4Mask(255, 255, 0, 0)                                                       // /24
	defaultIPv6Mask = net.IPMask{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0} // /64
)

type UserPrivacyProcessor struct {
	config *dnsutils.ConfigTransformers
	v4Mask net.IPMask
	v6Mask net.IPMask
}

func NewUserPrivacySubprocessor(config *dnsutils.ConfigTransformers) UserPrivacyProcessor {
	s := UserPrivacyProcessor{
		config: config,
		v4Mask: defaultIPv4Mask,
		v6Mask: defaultIPv6Mask,
	}

	return s
}

func (s *UserPrivacyProcessor) MinimazeQname(qname string) string {
	if etpo, err := publicsuffix.EffectiveTLDPlusOne(qname); err == nil {
		return etpo
	}

	return qname
}

func (s *UserPrivacyProcessor) AnonymizeIP(ip string) string {
	ipaddr := net.ParseIP(ip)
	isipv4 := strings.LastIndex(ip, ".")

	// ipv4, /16 mask
	if isipv4 != -1 {
		return ipaddr.Mask(s.v4Mask).String()
	}

	// ipv6, /64 mask
	return ipaddr.Mask(s.v6Mask).String()
}

func (s *UserPrivacyProcessor) HashIP(ip string) string {
	hash := sha1.New()
	hash.Write([]byte(ip))
	return fmt.Sprintf("%x", hash.Sum(nil))
}
