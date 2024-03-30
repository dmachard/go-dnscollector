package transformers

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
	"golang.org/x/net/publicsuffix"
)

func parseCIDRMask(mask string) (net.IPMask, error) {
	parts := strings.Split(mask, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid mask format, expected /integer: %s", mask)
	}

	ones, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid /%s cidr", mask)
	}

	if strings.Contains(parts[0], ":") {
		ipv6Mask := net.CIDRMask(ones, 128)
		return ipv6Mask, nil
	}

	ipv4Mask := net.CIDRMask(ones, 32)
	return ipv4Mask, nil
}

type UserPrivacyProcessor struct {
	config            *pkgconfig.ConfigTransformers
	v4Mask, v6Mask    net.IPMask
	outChannels       []chan dnsutils.DNSMessage
	LogInfo, LogError func(msg string, v ...interface{})
}

func NewUserPrivacyTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string,
	instance int, outChannels []chan dnsutils.DNSMessage) UserPrivacyProcessor {
	s := UserPrivacyProcessor{config: config, outChannels: outChannels}

	s.LogInfo = func(msg string, v ...interface{}) {
		log := fmt.Sprintf("transformer - [%s] conn #%d - userprivacy - ", name, instance)
		logger.Info(log+msg, v...)
	}

	s.LogError = func(msg string, v ...interface{}) {
		log := fmt.Sprintf("transformer - [%s] conn #%d - userprivacy - ", name, instance)
		logger.Error(log+msg, v...)
	}

	s.ReadConfig()
	return s
}

func (s *UserPrivacyProcessor) ReadConfig() {

	var err error
	s.v4Mask, err = parseCIDRMask(s.config.UserPrivacy.AnonymizeIPV4Bits)
	if err != nil {
		s.LogError("unable to init v4 mask: %v", err)
	}

	if !strings.Contains(s.config.UserPrivacy.AnonymizeIPV6Bits, ":") {
		s.LogError("invalid v6 mask, expect format ::/integer")
	}
	s.v6Mask, err = parseCIDRMask(s.config.UserPrivacy.AnonymizeIPV6Bits)
	if err != nil {
		s.LogError("unable to init v6 mask: %v", err)
	}
}

func (s *UserPrivacyProcessor) ReloadConfig(config *pkgconfig.ConfigTransformers) {
	s.config = config
}

func (s *UserPrivacyProcessor) MinimazeQname(qname string) string {
	if etpo, err := publicsuffix.EffectiveTLDPlusOne(qname); err == nil {
		return etpo
	}

	return qname
}

func (s *UserPrivacyProcessor) AnonymizeIP(ip string) string {
	// if mask is nil, something is wrong
	if s.v4Mask == nil {
		return ip
	}
	if s.v6Mask == nil {
		return ip
	}

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
	switch s.config.UserPrivacy.HashIPAlgo {
	case "sha1":
		hash := sha1.New()
		hash.Write([]byte(ip))
		return fmt.Sprintf("%x", hash.Sum(nil))
	case "sha256":
		hash := sha256.New()
		hash.Write([]byte(ip))
		return fmt.Sprintf("%x", hash.Sum(nil))
	case "sha512": // nolint
		hash := sha512.New()
		hash.Write([]byte(ip))
		return fmt.Sprintf("%x", hash.Sum(nil))
	default:
		return ip
	}
}
