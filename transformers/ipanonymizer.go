package transformers

import (
	"net"
	"strings"

	"github.com/dmachard/go-dnscollector/dnsutils"
)

var (
	defaultIPv4Mask = net.IPv4Mask(255, 255, 0, 0)                                                       // /24
	defaultIPv6Mask = net.IPMask{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0} // /64
)

type IpAnonymizerSubproc struct {
	config  *dnsutils.Config
	enabled bool
	v4Mask  net.IPMask
	v6Mask  net.IPMask
}

func NewIpAnonymizerSubprocessor(config *dnsutils.Config) IpAnonymizerSubproc {
	s := IpAnonymizerSubproc{
		config: config,
		v4Mask: defaultIPv4Mask,
		v6Mask: defaultIPv6Mask,
	}

	s.ReadConfig()

	return s
}

func (s *IpAnonymizerSubproc) ReadConfig() {
	s.enabled = s.config.Transformers.UserPrivacy.AnonymizeIP
}

func (s *IpAnonymizerSubproc) IsEnabled() bool {
	return s.enabled
}

func (s *IpAnonymizerSubproc) Anonymize(ip string) string {

	ipaddr := net.ParseIP(ip)
	isipv4 := strings.LastIndex(ip, ".")

	// ipv4, /16 mask
	if isipv4 != -1 {
		return ipaddr.Mask(s.v4Mask).String()
	}

	// ipv6, /64 mask
	return ipaddr.Mask(s.v6Mask).String()
}
