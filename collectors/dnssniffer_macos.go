//go:build macos
// +build macos

package collectors

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

// workaround for macos, not yet supported
func NewDnsSniffer(loggers []dnsutils.Worker, config *dnsutils.Config, logger *logger.Logger) *DnsSniffer {
}
