package common

import "github.com/dmachard/go-dnscollector/dnsmessage"

type Worker interface {
	Stop()
	Run()
	Channel() chan dnsmessage.DnsMessage
}
