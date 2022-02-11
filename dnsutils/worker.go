package dnsutils

type Worker interface {
	Stop()
	Run()
	Channel() chan DnsMessage
	ReadConfig()
}
