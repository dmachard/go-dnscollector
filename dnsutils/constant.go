package dnsutils

const (
	ProtoDoT = "DOT"
	ProtoDoH = "DOH"

	DNSRcodeNXDomain = "NXDOMAIN"
	DNSRcodeServFail = "SERVFAIL"
	DNSRcodeTimeout  = "TIMEOUT"

	DNSTapOperationQuery = "QUERY"
	DNSTapOperationReply = "REPLY"

	DNSTapClientResponse = "CLIENT_RESPONSE"
	DNSTapClientQuery    = "CLIENT_QUERY"

	DNSTapIdentityTest = "test_id"

	MatchingModeInclude     = "include"
	MatchingModeGreaterThan = "greater-than"
)
