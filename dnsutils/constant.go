package dnsutils

const (
	ProtoDoT = "DOT"
	ProtoDoH = "DOH"

	DNSRcodeNoError  = "NOERROR"
	DNSRcodeNXDomain = "NXDOMAIN"
	DNSRcodeServFail = "SERVFAIL"
	DNSRcodeTimeout  = "TIMEOUT"

	DNSTapOperationQuery = "QUERY"
	DNSTapOperationReply = "REPLY"

	DNSTapClientResponse = "CLIENT_RESPONSE"
	DNSTapClientQuery    = "CLIENT_QUERY"

	DNSTapIdentityTest = "test_id"

	MatchingModeInclude   = "include"
	MatchingOpGreaterThan = "greater-than"
	MatchingOpLowerThan   = "lower-than"
	MatchingOpSource      = "match-source"
	MatchingOpSourceKind  = "source-kind"
	MatchingKindString    = "string_list"
	MatchingKindRegexp    = "regexp_list"
)
