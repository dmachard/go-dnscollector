package netutils

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test ConvertIP4 function
func TestConvertIP4(t *testing.T) {
	ip := uint32(3232235521) // Corresponds to 192.168.0.1
	expectedIP := net.IPv4(192, 168, 0, 1)
	actualIP := ConvertIP4(ip)
	assert.Equal(t, expectedIP.String(), actualIP.String(), "IP does not match")
}
