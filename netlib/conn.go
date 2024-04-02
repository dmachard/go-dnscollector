package netlib

import (
	"errors"
	"io"
	"net"
)

func IsClosedConnectionError(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Err.Error() == "use of closed network connection" {
			return true
		}
	}
	return false
}

// thanks to https://stackoverflow.com/questions/28967701/golang-tcp-socket-cant-close-after-get-file,
// call conn.CloseRead() before calling conn.Close()
func Close(conn io.Closer, reset bool) error {
	type ReadCloser interface {
		CloseRead() error
	}

	// Aggressive closing, send TCP RESET instead of FIN
	if reset {
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetLinger(0)
		}
	}

	var errs []error
	if closer, ok := conn.(ReadCloser); ok {
		errs = append(errs, closer.CloseRead())
	}
	errs = append(errs, conn.Close())
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// GetPeerName returns the hostname associated with the given peer address.
// If the peer address cannot be split into IP and port or if the hostname lookup fails,
// it returns the peer address or IP itself.
func GetPeerName(peerAddr string) string {
	// Split the peer address into IP and port
	peerIP, _, err := net.SplitHostPort(peerAddr)
	if err != nil {
		// If splitting fails, return the original peer address
		return peerAddr
	}

	// Lookup hostname associated with the IP address
	names, err := net.LookupAddr(peerIP)
	if err != nil {
		// If hostname lookup fails, return the IP address
		return peerIP
	}

	// If hostname is found, return the first name in the list
	if len(names) > 0 {
		return names[0]
	}

	// If no hostname is found, return the IP address
	return peerIP
}
