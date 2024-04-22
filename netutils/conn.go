package netutils

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
)

func AcceptConnections(listener net.Listener, acceptChan chan<- net.Conn) {
	go func() {
		defer close(acceptChan)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			acceptChan <- conn
		}
	}()
}

func IsClosedConnectionError(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Err.Error() == "use of closed network connection" {
			return true
		}
	}
	return false
}

func StartToListen(listenIP string, listenPort int, sockPath string, tlsSupport bool, tlsMin uint16, certFile, keyFile string) (net.Listener, error) {
	var err error
	var listener net.Listener

	// prepare address
	var addr string
	if len(sockPath) > 0 {
		addr = sockPath
		_ = os.Remove(sockPath)
	} else {
		addr = net.JoinHostPort(listenIP, strconv.Itoa(listenPort))
	}

	// listening with tls enabled ?
	if tlsSupport {
		var cer tls.Certificate
		cer, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate: %w", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cer},
			MinVersion:   tls.VersionTLS12,
		}

		// update tls min version according to the user config
		tlsConfig.MinVersion = tlsMin

		// listen
		if len(sockPath) > 0 {
			listener, err = tls.Listen(SocketUnix, addr, tlsConfig)
		} else {
			listener, err = tls.Listen(SocketTCP, addr, tlsConfig)
		}

	} else {
		// basic listening
		if len(sockPath) > 0 {
			listener, err = net.Listen(SocketUnix, addr)
		} else {
			listener, err = net.Listen(SocketTCP, addr)
		}
	}

	// something is wrong ?
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}
	return listener, nil
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
