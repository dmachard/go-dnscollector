package netlib

import (
	"io"
	"net"
)

// thanks to https://stackoverflow.com/questions/28967701/golang-tcp-socket-cant-close-after-get-file,
// call conn.CloseRead() before calling conn.Close()
func Close(conn io.Closer, reset bool) error {
	type ReadCloser interface {
		CloseRead() error
	}

	// Agressive closing, send TCP RESET instead of FIN
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
