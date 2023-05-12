//go:build linux || darwin
// +build linux darwin

package netlib

import (
	"crypto/tls"
	"io"
	"net"
	"os"
	"syscall"
)

// thanks to https://stackoverflow.com/questions/28967701/golang-tcp-socket-cant-close-after-get-file,
// call conn.CloseRead() before calling conn.Close()
func Close(conn io.Closer, reset bool) error {
	type ReadCloser interface {
		CloseRead() error
	}

	// send reset
	if reset {
		tcpConn := conn.(*net.TCPConn)
		tcpConn.SetLinger(0)
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

// Configure SO_RCVBUF, thanks to https://github.com/dmachard/go-dns-collector/issues/61#issuecomment-1201199895
func SetSock_RCVBUF(conn net.Conn, desired int, is_tls bool) (int, int, error) {
	var file *os.File
	var err error
	if is_tls {
		tlsConn := conn.(*tls.Conn).NetConn()
		file, err = tlsConn.(*net.TCPConn).File()
		if err != nil {
			return 0, 0, err
		}
	} else {
		file, err = conn.(*net.TCPConn).File()
		if err != nil {
			return 0, 0, err
		}
	}

	// get the before value
	before, err := syscall.GetsockoptInt(int(file.Fd()), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err != nil {
		return 0, 0, err
	}

	// set the new one and check the new actual value
	syscall.SetsockoptInt(int(file.Fd()), syscall.SOL_SOCKET, syscall.SO_RCVBUF, desired)
	actual, err := syscall.GetsockoptInt(int(file.Fd()), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err != nil {
		return 0, 0, err
	}
	return before, actual, nil
}
