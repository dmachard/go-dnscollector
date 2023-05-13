//go:build linux || darwin
// +build linux darwin

package netlib

import (
	"crypto/tls"
	"net"
	"os"
	"syscall"
)

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
