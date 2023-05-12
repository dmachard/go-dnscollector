//go:build windows
// +build windows

package netlib

import (
	"crypto/tls"
	"net"
	"os"

	"golang.org/x/sys/windows"
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
	before, err := windows.GetsockoptInt(windows.Handle(file.Fd()), windows.SOL_SOCKET, windows.SO_RCVBUF)
	if err != nil {
		return 0, 0, err
	}

	// set the new one and check the new actual value
	windows.SetsockoptInt(windows.Handle(file.Fd()), windows.SOL_SOCKET, windows.SO_RCVBUF, desired)
	actual, err := windows.GetsockoptInt(windows.Handle(file.Fd()), windows.SOL_SOCKET, windows.SO_RCVBUF)
	if err != nil {
		return 0, 0, err
	}
	return before, actual, nil
}
