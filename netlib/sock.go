//go:build linux || darwin || freebsd
// +build linux darwin freebsd

package netlib

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
)

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

// Configure SO_RCVBUF, thanks to https://github.com/dmachard/go-dns-collector/issues/61#issuecomment-1201199895
func SetSockRCVBUF(conn net.Conn, desired int, isTLS bool) (int, int, error) {
	var file *os.File
	var err error
	if isTLS {
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
