package main

//quick TLS Handshake example

import (
	"fmt"
	"net"
	"time"

	tls "github.com/rp-psiphon/utls"
)

var (
	dialTimeout = time.Duration(15) * time.Second
)

//var requestHostname = "google.com" // speaks http2 and TLS 1.3
//var requestAddr = "google.com:443"

var requestHostname = "cloudflare.com" // speaks http2 and TLS 1.3
// 	var requestAddr = "104.16.133.229:443"
var requestAddr = "cloudflare.com:443"

func main() {
	//hellos to test:
	/*
		HelloChrome_87
		HelloChrome_96
		HelloIOS_13
		HelloIOS_14
		HelloAndroid_11_OkHttp

	*/
	helloList := []tls.ClientHelloID{tls.HelloChrome_87, tls.HelloChrome_96, tls.HelloIOS_13, tls.HelloIOS_13, tls.HelloIOS_14, tls.HelloAndroid_11_OkHttp}

	for _, helloType := range helloList {

		var err error = TlsHandshake(requestHostname, requestAddr, helloType)
		if err != nil {
			fmt.Printf("#> TlsHandshake() failed: %+v\n", err)
		} else {
			fmt.Println("success!")
		}

	}

}

func TlsHandshake(hostname string, addr string, helloType tls.ClientHelloID) error {
	config := tls.Config{ServerName: hostname}
	dialConn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return fmt.Errorf("net.DialTimeout error: %+v", err)
	}
	uTlsConn := tls.UClient(dialConn, &config, tls.HelloCustom)
	defer uTlsConn.Close()

	spec := GenerateSpec(helloType)
	err = uTlsConn.ApplyPreset(&spec)

	if err != nil {
		return fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	err = uTlsConn.Handshake()
	if err != nil {
		return fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	return err
}

func GenerateSpec(id tls.ClientHelloID) tls.ClientHelloSpec {

	spec := tls.utlsIDToSpec(tls.clientHelloID)

	return spec

}
