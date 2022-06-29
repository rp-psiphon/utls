package main

//quick TLS Handshake example for ClientHello fingerprints of different browser versions to CDNs specified in CDNs.config

import (
	"fmt"
	"io/ioutil"

	"net"
	"os"
	"strings"
	"time"

	tls "github.com/rp-psiphon/utls"
)

var (
	dialTimeout = time.Duration(15) * time.Second
)

type Host struct {
	Name string
	IP   string
}

func main() {

	helloList := []tls.ClientHelloID{
		//from sleeyax/utls
		tls.HelloChrome_87,
		tls.HelloChrome_96,
		tls.HelloIOS_13,
		tls.HelloIOS_14,
		tls.HelloAndroid_11_OkHttp,
		//from rp-psiphon/utls
		tls.HelloChrome_102,
		tls.HelloFirefox_102,
		//from Noooste/utls, identical to Firefox102
		tls.HelloFirefox_99}

	helloList = []tls.ClientHelloID{
		tls.HelloFirefox_99}

	var nameList []string
	var hostList []Host

	logFile, _ := os.Create("handshake_example.log")
	defer logFile.Close()

	configFile, err := ioutil.ReadFile("CDNs.config")
	if err == nil {
		nameList = strings.Split(string(configFile), "\n")
	}

	for _, hostAddress := range nameList {

		ip, err := DNSLookup(hostAddress)
		if err == nil {
			host := Host{hostAddress, (ip + ":443")}
			hostList = append(hostList, host)
		}
	}
	for _, helloType := range helloList {

		for _, host := range hostList {
			var err error = TlsHandshake(host, helloType)
			fmt.Printf("%v %v Hello -> %v (%v)   : ", helloType.Client, helloType.Version, host.Name, host.IP)
			logFile.WriteString(fmt.Sprintf("%v %v Hello -> %v (%v)   : ", helloType.Client, helloType.Version, host.Name, host.IP))

			if err != nil {
				fmt.Printf("\n#> TlsHandshake() failed: %+v\n", err)
				logFile.WriteString(fmt.Sprintf("\n#> TlsHandshake() failed: %+v\n", err))

			} else {
				fmt.Println("success!")
				logFile.WriteString("success!\n")
			}
			//time.Sleep(1 * time.Second)
		}
	}

}

func TlsHandshake(host Host, helloType tls.ClientHelloID) error {
	config := tls.Config{ServerName: host.Name, InsecureSkipVerify: true}
	dialConn, err := net.DialTimeout("tcp", host.IP, dialTimeout)
	if err != nil {
		return fmt.Errorf("net.DialTimeout error: %+v", err)
	}
	uTlsConn := tls.UClient(dialConn, &config, helloType)
	defer uTlsConn.Close()

	err = uTlsConn.Handshake()
	if err != nil {
		return fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	return err
}

func DNSLookup(hostName string) (string, error) {
	ips, err := net.LookupIP(hostName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not get IPs for %s: %v\n", hostName, err)
		return "", err
	}
	for _, ip := range ips {
		//fmt.Printf("%s. IN A %s\n", hostName, ip.String())
		return ip.String(), nil
	}
	return "", err
}
