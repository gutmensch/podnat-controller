package main

import (
	"errors"
	"net"
	"os"
	"strings"

	"github.com/golang/glog"

	"github.com/jpillora/ipfilter"
)

// http://cavaliercoder.com/blog/optimized-abs-for-int64-in-go.html
func abs(n int16) int16 {
	y := n >> 15
	return (n ^ y) - y
}

func parseIP(ip string) net.Addr {
	_ip, err := net.ResolveIPAddr("ip", ip)
	if err != nil {
		return nil
	}
	return _ip
}

func ptr[T any](t T) *T {
	return &t
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func shortHostName(hostname string) string {
	if strings.Contains(hostname, ".") {
		return strings.Split(hostname, ".")[0]
	}
	return hostname
}

func filterIPs(collection []net.Addr, fn func(elem net.Addr) bool) []net.Addr {
	var result []net.Addr
	for _, item := range collection {
		if fn(item) {
			result = append(result, item)
		}
	}
	return result
}

func getPublicIPAddress(version uint8) (net.Addr, error) {
	list, err := net.InterfaceAddrs()
	if err != nil {
		glog.Errorf("%v\n", err)
		return nil, errors.New("could not read interface IP addresses")
	}

	f := ipfilter.New(ipfilter.Options{
		BlockedIPs: []string{
			// loopback
			"127.0.0.0/8",
			// RFC 1918
			"10.0.0.0/8",
			"172.16.0.0/12",
			//"192.168.0.0/16",
			// RFC 3927
			"169.254.0.0/16",
			// RFC 6598
			"100.64.0.0/10",
			"::1/128",
			"fc00::/7",
			"fe80::/10",
		},
		BlockByDefault: false,
	})

	filteredList := filterIPs(list, func(a net.Addr) bool {
		b := a.String()
		if strings.Contains(b, "/") {
			b = strings.Split(b, "/")[0]
		}
		return !f.Blocked(b)
	})

	// TODO: stupidly getting first address of version
	for _, addr := range filteredList {
		if version == 4 && strings.Contains(addr.String(), ".") {
			return addr, nil
		}
		if version == 6 && strings.Contains(addr.String(), ":") {
			return addr, nil
		}
	}

	return nil, nil
}
