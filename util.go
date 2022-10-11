package main

import (
	"errors"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/golang/glog"

	"github.com/jpillora/ipfilter"
)

// http://cavaliercoder.com/blog/optimized-abs-for-int64-in-go.html
func abs(n int16) int16 {
	y := n >> 15
	return (n ^ y) - y
}

func remove(s []*NATRule, index int) []*NATRule {
	return append(s[:index], s[index+1:]...)
}

func parseIP(ip string) *net.IPAddr {
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

func getPublicIPAddress(version uint8) (*net.IPAddr, error) {
	list, err := net.InterfaceAddrs()
	if err != nil {
		glog.Errorf("%v\n", err)
		return nil, errors.New("could not read interface IP addresses")
	}

	f := ipfilter.New(ipfilter.Options{
		BlockedIPs:     getFilteredNetworks(*excludeNetworks, *includeNetworks),
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
		var _temp string
		if strings.Contains(addr.String(), "/") {
			_temp = strings.Split(addr.String(), "/")[0]
		} else {
			_temp = addr.String()
		}
		if version == 4 && strings.Contains(_temp, ".") {
			return parseIP(_temp), nil
		}
		if version == 6 && strings.Contains(_temp, ":") {
			return parseIP(_temp), nil
		}
	}

	return nil, nil
}

func getFilteredNetworks(exclude, include string) []string {
	excludeFromFiltered := strings.Split(exclude, ",")
	includeInFiltered := strings.Split(include, ",")
	internalNetworks := []string{
		// loopback
		"127.0.0.0/8",
		// RFC 1918
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		// RFC 3927
		"169.254.0.0/16",
		// RFC 6598
		"100.64.0.0/10",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	var result []string
	for _, n := range internalNetworks {
		for _, m := range excludeFromFiltered {
			if n != m {
				result = append(result, n)
			}
		}
	}
	for _, o := range includeInFiltered {
		result = append(result, o)
	}
	return result
}

func sliceAtoi(sa []string) ([]uint16, error) {
	si := make([]uint16, 0, len(sa))
	for _, a := range sa {
		i, err := strconv.Atoi(a)
		if err != nil {
			return si, err
		}
		si = append(si, uint16(i))
	}
	return si, nil
}
