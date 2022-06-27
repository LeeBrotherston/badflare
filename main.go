package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/ns3777k/go-shodan/v4/shodan" // shodan module
)

// Cloudflare IP address ranges per https://www.cloudflare.com/ips/
var cloudflareBlocks = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

func main() {
	// I swear that this double bool fun will make sense (they could both be true)
	isCloudflare := false
	isNonCloudflare := false
	hostname := flag.String("h", "", "hostname to search")
	shodanAPI := flag.String("s", "", "your shodan API key (or env var SHODAN_API")
	flag.Parse()

	if len(*shodanAPI) == 0 {
		if len(os.Getenv("SHODAN_API")) > 0 {
			*shodanAPI = os.Getenv("SHODAN_API")
		} else {
			fmt.Printf("Shodan API required")
			os.Exit(0)
		}
	}

	// First let's look up the public DNS records for this host
	iplookup, err := net.LookupIP(*hostname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not get IPs: %v\n", err)
		os.Exit(1)
	}

	// For each response, check if it is in the cloudflare address block
	for _, ip := range iplookup {
		if isCF(ip.String()) {
			fmt.Printf("'%s' has IP '%s' which is part of a Cloudflare block\n", *hostname, ip.String())
			isCloudflare = true
		} else {
			isNonCloudflare = true
		}
	}

	// A mix of cloudflare and non-cloudflare IPs returned from DNS
	if isCloudflare && isNonCloudflare {
		fmt.Printf("Mixed CF and non-CF response.  Real host may be in DNS?\n")
	}

	// Do this after the above for loop, otherwise this will run multiple times if
	// multiple DNS records exist for the hostname, and we want to be nice to shodan
	// :)
	if isCloudflare {
		shodanQuery := fmt.Sprintf("hostname:%s", *hostname)
		client := shodan.NewEnvClient(nil)
		client.Token = *shodanAPI
		shodanOptions := shodan.HostQueryOptions{
			Query:  shodanQuery,
			Facets: "ip",
			Minify: false,
			Page:   0,
		}
		shodanResponse, err := client.GetHostsForQuery(context.Background(), &shodanOptions)
		if err != nil {
			fmt.Printf("Shodan Issue: %v\n", err)
		}

		// Let's look at the responses and see if any of them are *not* Cloudflare (i.e.
		// a potential real host)
		for _, facets := range shodanResponse.Facets {
			for _, shodanip := range facets {
				if !isCF(shodanip.Value) {
					fmt.Printf("Found \"real\" (non-Cloudflare) host: %s\n", shodanip.Value)
				}
			}
		}

	} else {
		// Well that's that really.... no need to worry too much :D
		fmt.Printf("Does not appear to be an host using Cloudflare\n")
	}

}

// Checks if the provided string representation of an IP address is in the
// cloudflare address block. Returns true if it is, false if it is not, or the
// IP cannot be parsed.
func isCF(ip string) bool {
	ipParsed := net.ParseIP(ip)
	if ipParsed == nil {
		return false
	}
	for _, subnet := range cloudflareBlocks {
		_, thisSubnet, _ := net.ParseCIDR(subnet)
		if thisSubnet.Contains(ipParsed) {
			fmt.Printf("Seems to be Cloudflare")
			return true
		}
	}
	return false
}
