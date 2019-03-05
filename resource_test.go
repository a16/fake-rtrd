package main

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/osrg/gobgp/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
)

func createFile(name string, content []string) string {
	tmpfile, _ := ioutil.TempFile(os.TempDir(), name)
	for _, str := range content {
		tmpfile.WriteString(str)
	}
	tmpfile.Close()
	return tmpfile.Name()
}

func removeFile(fileName string) {
	os.Remove(fileName)
}

func TestResource(t *testing.T) {
	examples := map[string]struct {
		Content           []string
		UseMaxLen         bool
		ExpectedRoute     string
		ExpectedIp        string
		ExpectedPrefixLen int
		ExpectedMaxLen    int
		ExpectedOriginAs  int
	}{
		"IPv4_WithUseMaxLen_WithoutRemarks": {
			[]string{
				"route: 192.168.1.0/24\n",
				"origin: AS65001\n",
				"source: TEST\n",
				"\n",
			},
			true,
			"192.168.1.0/24",
			"192.168.1.0",
			24,
			32,
			65001,
		},
		"IPv4_WithUseMaxLen_WithRemarks": {
			[]string{
				"route: 192.168.2.0/24\n",
				"origin: AS65002\n",
				"remarks: maxLength 26\n",
				"source: TEST\n",
				"\n",
			},
			true,
			"192.168.2.0/24",
			"192.168.2.0",
			24,
			26,
			65002,
		},
		"IPv6_WithUseMaxLen_WithoutRemarks": {
			[]string{
				"route6: 2001:db8:1::/48\n",
				"origin: AS65001\n",
				"source: TEST\n",
				"\n",
			},
			true,
			"2001:db8:1::/48",
			"2001:db8:1::",
			48,
			128,
			65001,
		},
		"IPv6_WithUseMaxLen_WithRemarks": {
			[]string{
				"route6: 2001:db8:2::/48\n",
				"origin: AS65002\n",
				"remarks: maxLength 64\n",
				"source: TEST\n",
				"\n",
			},
			true,
			"2001:db8:2::/48",
			"2001:db8:2::",
			48,
			64,
			65002,
		},
		"IPv4_WithoutUseMaxLen_WithoutRemarks": {
			[]string{
				"route: 192.168.1.0/24\n",
				"origin: AS65001\n",
				"source: TEST\n",
				"\n",
			},
			false,
			"192.168.1.0/24",
			"192.168.1.0",
			24,
			24,
			65001,
		},
		"IPv4_WithoutUseMaxLen_WithRemarks": {
			[]string{
				"route: 192.168.2.0/24\n",
				"origin: AS65002\n",
				"remarks: maxLength 26\n",
				"source: TEST\n",
				"\n",
			},
			false,
			"192.168.2.0/24",
			"192.168.2.0",
			24,
			26,
			65002,
		},
		"IPv6_WithoutUseMaxLen_WithoutRemarks": {
			[]string{
				"route6: 2001:db8:1::/48\n",
				"origin: AS65001\n",
				"source: TEST\n",
				"\n",
			},
			false,
			"2001:db8:1::/48",
			"2001:db8:1::",
			48,
			48,
			65001,
		},
		"IPv6_WithoutUseMaxLen_WithRemarks": {
			[]string{
				"route6: 2001:db8:2::/48\n",
				"origin: AS65002\n",
				"remarks: maxLength 64\n",
				"source: TEST\n",
				"\n",
			},
			false,
			"2001:db8:2::/48",
			"2001:db8:2::",
			48,
			64,
			65002,
		},
	}

	for name, v := range examples {
		tmpFile := createFile(name, v.Content)
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			r, _ := newResource([]string{tmpFile}, v.UseMaxLen)

			rf, addr, maskLen, _, _ := parsePrefix(v.ExpectedRoute)
			b, _ := r.table[r.currentSN][rf].Get(generateKey(rf, addr, maskLen))
			bucket := b.(*prefixResource)

			assert.Equal(v.ExpectedIp, bucket.prefix.String())
			assert.Equal(v.ExpectedPrefixLen, int(bucket.prefixLen))
			assert.Equal(v.ExpectedMaxLen, int(bucket.values[0].maxLen))
			assert.Equal(v.ExpectedOriginAs, int(bucket.values[0].asns[0]))
		})
		os.Remove(tmpFile)
	}
}

func TestParseCIDR(t *testing.T) {
	examples := map[string]struct {
		RouteFamily bgp.RouteFamily
		Address     string
		Mask     uint8
		MaskLenMax  uint8
	}{
		"192.168.0.0/24": {
			bgp.RF_IPv4_UC,
			"192.168.0.0",
      24,
			32,
		},
		"2001:db8::/32": {
			bgp.RF_IPv6_UC,
			"2001:db8::",
      32,
			128,
		},
	}

	for prefix, expected := range examples {
		t.Run(prefix, func(t *testing.T) {
			assert := assert.New(t)
			rf, ip, maskLen, maskLenMax, _ := parsePrefix(prefix)
			assert.Equal(expected.RouteFamily, rf)
			assert.Equal(expected.Address, ip.String())
			assert.Equal(expected.Mask, maskLen)
			assert.Equal(expected.MaskLenMax, maskLenMax)
		})
	}
}
