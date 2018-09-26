// Copyright (C) 2015 Eiichiro Watanabe
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/armon/go-radix"
	"github.com/martinolsen/go-rpsl"
	"github.com/osrg/gobgp/pkg/packet/bgp"
)

type subResource struct {
	maxLen uint8
	asns   []uint32
}

type prefixResource struct {
	prefix    net.IP
	prefixLen uint8
	values    []*subResource
}

type resource struct {
	files     []string
	currentSN uint32
	table     map[uint32]map[bgp.RouteFamily]*radix.Tree
	useMaxLen bool
}

func newResource(files []string, useMaxLen bool) (*resource, error) {
	rsrc := &resource{
		files:     files,
		table:     make(map[uint32]map[bgp.RouteFamily]*radix.Tree),
		useMaxLen: useMaxLen,
	}

	rsrc.currentSN = uint32(time.Now().Unix())
	rsrc, err := rsrc.loadAs(rsrc.currentSN)
	if err != nil {
		return nil, err
	}
	return rsrc, nil
}

func (rsrc *resource) loadAs(sn uint32) (*resource, error) {
	var err error
	for _, f := range rsrc.files {
		rsrc, err = rsrc.loadFromIRRdb(sn, f)
		if err != nil {
			return nil, err
		}
	}

	return rsrc, nil
}

func (rsrc *resource) loadFromIRRdb(sn uint32, irrDBFileName string) (*resource, error) {
	byObjects := regexp.MustCompile("\n\n")

	if _, ok := rsrc.table[sn]; !ok {
		rsrc.table[sn] = make(map[bgp.RouteFamily]*radix.Tree)
		for _, rf := range []bgp.RouteFamily{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC} {
			rsrc.table[sn][rf] = radix.New()
		}
	}

	irrDb, err := ioutil.ReadFile(irrDBFileName)
	if err != nil {
		return nil, err
	}

	irrObjects := byObjects.Split(string(irrDb), -1)

	for i := 0; i < len(irrObjects); i++ {
		object, err := rpsl.NewReader(strings.NewReader(irrObjects[i])).Read()
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return nil, err
			}
		}
		switch object.Class {
		case "route":
			rsrc, err = rsrc.addValidInfo(
				sn,
				object.Get("origin"),
				object.Get("route"),
			)
		case "route6":
			rsrc, err = rsrc.addValidInfo(
				sn,
				object.Get("origin"),
				object.Get("route6"),
			)
		}
		if err != nil {
			return nil, err
		}
	}
	return rsrc, nil
}

func (rsrc *resource) addValidInfo(sn uint32, as string, prefix string) (*resource, error) {
	a, _ := strconv.ParseUint(strings.TrimLeft(as, "AS"), 10, 32)
	rf, n, maxLen, err := parseCIDR(prefix)
	if err != nil {
		return nil, err
	}
	addr := n.IP
	m, _ := n.Mask.Size()
	prefixLen := uint8(m)
	if !rsrc.useMaxLen {
		maxLen = prefixLen
	}

	key := func() string {
		var buf1 []byte
		switch rf {
		case bgp.RF_IPv4_UC:
			buf1 = addr.To4()
		case bgp.RF_IPv6_UC:
			buf1 = addr.To16()
		}
		return func(buf2 []byte) string {
			var buf3 bytes.Buffer
			for i := 0; i < len(buf2) && i < int(prefixLen); i++ {
				buf3.WriteString(fmt.Sprintf("%08b", buf2[i]))
			}
			return buf3.String()[:prefixLen]
		}(buf1)
	}()

	b, _ := rsrc.table[sn][rf].Get(key)
	if b == nil {
		p := make([]byte, len(addr))
		copy(p, addr)

		r := &subResource{
			asns:   []uint32{uint32(a)},
			maxLen: maxLen,
		}

		b := &prefixResource{
			prefixLen: prefixLen,
			prefix:    p,
			values:    []*subResource{r},
		}

		rsrc.table[sn][rf].Insert(key, b)
	} else {
		bucket := b.(*prefixResource)
		for _, r := range bucket.values {
			if r.maxLen == maxLen {
				for _, asn := range r.asns {
					if asn == uint32(a) {
						return rsrc, nil
					}
				}
				r.asns = append(r.asns, uint32(a))
				return rsrc, nil
			}
		}
		r := &subResource{
			maxLen: maxLen,
			asns:   []uint32{uint32(a)},
		}
		bucket.values = append(bucket.values, r)
	}
	return rsrc, nil
}

// Wrapper for net.ParseCIDR
// net.ParseCIDR parses IPv4 mapped IP v6 address (eg. ::FFFF:0.0.0.0/96) as IPv4!
// In this program(routing world), it should be parsed as IPv6.
func parseCIDR(s string) (bgp.RouteFamily, *net.IPNet, uint8, error) {
	rf := bgp.RF_IPv6_UC
	maxLen := uint8(net.IPv6len * 8)
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		return rf, nil, maxLen, err
	}
	if !strings.Contains(s, ":") {
		if ip.To4() != nil {
			rf = bgp.RF_IPv4_UC
			maxLen = uint8(net.IPv4len * 8)
		}
	}
	return rf, n, maxLen, nil
}
