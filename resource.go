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
	maxLength := regexp.MustCompile(`\s*[Mm]axLength\s*(\d+)`)

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
		case "route", "route6":
			findMaxLen := func() int {
				vs, ok := object.Values[strings.ToLower("remarks")]
				if ok {
					for _, v := range vs {
						result := maxLength.FindStringSubmatch(v)
						if len(result) == 0 {
							continue
						}
						num, _ := strconv.Atoi(result[1])
						return num
					}
				}
				return -1
			}
			rsrc, err = rsrc.addValidInfo(
				sn,
				object.Get("origin"),
				object.Get(object.Class),
				findMaxLen(),
			)
		}
		if err != nil {
			return nil, err
		}
	}
	return rsrc, nil
}

func generateKey(rf bgp.RouteFamily, addr net.IP, prefixLen uint8) string {
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
}

func (rsrc *resource) addValidInfo(sn uint32, as string, prefix string, mLenFromObj int) (*resource, error) {
	a, _ := strconv.ParseUint(strings.TrimLeft(as, "AS"), 10, 32)
	rf, ip, maskLen, maxLen, err := parsePrefix(prefix)
	if err != nil {
		return nil, err
	}
	if !rsrc.useMaxLen {
		maxLen = maskLen
	}
	if mLenFromObj >= 0 {
		switch rf {
		case bgp.RF_IPv4_UC:
			if mLenFromObj <= 32 {
				maxLen = uint8(mLenFromObj)
			}
		case bgp.RF_IPv6_UC:
			if mLenFromObj <= 128 {
				maxLen = uint8(mLenFromObj)
			}
		}
	}

	key := generateKey(rf, ip, maskLen)
	b, _ := rsrc.table[sn][rf].Get(key)
	if b == nil {
		p := make([]byte, len(ip))
		copy(p, ip)

		r := &subResource{
			asns:   []uint32{uint32(a)},
			maxLen: maxLen,
		}

		b := &prefixResource{
			prefixLen: maskLen,
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

func parsePrefix(prefix string) (bgp.RouteFamily, net.IP, uint8, uint8, error) {
	rf := bgp.RF_IPv6_UC
	maskLenMax := uint8(net.IPv6len * 8)
	ip, n, err := net.ParseCIDR(prefix)
	if err != nil {
		return 0, nil, 0, 0, err
	}
	if ip.To4() != nil {
		rf = bgp.RF_IPv4_UC
		maskLenMax = uint8(net.IPv4len * 8)
	}
  maskLen, _ := n.Mask.Size()
	return rf, n.IP, uint8(maskLen), maskLenMax, nil
}
