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
// See the License for the specific language governing permgrissions and
// limitations under the License.

package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/armon/go-radix"
	set "github.com/deckarep/golang-set"
	"github.com/grafov/bcast"
	"github.com/martinolsen/go-rpsl"
	"github.com/osrg/gobgp/packet"
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

type resourceManager struct {
	files     []string
	currentSN uint32
	table     map[uint32]map[bgp.RouteFamily]*radix.Tree
	sync.RWMutex
	group *bcast.Group
}

func newResourceManager(files []string) (*resourceManager, error) {
	rmgr := &resourceManager{
		files: files,
		table: make(map[uint32]map[bgp.RouteFamily]*radix.Tree),
	}

	rmgr.group = bcast.NewGroup()
	go rmgr.group.Broadcasting(0)
	rmgr.currentSN = uint32(time.Now().Unix())
	rmgr, err := rmgr.loadAs(rmgr.currentSN)
	log.Debugf("The resources have been loaded. (SN: %v)", rmgr.currentSN)
	checkError(err)
	return rmgr, nil
}

func (rmgr *resourceManager) loadAs(sn uint32) (*resourceManager, error) {
	var err error
	rmgr.Lock()
	for _, f := range rmgr.files {
		rmgr, err = rmgr.loadFromIRRdb(sn, f)
		if err != nil {
			return nil, err
		}
	}
	rmgr.Unlock()

	return rmgr, nil
}

func (rmgr *resourceManager) reload() {
	broadcast := rmgr.group.Join()
	defer broadcast.Close()
	nextSN := uint32(time.Now().Unix())
	rmgr, err := rmgr.loadAs(nextSN)
	checkError(err)

	rmgr.Lock()
	if eql := reflect.DeepEqual(rmgr.table[rmgr.currentSN], rmgr.table[nextSN]); !eql {
		log.Debugf("The resources have been updated. (SN: %v -> %v)", rmgr.currentSN, nextSN)
		rmgr.currentSN = nextSN
		rmgr.group.Send(true)
		for k, _ := range rmgr.table {
			t := time.Now()
			if int64(k) < t.Add(-1*time.Hour).Unix() {
				delete(rmgr.table, k)
				log.Debugf("The resources as of %v were expired. (SN: %v)", time.Unix(int64(k), 0).Format("2006/01/02 15:04:05"), k)
			}
		}
	} else {
		delete(rmgr.table, nextSN)
	}
	rmgr.Unlock()
}

func (rmgr *resourceManager) loadFromIRRdb(sn uint32, irrDBFileName string) (*resourceManager, error) {
	byObjects := regexp.MustCompile("\n\n")

	if _, ok := rmgr.table[sn]; !ok {
		rmgr.table[sn] = make(map[bgp.RouteFamily]*radix.Tree)
		for _, rf := range []bgp.RouteFamily{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC} {
			rmgr.table[sn][rf] = radix.New()
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
			rmgr, err = rmgr.addValidInfo(
				sn,
				object.Get("origin"),
				object.Get("route"),
				uint8(net.IPv4len*8),
			)
		case "route6":
			rmgr, err = rmgr.addValidInfo(
				sn,
				object.Get("origin"),
				object.Get("route6"),
				uint8(net.IPv6len*8),
			)
		}
		if err != nil {
			return nil, err
		}
	}
	return rmgr, nil
}

func (rmgr *resourceManager) addValidInfo(sn uint32, as string, prefix string, maxLen uint8) (*resourceManager, error) {
	a, _ := strconv.ParseUint(strings.TrimLeft(as, "AS"), 10, 32)
	rf, n, maxLen, err := parseCIDR(prefix)
	if err != nil {
		return nil, err
	}
	addr := n.IP
	m, _ := n.Mask.Size()
	prefixLen := uint8(m)

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

	b, _ := rmgr.table[sn][rf].Get(key)
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

		rmgr.table[sn][rf].Insert(key, b)
	} else {
		bucket := b.(*prefixResource)
		for _, r := range bucket.values {
			if r.maxLen == maxLen {
				for _, asn := range r.asns {
					if asn == uint32(a) {
						return rmgr, nil
					}
				}
				r.asns = append(r.asns, uint32(a))
				return rmgr, nil
			}
		}
		r := &subResource{
			maxLen: maxLen,
			asns:   []uint32{uint32(a)},
		}
		bucket.values = append(bucket.values, r)
	}
	return rmgr, nil
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

func treeToSet(table *radix.Tree) set.Set {
	i := 0
	tableMap := make([]*prefixResource, table.Len())
	table.Walk(func(s string, v interface{}) bool {
		ct, _ := v.(*prefixResource)
		tableMap[i] = ct
		i++
		return false
	})
	result := set.NewSet()
	for _, x := range tableMap {
		for _, y := range x.values {
			for _, z := range y.asns {
				result.Add(fmt.Sprintf(fmt.Sprintf("%v/%v-%v-%d", x.prefix, x.prefixLen, y.maxLen, z)))

			}
		}
	}
	return result
}

func toBeAdded(older *radix.Tree, newer *radix.Tree) []string {
	result := make([]string, 0)
	for _, add := range treeToSet(newer).Difference(treeToSet(older)).ToSlice() {
		result = append(result, add.(string))
	}
	return result
}

func toBeDeleted(older *radix.Tree, newer *radix.Tree) []string {
	result := make([]string, 0)
	for _, del := range treeToSet(older).Difference(treeToSet(newer)).ToSlice() {
		result = append(result, del.(string))
	}
	return result
}
