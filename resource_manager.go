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
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/armon/go-radix"
	set "github.com/deckarep/golang-set"
	"github.com/grafov/bcast"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/packet/rtr"
)

const (
	UNKNOWN = iota
	REQ_LOAD
	REQ_RELOAD
	REQ_CURRENT_SERIAL
	REQ_CURRENT_LIST
	REQ_DELTA_LIST
	REQ_IF_SERIAL_EXISTS
	REQ_BEGIN_TRANSACTION
	REQ_END_TRANSACTION
)

type RequestType int

type Request struct {
	RequestType RequestType
	Key         interface{}
	Value       string
	Response    chan *Response
	transaction chan Request
}

type FakeROA struct {
	Prefix    net.IP
	PrefixLen uint8
	MaxLen    uint8
	AS        uint32
}

type FakeROATable map[bgp.RouteFamily]map[uint8][]*FakeROA

type Response struct {
	Error error
	Data  interface{}
}

type ResourceManager struct {
	ch           chan Request
	serialNotify *bcast.Group
	init         sync.Once
}

func NewResourceManager() *ResourceManager {
	return &ResourceManager{
		ch:           make(chan Request),
		serialNotify: bcast.NewGroup(),
	}
}

func (mgr *ResourceManager) Load(args []string) error {
	mgr.init.Do(func() {
		go mgr.serialNotify.Broadcast(0)
		mgr.ch = make(chan Request)
		go mgr.run()
	})
	result := make(chan *Response)
	extracted_files := []string{}
	for _, arg := range args {
		files, _ := filepath.Glob(arg)
		for _, f := range files {
			extracted_files = append(extracted_files, f)
		}
	}
	mgr.ch <- Request{RequestType: REQ_LOAD, Key: extracted_files, Response: result}
	res := <-result
	return res.Error
}

func (mgr *ResourceManager) Reload() error {
	result := make(chan *Response)
	mgr.ch <- Request{RequestType: REQ_RELOAD, Response: result}
	res := <-result
	return res.Error
}

func (mgr *ResourceManager) CurrentSerial() uint32 {
	result := make(chan *Response)
	mgr.ch <- Request{RequestType: REQ_CURRENT_SERIAL, Response: result}
	res := <-result
	return res.Data.(uint32)
}

func (mgr *ResourceManager) CurrentList() FakeROATable {
	result := make(chan *Response)
	mgr.ch <- Request{RequestType: REQ_CURRENT_LIST, Response: result}
	res := <-result
	return res.Data.(FakeROATable)
}

func (mgr *ResourceManager) DeltaList(sn uint32) FakeROATable {
	result := make(chan *Response)
	mgr.ch <- Request{RequestType: REQ_DELTA_LIST, Key: sn, Response: result}
	res := <-result
	return res.Data.(FakeROATable)
}

func (mgr *ResourceManager) HasKey(sn uint32) bool {
	result := make(chan *Response)
	mgr.ch <- Request{RequestType: REQ_IF_SERIAL_EXISTS, Key: sn, Response: result}
	res := <-result
	return res.Data.(bool)
}

func (mgr *ResourceManager) BeginTransaction() *ResourceManager {
	result := make(chan *Response)
	trans := make(chan Request)
	mgr.ch <- Request{RequestType: REQ_BEGIN_TRANSACTION, Response: result, transaction: trans}
	return &ResourceManager{
		ch:           trans,
		serialNotify: mgr.serialNotify,
		init:         mgr.init,
	}
}

func (mgr *ResourceManager) EndTransaction() {
	mgr.ch <- Request{RequestType: REQ_END_TRANSACTION}
}

func handleRequests(mgr *ResourceManager, rsrc *resource) {
	var err error
	for {
		req := <-mgr.ch
		switch req.RequestType {
		case REQ_LOAD:
			rsrc, err = newResource(req.Key.([]string))
			log.Infof("Resource has been loaded. (SN: %v)", rsrc.currentSN)
			req.Response <- &Response{Error: err}
		case REQ_CURRENT_SERIAL:
			req.Response <- &Response{Data: rsrc.currentSN}
		case REQ_RELOAD:
			serialNotify := false
			nextSN := uint32(time.Now().Unix())
			rsrc, err = rsrc.loadAs(nextSN)
			if err != nil {
				req.Response <- &Response{Error: err}
				break
			}

			if eql := reflect.DeepEqual(rsrc.table[rsrc.currentSN], rsrc.table[nextSN]); !eql {
				log.Infof("Resource has been updated. (SN: %v -> %v)", rsrc.currentSN, nextSN)
				rsrc.currentSN = nextSN
				serialNotify = true
			} else {
				delete(rsrc.table, nextSN)
			}

			for k, _ := range rsrc.table {
				if rsrc.currentSN != k {
					t := time.Now()
					if int64(k) < t.Add(-24*time.Hour).Unix() {
						delete(rsrc.table, k)
						log.Infof("Resource as of %v was expired. (SN: %v)", time.Unix(int64(k), 0).Format("2006/01/02 15:04:05"), k)
					}
				}
			}
			if serialNotify {
				mgr.serialNotify.Send(true)
			}

			req.Response <- &Response{Error: nil}
		case REQ_CURRENT_LIST:
			lists := FakeROATable{
				bgp.RF_IPv4_UC: map[uint8][]*FakeROA{},
				bgp.RF_IPv6_UC: map[uint8][]*FakeROA{},
			}

			lists[bgp.RF_IPv4_UC][rtr.ANNOUNCEMENT] = fakeROALists(rsrc, treeToSet(rsrc.table[rsrc.currentSN][bgp.RF_IPv4_UC]))
			lists[bgp.RF_IPv6_UC][rtr.ANNOUNCEMENT] = fakeROALists(rsrc, treeToSet(rsrc.table[rsrc.currentSN][bgp.RF_IPv6_UC]))

			req.Response <- &Response{Data: lists}
		case REQ_DELTA_LIST:
			k := req.Key.(uint32)
			lists := FakeROATable{
				bgp.RF_IPv4_UC: map[uint8][]*FakeROA{},
				bgp.RF_IPv6_UC: map[uint8][]*FakeROA{},
			}

			lists[bgp.RF_IPv4_UC][rtr.ANNOUNCEMENT] = fakeROALists(rsrc, treeToSet(rsrc.table[rsrc.currentSN][bgp.RF_IPv4_UC]).Difference(treeToSet(rsrc.table[k][bgp.RF_IPv4_UC])))
			lists[bgp.RF_IPv6_UC][rtr.ANNOUNCEMENT] = fakeROALists(rsrc, treeToSet(rsrc.table[rsrc.currentSN][bgp.RF_IPv6_UC]).Difference(treeToSet(rsrc.table[k][bgp.RF_IPv6_UC])))
			lists[bgp.RF_IPv4_UC][rtr.WITHDRAWAL] = fakeROALists(rsrc, treeToSet(rsrc.table[k][bgp.RF_IPv4_UC]).Difference(treeToSet(rsrc.table[rsrc.currentSN][bgp.RF_IPv4_UC])))
			lists[bgp.RF_IPv6_UC][rtr.WITHDRAWAL] = fakeROALists(rsrc, treeToSet(rsrc.table[k][bgp.RF_IPv6_UC]).Difference(treeToSet(rsrc.table[rsrc.currentSN][bgp.RF_IPv6_UC])))

			req.Response <- &Response{Data: lists}
		case REQ_IF_SERIAL_EXISTS:
			_, ok := rsrc.table[req.Key.(uint32)]
			req.Response <- &Response{Data: ok}
		case REQ_BEGIN_TRANSACTION:
			transaction := &ResourceManager{ch: req.transaction}
			handleRequests(transaction, rsrc)
		case REQ_END_TRANSACTION:
			return
		}
	}
}

func fakeROALists(rsrc *resource, list set.Set) []*FakeROA {
	fakeROAs := make([]*FakeROA, 0)
	for _, item := range list.ToSlice() {
		addr, plen, mlen, asn := stringToValues(item.(string))
		fakeROAs = append(fakeROAs, &FakeROA{
			Prefix:    addr,
			PrefixLen: plen,
			MaxLen:    mlen,
			AS:        asn,
		})
	}
	return fakeROAs
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
				result.Add(fmt.Sprintf("%v/%v-%v-%d", x.prefix, x.prefixLen, y.maxLen, z))
			}
		}
	}
	return result
}

func stringToValues(str string) (net.IP, uint8, uint8, uint32) {
	arr := strings.Split(str, "-")
	_, n, _, _ := parseCIDR(arr[0])
	addr := n.IP
	m, _ := n.Mask.Size()
	maxLen, _ := strconv.ParseUint(arr[1], 10, 8)
	asn, _ := strconv.ParseUint(arr[2], 10, 32)
	return addr, uint8(m), uint8(maxLen), uint32(asn)
}

func (mgr *ResourceManager) run() {
	var rsrc *resource
	handleRequests(mgr, rsrc)
}
