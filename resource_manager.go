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
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/armon/go-radix"
	set "github.com/deckarep/golang-set"
	"github.com/grafov/bcast"
	"github.com/osrg/gobgp/packet"
)

const (
	UNKNOWN = iota
	REQ_LOAD
	REQ_RELOAD
	REQ_CURRENT_SERIAL
	REQ_CURRENT_LIST
	REQ_LIST_TO_BE_DELETED
	REQ_LIST_TO_BE_ADDED
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

type reqKeys struct {
	RF bgp.RouteFamily
	SN uint32
}

type FakeROA struct {
	Prefix    net.IP
	PrefixLen uint8
	MaxLen    uint8
	AS        uint32
}

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

func (r *ResourceManager) Load(files []string) error {
	r.init.Do(func() {
		go r.serialNotify.Broadcasting(0)
		r.ch = make(chan Request)
		go r.run()
	})
	result := make(chan *Response)
	r.ch <- Request{RequestType: REQ_LOAD, Key: files, Response: result}
	res := <-result
	return res.Error
}

func (r *ResourceManager) Reload() error {
	result := make(chan *Response)
	r.ch <- Request{RequestType: REQ_RELOAD, Response: result}
	res := <-result
	return res.Error
}

func (r *ResourceManager) CurrentSerial() uint32 {
	result := make(chan *Response)
	r.ch <- Request{RequestType: REQ_CURRENT_SERIAL, Response: result}
	res := <-result
	return res.Data.(uint32)
}

func (r *ResourceManager) CurrentList(rf bgp.RouteFamily) []*FakeROA {
	result := make(chan *Response)
	r.ch <- Request{RequestType: REQ_CURRENT_LIST, Key: reqKeys{RF: rf}, Response: result}
	res := <-result
	return res.Data.([]*FakeROA)
}

func (r *ResourceManager) ToBeDeleted(rf bgp.RouteFamily, sn uint32) []*FakeROA {
	result := make(chan *Response)
	r.ch <- Request{RequestType: REQ_LIST_TO_BE_DELETED, Key: reqKeys{RF: rf, SN: sn}, Response: result}
	res := <-result
	return res.Data.([]*FakeROA)
}

func (r *ResourceManager) ToBeAdded(rf bgp.RouteFamily, sn uint32) []*FakeROA {
	result := make(chan *Response)
	r.ch <- Request{RequestType: REQ_LIST_TO_BE_ADDED, Key: reqKeys{RF: rf, SN: sn}, Response: result}
	res := <-result
	return res.Data.([]*FakeROA)
}

func (r *ResourceManager) HasKey(sn uint32) bool {
	result := make(chan *Response)
	r.ch <- Request{RequestType: REQ_IF_SERIAL_EXISTS, Key: sn, Response: result}
	res := <-result
	return res.Data.(bool)
}

func (r *ResourceManager) BeginTransaction() *ResourceManager {
	result := make(chan *Response)
	t := make(chan Request)
	r.ch <- Request{RequestType: REQ_BEGIN_TRANSACTION, Response: result, transaction: t}
	return &ResourceManager{
		ch:           t,
		serialNotify: r.serialNotify,
		init:         r.init,
	}
}

func (r *ResourceManager) EndTransaction() {
	r.ch <- Request{RequestType: REQ_END_TRANSACTION}
}

func handleRequests(r *ResourceManager, rsrc *resource) {
	var err error
	for {
		req := <-r.ch
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
				r.serialNotify.Send(true)
			}
			req.Response <- &Response{Error: nil}
		case REQ_CURRENT_LIST:
			keys := req.Key.(reqKeys)
			req.Response <- &Response{Data: fakeROALists(rsrc, treeToSet(rsrc.table[rsrc.currentSN][keys.RF]))}
		case REQ_LIST_TO_BE_DELETED:
			keys := req.Key.(reqKeys)
			req.Response <- &Response{Data: fakeROALists(rsrc, treeToSet(rsrc.table[keys.SN][keys.RF]).Difference(treeToSet(rsrc.table[rsrc.currentSN][keys.RF])))}
		case REQ_LIST_TO_BE_ADDED:
			keys := req.Key.(reqKeys)
			req.Response <- &Response{Data: fakeROALists(rsrc, treeToSet(rsrc.table[rsrc.currentSN][keys.RF]).Difference(treeToSet(rsrc.table[keys.SN][keys.RF])))}
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

func (r *ResourceManager) run() {
	var rsrc *resource
	handleRequests(r, rsrc)
}
