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
	"net"
	"reflect"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
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

type ResourceMap struct {
	ch   chan Request
	init sync.Once
}

func (rMap *ResourceMap) Load(files []string) (uint32, error) {
	rMap.init.Do(func() {
		rMap.ch = make(chan Request)
		go runMap(rMap.ch)
	})
	result := make(chan *Response)
	rMap.ch <- Request{RequestType: REQ_LOAD, Key: files, Response: result}
	res := <-result
	return res.Data.(uint32), res.Error
}

func (rMap *ResourceMap) Reload() (uint32, error) {
	result := make(chan *Response)
	rMap.ch <- Request{RequestType: REQ_RELOAD, Response: result}
	res := <-result
	return res.Data.(uint32), res.Error
}

func (rMap *ResourceMap) CurrentSerial() uint32 {
	result := make(chan *Response)
	rMap.ch <- Request{RequestType: REQ_CURRENT_SERIAL, Response: result}
	res := <-result
	return res.Data.(uint32)
}

func (rMap *ResourceMap) CurrentList(rf bgp.RouteFamily) []*FakeROA {
	result := make(chan *Response)
	rMap.ch <- Request{RequestType: REQ_CURRENT_LIST, Key: reqKeys{RF: rf}, Response: result}
	res := <-result
	return res.Data.([]*FakeROA)
}

func (rMap *ResourceMap) ToBeDeleted(rf bgp.RouteFamily, sn uint32) []*FakeROA {
	result := make(chan *Response)
	rMap.ch <- Request{RequestType: REQ_LIST_TO_BE_DELETED, Key: reqKeys{RF: rf, SN: sn}, Response: result}
	res := <-result
	return res.Data.([]*FakeROA)
}

func (rMap *ResourceMap) ToBeAdded(rf bgp.RouteFamily, sn uint32) []*FakeROA {
	result := make(chan *Response)
	rMap.ch <- Request{RequestType: REQ_LIST_TO_BE_ADDED, Key: reqKeys{RF: rf, SN: sn}, Response: result}
	res := <-result
	return res.Data.([]*FakeROA)
}

func (rMap *ResourceMap) HasKey(sn uint32) bool {
	result := make(chan *Response)
	rMap.ch <- Request{RequestType: REQ_IF_SERIAL_EXISTS, Key: sn, Response: result}
	res := <-result
	return res.Data.(bool)
}

func (rMap *ResourceMap) Begin() chan Request {
	result := make(chan *Response)
	t := make(chan Request)
	rMap.ch <- Request{RequestType: REQ_BEGIN_TRANSACTION, Response: result, transaction: t}
	res := <-result
	return res.Data.transaction
}

func (rMap *ResourceMap) End() {
	rMap.ch <- Request{RequestType: REQ_END_TRANSACTION}
}

func handleRequests(c chan Request, rsrc *resource) {
	var err error
	for {
		req := <-c
		switch req.RequestType {
		case REQ_LOAD:
			rsrc, err = newResource(req.Key.([]string))
			log.Infof("The resources have been loaded. (SN: %v)", rsrc.currentSN)
			fallthrough
		case REQ_CURRENT_SERIAL:
			req.Response <- &Response{Data: rsrc.currentSN, Error: err}
		case REQ_RELOAD:
			nextSN := uint32(time.Now().Unix())
			rsrc, err = rsrc.loadAs(nextSN)
			if err == nil {
				req.Response <- &Response{Data: rsrc.currentSN, Error: err}
				break
			}

			if eql := reflect.DeepEqual(rsrc.table[rsrc.currentSN], rsrc.table[nextSN]); !eql {
				log.Infof("The resources have been updated. (SN: %v -> %v)", rsrc.currentSN, nextSN)
				rsrc.currentSN = nextSN
			} else {
				delete(rsrc.table, nextSN)
			}

			for k, _ := range rsrc.table {
				if rsrc.currentSN != k {
					t := time.Now()
					if int64(k) < t.Add(-24*time.Hour).Unix() {
						delete(rsrc.table, k)
						log.Infof("The resources as of %v were expired. (SN: %v)", time.Unix(int64(k), 0).Format("2006/01/02 15:04:05"), k)
					}
				}
			}
			req.Response <- &Response{Data: rsrc.currentSN, Error: err}
		case REQ_CURRENT_LIST:
			fakeROAs := make([]*FakeROA, 0)
			keys := req.Key.(*reqKeys)
			for _, fROA := range treeToSet(rsrc.table[rsrc.currentSN][keys.RF]).ToSlice() {
				fakeROAs = append(fakeROAs, fROA.(*FakeROA))
			}
			req.Response <- &Response{Data: fakeROAs}
		case REQ_LIST_TO_BE_DELETED:
			fakeROAs := make([]*FakeROA, 0)
			keys := req.Key.(*reqKeys)
			for _, fROA := range treeToSet(rsrc.table[keys.SN][keys.RF]).Difference(treeToSet(rsrc.table[rsrc.currentSN][keys.RF])).ToSlice() {
				fakeROAs = append(fakeROAs, fROA.(*FakeROA))
			}
			req.Response <- &Response{Data: fakeROAs}
		case REQ_LIST_TO_BE_ADDED:
			fakeROAs := make([]*FakeROA, 0)
			keys := req.Key.(*reqKeys)
			for _, fROA := range treeToSet(rsrc.table[rsrc.currentSN][keys.RF]).Difference(treeToSet(rsrc.table[keys.SN][keys.RF])).ToSlice() {
				fakeROAs = append(fakeROAs, fROA.(*FakeROA))
			}
			req.Response <- &Response{Data: fakeROAs}
		case REQ_IF_SERIAL_EXISTS:
			_, ok := rsrc.table[req.Key.(uint32)]
			req.Response <- &Response{Data: ok}
		case REQ_BEGIN_TRANSACTION:
			handleRequests(req.transaction, rsrc)
		case REQ_END_TRANSACTION:
			return
		}
	}
}

func runMap(c chan Request) {
	var rsrc *resource
	handleRequests(c, rsrc)
}
