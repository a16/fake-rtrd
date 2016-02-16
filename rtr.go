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
	"bufio"
	"bytes"
	"net"
	"strconv"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/packet"
)

const rtrProtocolVersion uint8 = 0
const chunkSizeIPPrefixMsg = 40

type rtrConn struct {
	conn       *net.TCPConn
	sessionId  uint16
	remoteAddr net.Addr
}

type rtrServer struct {
	connCh     chan *rtrConn
	listenPort int
}

func newRTRServer(port int) *rtrServer {
	s := &rtrServer{
		connCh:     make(chan *rtrConn, 1),
		listenPort: port,
	}
	return s
}

func (s *rtrServer) run() {
	service := ":" + strconv.Itoa(s.listenPort)
	addr, _ := net.ResolveTCPAddr("tcp", service)

	l, err := net.ListenTCP("tcp", addr)
	checkError(err)

	for i := 0; ; {
		conn, err := l.AcceptTCP()
		if err != nil {
			continue
		}
		i++
		c := &rtrConn{
			conn:       conn,
			sessionId:  uint16(i),
			remoteAddr: conn.RemoteAddr(),
		}
		s.connCh <- c
	}
}

func (rtr *rtrConn) sendPDU(msg bgp.RTRMessage) error {
	pdu, _ := msg.Serialize()
	_, err := rtr.conn.Write(pdu)
	if err != nil {
		return err
	}
	return nil
}

func (rtr *rtrConn) sendPDUs(msgs []bgp.RTRMessage) (int, error) {
	pdus := make([][]byte, 0)
	counter := 0
	for _, msg := range msgs {
		pdu, err := msg.Serialize()
		if err != nil {
			return 0, err
		}
		counter++
		pdus = append(pdus, pdu)
	}
	_, err := rtr.conn.Write(bytes.Join(pdus, nil))
	if err != nil {
		return 0, err
	}
	return counter, nil
}

func chunkFakeROAs(list []*FakeROA, n int) chan []*FakeROA {
	ch := make(chan []*FakeROA)

	go func() {
		for i := 0; i < len(list); i += n {
			fromIdx := i
			toIdx := i + n
			if toIdx > len(list) {
				toIdx = len(list)
			}
			ch <- list[fromIdx:toIdx]
		}
		close(ch)
	}()

	return ch
}

func (rtr *rtrConn) cacheResponse(currentSN uint32, lists FakeROATable) error {
	if err := rtr.sendPDU(bgp.NewRTRCacheResponse(rtr.sessionId)); err != nil {
		return err
	}
	log.Infof("Sent Cache Response PDU to %v (ID: %v)", rtr.remoteAddr, rtr.sessionId)

	for _, rf := range []bgp.RouteFamily{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC} {
		for _, flag := range []uint8{bgp.ANNOUNCEMENT, bgp.WITHDRAWAL} {
			msgs := make([]bgp.RTRMessage, 0)
			for roas := range chunkFakeROAs(lists[rf][flag], chunkSizeIPPrefixMsg) {
				for _, v := range roas {
					msgs = append(msgs, bgp.NewRTRIPPrefix(v.Prefix, v.PrefixLen, v.MaxLen, v.AS, flag))
				}
				counter, err := rtr.sendPDUs(msgs)
				if err != nil {
					return err
				}
				log.Infof("Sent %s Prefix PDU(s) to %v (%d ROA(s), flags: %v)", strings.Split(rf.String(), "_")[1], rtr.remoteAddr, counter, flag)
			}
		}
	}

	if err := rtr.sendPDU(bgp.NewRTREndOfData(rtr.sessionId, currentSN)); err != nil {
		return err
	}
	log.Infof("Sent End of Data PDU to %v (ID: %v, SN: %v)", rtr.remoteAddr, rtr.sessionId, currentSN)

	return nil
}

func (rtr *rtrConn) noIncrementalUpdateAvailable() error {
	if err := rtr.sendPDU(bgp.NewRTRCacheReset()); err != nil {
		return err
	}
	log.Infof("Sent Cache Reset PDU to %v", rtr.remoteAddr)

	return nil
}

func (rtr *rtrConn) cacheHasNoDataAvailable() error {
	if err := rtr.sendPDU(bgp.NewRTRErrorReport(bgp.NO_DATA_AVAILABLE, nil, nil)); err != nil {
		return err
	}
	log.Infof("Sent Error Report PDU to %v (ID: %v, ErrorCode: %v)", rtr.remoteAddr, rtr.sessionId, bgp.NO_DATA_AVAILABLE)

	return nil
}

type errMsg struct {
	code uint16
	data []byte
}

type resourceResponse struct {
	sn   uint32
	list FakeROATable
}

func handleRTR(rtr *rtrConn, mgr *ResourceManager) {
	bcastReceiver := mgr.serialNotify.Join()
	scanner := bufio.NewScanner(bufio.NewReader(rtr.conn))
	scanner.Split(bgp.SplitRTR)

	msgCh := make(chan bgp.RTRMessage, 1)
	errCh := make(chan *errMsg, 1)
	go func() {
		defer func() {
			log.Infof("Connection to %v was closed. (ID: %v)", rtr.remoteAddr, rtr.sessionId)
			rtr.conn.Close()
		}()

		for scanner.Scan() {
			buf := scanner.Bytes()
			if buf[0] != rtrProtocolVersion {
				errCh <- &errMsg{code: bgp.UNSUPPORTED_PROTOCOL_VERSION, data: buf}
				continue
			}
			m, err := bgp.ParseRTR(buf)
			if err != nil {
				errCh <- &errMsg{code: bgp.INVALID_REQUEST, data: buf}
				continue
			}
			msgCh <- m
		}
	}()

LOOP:
	for {
		select {
		case <-bcastReceiver.In:
			currentSN := mgr.CurrentSerial()
			if err := rtr.sendPDU(bgp.NewRTRSerialNotify(rtr.sessionId, currentSN)); err != nil {
				break LOOP
			}
			log.Infof("Sent Serial Notify PDU to %v (ID: %v, SN: %v)", rtr.remoteAddr, rtr.sessionId, currentSN)
		case msg := <-errCh:
			rtr.sendPDU(bgp.NewRTRErrorReport(msg.code, msg.data, nil))
			log.Infof("Sent Error Report PDU to %v (ID: %v, ErrorCode: %v)", rtr.remoteAddr, rtr.sessionId, msg.code)
			return
		case m := <-msgCh:
			switch msg := m.(type) {
			case *bgp.RTRSerialQuery:
				peerSN := msg.SerialNumber
				log.Infof("Received Serial Query PDU from %v (ID: %v, SN: %d)", rtr.remoteAddr, msg.SessionID, peerSN)

				timeoutCh := make(chan bool, 1)
				resourceResponseCh := make(chan *resourceResponse, 1)

				go func(tCh chan bool) {
					time.Sleep(10 * time.Second)
					tCh <- true
				}(timeoutCh)

				go func(rrCh chan *resourceResponse, peerSN uint32) {
					trans := mgr.BeginTransaction()
					defer trans.EndTransaction()
					if trans.HasKey(peerSN) {
						rrCh <- &resourceResponse{
							sn:   trans.CurrentSerial(),
							list: trans.DeltaList(peerSN),
						}
					} else {
						rrCh <- nil
					}
				}(resourceResponseCh, peerSN)

				select {
				case rr := <-resourceResponseCh:
					if rr != nil {
						if err := rtr.cacheResponse(rr.sn, rr.list); err == nil {
							continue
						}
					} else {
						if err := rtr.noIncrementalUpdateAvailable(); err == nil {
							continue
						}
					}
				case <-timeoutCh:
					if err := rtr.cacheHasNoDataAvailable(); err == nil {
						continue
					}
				}
				break LOOP
			case *bgp.RTRResetQuery:
				log.Infof("Received Reset Query PDU from %v", rtr.remoteAddr)

				timeoutCh := make(chan bool, 1)
				resourceResponseCh := make(chan *resourceResponse, 1)

				go func(tCh chan bool) {
					time.Sleep(10 * time.Second)
					tCh <- true
				}(timeoutCh)

				go func(rrCh chan *resourceResponse) {
					trans := mgr.BeginTransaction()
					defer trans.EndTransaction()
					rrCh <- &resourceResponse{
						sn:   trans.CurrentSerial(),
						list: trans.CurrentList(),
					}
				}(resourceResponseCh)

				select {
				case rr := <-resourceResponseCh:
					if err := rtr.cacheResponse(rr.sn, rr.list); err == nil {
						continue
					}
				case <-timeoutCh:
					if err := rtr.cacheHasNoDataAvailable(); err == nil {
						continue
					}
				}

				break LOOP
			case *bgp.RTRErrorReport:
				log.Warnf("Received Error Report PDU from %v (%#v)", rtr.remoteAddr, msg)
				return
			default:
				pdu, _ := msg.Serialize()
				log.Warnf("Received unsupported PDU (type %d) from %v (%#v)", pdu[1], rtr.remoteAddr, msg)
				rtr.sendPDU(bgp.NewRTRErrorReport(bgp.UNSUPPORTED_PDU_TYPE, pdu, nil))
				return
			}
		}
	}
	rtr.sendPDU(bgp.NewRTRErrorReport(bgp.INTERNAL_ERROR, nil, nil))
	return
}
