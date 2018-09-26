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
	"net"
	"strconv"
	"time"

	"github.com/osrg/gobgp/pkg/packet/bgp"
	"github.com/osrg/gobgp/pkg/packet/rtr"
	log "github.com/sirupsen/logrus"
)

const rtrProtocolVersion uint8 = 0

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

func (r *rtrConn) sendPDU(msg rtr.RTRMessage) error {
	pdu, _ := msg.Serialize()
	_, err := r.conn.Write(pdu)
	if err != nil {
		return err
	}
	return nil
}

func (r *rtrConn) cacheResponse(currentSN uint32, lists FakeROATable) error {
	if err := r.sendPDU(rtr.NewRTRCacheResponse(r.sessionId)); err != nil {
		return err
	}
	log.Infof("Sent Cache Response PDU to %v (ID: %v)", r.remoteAddr, r.sessionId)

	for _, rf := range []bgp.RouteFamily{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC} {
		for _, flag := range []uint8{rtr.ANNOUNCEMENT, rtr.WITHDRAWAL} {
			for _, v := range lists[rf][flag] {
				if err := r.sendPDU(rtr.NewRTRIPPrefix(v.Prefix, v.PrefixLen, v.MaxLen, v.AS, flag)); err != nil {
					return err
				}
				log.Debugf("Sent %s Prefix PDU to %v (Prefix: %v/%v, Maxlen: %v, AS: %v, flags: %v)", RFToIPVer(rf), r.remoteAddr, v.Prefix, v.PrefixLen, v.MaxLen, v.AS, flag)
			}
			prefixes := len(lists[rf][flag])
			if !commandOpts.Debug && prefixes != 0 {
				log.Infof("Sent %s Prefix PDU(s) to %v (%d ROA(s), flags: %v)", RFToIPVer(rf), r.remoteAddr, prefixes, flag)
			}
		}
	}

	if err := r.sendPDU(rtr.NewRTREndOfData(r.sessionId, currentSN)); err != nil {
		return err
	}
	log.Infof("Sent End of Data PDU to %v (ID: %v, SN: %v)", r.remoteAddr, r.sessionId, currentSN)

	return nil
}

func (r *rtrConn) noIncrementalUpdateAvailable() error {
	if err := r.sendPDU(rtr.NewRTRCacheReset()); err != nil {
		return err
	}
	log.Infof("Sent Cache Reset PDU to %v", r.remoteAddr)

	return nil
}

func (r *rtrConn) cacheHasNoDataAvailable() error {
	if err := r.sendPDU(rtr.NewRTRErrorReport(rtr.NO_DATA_AVAILABLE, nil, nil)); err != nil {
		return err
	}
	log.Infof("Sent Error Report PDU to %v (ID: %v, ErrorCode: %v)", r.remoteAddr, r.sessionId, rtr.NO_DATA_AVAILABLE)

	return nil
}

func RFToIPVer(rf bgp.RouteFamily) string {
	switch rf {
	case bgp.RF_IPv4_UC:
		return "IPv4"
	case bgp.RF_IPv6_UC:
		return "IPv6"
	default:
		return "Unsupported"
	}
}

type errMsg struct {
	code uint16
	data []byte
}

type resourceResponse struct {
	sn   uint32
	list FakeROATable
}

func handleRTR(r *rtrConn, mgr *ResourceManager) {
	bcastReceiver := mgr.serialNotify.Join()
	scanner := bufio.NewScanner(bufio.NewReader(r.conn))
	scanner.Split(rtr.SplitRTR)

	msgCh := make(chan rtr.RTRMessage, 1)
	errCh := make(chan *errMsg, 1)
	go func() {
		defer func() {
			log.Infof("Connection to %v was closed. (ID: %v)", r.remoteAddr, r.sessionId)
			r.conn.Close()
		}()

		for scanner.Scan() {
			buf := scanner.Bytes()
			if buf[0] != rtrProtocolVersion {
				errCh <- &errMsg{code: rtr.UNSUPPORTED_PROTOCOL_VERSION, data: buf}
				continue
			}
			m, err := rtr.ParseRTR(buf)
			if err != nil {
				errCh <- &errMsg{code: rtr.INVALID_REQUEST, data: buf}
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
			if err := r.sendPDU(rtr.NewRTRSerialNotify(r.sessionId, currentSN)); err != nil {
				break LOOP
			}
			log.Infof("Sent Serial Notify PDU to %v (ID: %v, SN: %v)", r.remoteAddr, r.sessionId, currentSN)
		case msg := <-errCh:
			r.sendPDU(rtr.NewRTRErrorReport(msg.code, msg.data, nil))
			log.Infof("Sent Error Report PDU to %v (ID: %v, ErrorCode: %v)", r.remoteAddr, r.sessionId, msg.code)
			return
		case m := <-msgCh:
			switch msg := m.(type) {
			case *rtr.RTRSerialQuery:
				peerSN := msg.SerialNumber
				log.Infof("Received Serial Query PDU from %v (ID: %v, SN: %d)", r.remoteAddr, msg.SessionID, peerSN)

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
						if err := r.cacheResponse(rr.sn, rr.list); err == nil {
							continue
						}
					} else {
						if err := r.noIncrementalUpdateAvailable(); err == nil {
							continue
						}
					}
				case <-timeoutCh:
					if err := r.cacheHasNoDataAvailable(); err == nil {
						continue
					}
				}
				break LOOP
			case *rtr.RTRResetQuery:
				log.Infof("Received Reset Query PDU from %v", r.remoteAddr)

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
					if err := r.cacheResponse(rr.sn, rr.list); err == nil {
						continue
					}
				case <-timeoutCh:
					if err := r.cacheHasNoDataAvailable(); err == nil {
						continue
					}
				}

				break LOOP
			case *rtr.RTRErrorReport:
				log.Warnf("Received Error Report PDU from %v (%#v)", r.remoteAddr, msg)
				return
			default:
				pdu, _ := msg.Serialize()
				log.Warnf("Received unsupported PDU (type %d) from %v (%#v)", pdu[1], r.remoteAddr, msg)
				r.sendPDU(rtr.NewRTRErrorReport(rtr.UNSUPPORTED_PDU_TYPE, pdu, nil))
				return
			}
		}
	}
	r.sendPDU(rtr.NewRTRErrorReport(rtr.INTERNAL_ERROR, nil, nil))
	return
}
