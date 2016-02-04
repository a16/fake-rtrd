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
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/packet"
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
		connCh:     make(chan *rtrConn),
		listenPort: port,
	}
	return s
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

func (rtr *rtrConn) sendDeltaPrefixes(rMap *ResourceMap, peerSN uint32) error {
	var counter uint32
	for _, rf := range []bgp.RouteFamily{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC} {
		counter = 0
		for _, v := range rMap.ToBeAdded(rf, peerSN) {
			if err := rtr.sendPDU(bgp.NewRTRIPPrefix(v.Prefix, v.PrefixLen, v.MaxLen, v.AS, bgp.ANNOUNCEMENT)); err != nil {
				return err
			}
			counter++
			log.Debugf("Sent %s Prefix PDU to %v (Prefix: %v/%v, Maxlen: %v, AS: %v, flags: ANNOUNCE)", RFToIPVer(rf), rtr.remoteAddr, v.Prefix, v.PrefixLen, v.MaxLen, v.AS)
		}
		if !commandOpts.Debug && counter != 0 {
			log.Infof("Sent %s Prefix PDU(s) to %v (%d ROA(s), flags: ANNOUNCE)", RFToIPVer(rf), rtr.remoteAddr, counter)
		}

		counter = 0
		for _, v := range rMap.ToBeDeleted(rf, peerSN) {
			if err := rtr.sendPDU(bgp.NewRTRIPPrefix(v.Prefix, v.PrefixLen, v.MaxLen, v.AS, bgp.WITHDRAWAL)); err != nil {
				return err
			}
			counter++
			log.Debugf("Sent %s PDU to %v (Prefix: %v/%v, Maxlen: %v, AS: %v, flags: WITHDRAW)", RFToIPVer(rf), rtr.remoteAddr, v.Prefix, v.PrefixLen, v.MaxLen, v.AS)
		}
		if !commandOpts.Debug && counter != 0 {
			log.Infof("Sent %s Prefix PDU(s) to %v (%d ROA(s), flags: WITHDRAW)", RFToIPVer(rf), rtr.remoteAddr, counter)
		}
	}
	return nil
}

func (rtr *rtrConn) sendAllPrefixes(rMap *ResourceMap) error {
	var counter uint32
	for _, rf := range []bgp.RouteFamily{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC} {
		counter = 0
		for _, v := range rMap.CurrentList(rf) {
			if err := rtr.sendPDU(bgp.NewRTRIPPrefix(v.Prefix, v.PrefixLen, v.MaxLen, v.AS, bgp.ANNOUNCEMENT)); err != nil {
				return err
			}
			counter++
			log.Debugf("Sent %s Prefix PDU to %v (Prefix: %v/%v, Maxlen: %v, AS: %v, flags: ANNOUNCE)", RFToIPVer(rf), rtr.remoteAddr, v.Prefix, v.PrefixLen, v.MaxLen, v.AS)
		}
		if !commandOpts.Debug && counter != 0 {
			log.Infof("Sent %s Prefix PDU(s) to %v (%d ROA(s), flags: ANNOUNCE)", RFToIPVer(rf), rtr.remoteAddr, counter)
		}
	}
	return nil
}

func (rtr *rtrConn) sendPDU(pdu bgp.RTRMessage) error {
	data, _ := pdu.Serialize()
	_, err := rtr.conn.Write(data)
	if err != nil {
		return err
	}
	return nil
}

func RFToIPVer(rf bgp.RouteFamily) string {
	return strings.Split(rf.String(), "_")[1]
}

type errMsg struct {
	code uint16
	data []byte
}

func handleRTR(rtr *rtrConn, rMap *ResourceMap) {
	scanner := bufio.NewScanner(bufio.NewReader(rtr.conn))
	scanner.Split(bgp.SplitRTR)

	msgCh := make(chan bgp.RTRMessage)
	errCh := make(chan *errMsg)
	go func() {
		defer func() {
			log.Infof("Connection to %v was closed. (ID: %v)", rtr.remoteAddr, rtr.sessionId)
			rtr.conn.Close()
		}()

		for scanner.Scan() {
			buf := scanner.Bytes()
			if buf[0] != rtrProtocolVersion {
				errCh <- &errMsg{code: bgp.UNSUPPORTED_PROTOCOL_VERSION, data: buf}
			}
			m, err := bgp.ParseRTR(buf)
			if err != nil {
				errCh <- &errMsg{code: bgp.INVALID_REQUEST, data: buf}
			}
			msgCh <- m
		}
	}()

LOOP:
	for {
		select {
		//case updatedResource := <-bcastReceiver.In:
		//	rsrc = updatedResource.(*resource)
		//	if rsrc.serialNotify {
		//		if err := rtr.sendPDU(bgp.NewRTRSerialNotify(rtr.sessionId, rsrc.currentSN)); err != nil {
		//			break LOOP
		//		}
		//		log.Infof("Sent Serial Notify PDU to %v (ID: %v, SN: %v)", rtr.remoteAddr, rtr.sessionId, rsrc.currentSN)
		//	}
		case msg := <-errCh:
			rtr.sendPDU(bgp.NewRTRErrorReport(msg.code, msg.data, nil))
			log.Infof("Sent Error Report PDU to %v (ID: %v, ErrorCode: %v)", rtr.remoteAddr, rtr.sessionId, msg.code)
			return
		case m := <-msgCh:
			switch msg := m.(type) {
			case *bgp.RTRSerialQuery:
				peerSN := msg.SerialNumber
				log.Infof("Received Serial Query PDU from %v (ID: %v, SN: %d)", rtr.remoteAddr, msg.SessionID, peerSN)
				if rMap.HasKey(peerSN) {
					if err := rtr.sendPDU(bgp.NewRTRCacheResponse(rtr.sessionId)); err == nil {
						log.Infof("Sent Cache Response PDU to %v (ID: %v)", rtr.remoteAddr, rtr.sessionId)
						if err := rtr.sendDeltaPrefixes(rMap, peerSN); err == nil {
							if err := rtr.sendPDU(bgp.NewRTREndOfData(rtr.sessionId, rMap.CurrentSerial())); err == nil {
								log.Infof("Sent End of Data PDU to %v (ID: %v, SN: %v)", rtr.remoteAddr, rtr.sessionId, rMap.CurrentSerial())
								continue
							}
						}
					}
				} else {
					if err := rtr.sendPDU(bgp.NewRTRCacheReset()); err == nil {
						log.Infof("Sent Cache Reset PDU to %v", rtr.remoteAddr)
						continue
					}
				}
				break LOOP
			case *bgp.RTRResetQuery:
				log.Infof("Received Reset Query PDU from %v", rtr.remoteAddr)

				if err := rtr.sendPDU(bgp.NewRTRCacheResponse(rtr.sessionId)); err == nil {
					log.Infof("Sent Cache Response PDU to %v (ID: %v)", rtr.remoteAddr, rtr.sessionId)
					//if rsrc == nil {
					//	rtr.sendPDU(bgp.NewRTRErrorReport(bgp.NO_DATA_AVAILABLE, nil, nil))
					//	return
					//} else {
					if err := rtr.sendAllPrefixes(rMap); err == nil {
						if err := rtr.sendPDU(bgp.NewRTREndOfData(rtr.sessionId, rMap.CurrentSerial())); err == nil {
							log.Infof("Sent End of Data PDU to %v (ID: %v, SN: %v)", rtr.remoteAddr, rtr.sessionId, rMap.CurrentSerial())
							continue
						}
					}
					//}
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
		default:
			rMap.CurrentSerial()
		}
	}
	rtr.sendPDU(bgp.NewRTRErrorReport(bgp.INTERNAL_ERROR, nil, nil))
	return
}
