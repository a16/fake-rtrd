package main

import (
	"bufio"
	"io/ioutil"
	"net"
	"os"
	"testing"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/grafov/bcast"
	"github.com/osrg/gobgp/packet"
	. "github.com/r7kamura/gospel"
)

var pROA *pseudoROA
var pROAGroup *bcast.Group

func TestMain(m *testing.M) {
	log.SetOutput(ioutil.Discard)
	prepare([]string{"test.db"})
	code := m.Run()
	defer os.Exit(code)
}

func prepare(files []string) {
	pROA, _ = newPseudoROA(files)
	pROAGroup = bcast.NewGroup()
	go pROAGroup.Broadcasting(0)

	go run(42420, 59, pROA, pROAGroup)
}

func connectRTRServer() (*rtrConn, *bufio.Scanner) {
	var tcpAddr *net.TCPAddr
	var conn *net.TCPConn
	var err error
	for {
		tcpAddr, err = net.ResolveTCPAddr("tcp", ":42420")
		if err == nil {
			break
		}
	}
	for {
		conn, err = net.DialTCP("tcp", nil, tcpAddr)
		if err == nil {
			break
		}
	}
	rtr := &rtrConn{conn: conn}
	scanner := bufio.NewScanner(bufio.NewReader(rtr.conn))
	scanner.Split(bgp.SplitRTR)
	return rtr, scanner
}

func TestHandleRTR(t *testing.T) {
	Describe(t, "handleRTR", func() {
		var buf []byte
		var m bgp.RTRMessage
		var sn uint32
		rtr, scanner := connectRTRServer()

		Context("6.1. Start or Restart", func() {
			pdu := bgp.NewRTRResetQuery()
			rtr.sendPDU(pdu)

			scanner.Scan()
			buf = scanner.Bytes()
			m, _ = bgp.ParseRTR(buf)
			It("should receive Cache Response PDU", func() {
				_, ok := m.(*bgp.RTRCacheResponse)
				Expect(ok).To(Equal, true)
			})

			scanner.Scan()
			buf = scanner.Bytes()
			m, _ = bgp.ParseRTR(buf)
			It("should receive IPv4 Prefix PDU", func() {
				rtrMsg, ok := m.(*bgp.RTRIPPrefix)
				Expect(ok).To(Equal, true)
				Expect(rtrMsg.Type).To(Equal, uint8(bgp.RTR_IPV4_PREFIX))
			})

			scanner.Scan()
			buf = scanner.Bytes()
			m, _ = bgp.ParseRTR(buf)
			It("should receive IPv6 Prefix PDU", func() {
				rtrMsg, ok := m.(*bgp.RTRIPPrefix)
				Expect(ok).To(Equal, true)
				Expect(rtrMsg.Type).To(Equal, uint8(bgp.RTR_IPV6_PREFIX))
			})

			scanner.Scan()
			buf = scanner.Bytes()
			m, _ = bgp.ParseRTR(buf)
			It("should receive End of Data PDU", func() {
				rtrMsg, ok := m.(*bgp.RTREndOfData)
				sn = rtrMsg.SerialNumber
				Expect(ok).To(Equal, true)
			})
		})

		Context("6.2. Typical Exchange", func() {
			Context("When its Serial Number is latest", func() {
				pdu := bgp.NewRTRSerialQuery(rtr.sessionId, sn)
				rtr.sendPDU(pdu)

				scanner.Scan()
				buf = scanner.Bytes()
				m, _ = bgp.ParseRTR(buf)
				It("should receive Cache Response PDU", func() {
					_, ok := m.(*bgp.RTRCacheResponse)
					Expect(ok).To(Equal, true)
				})

				scanner.Scan()
				buf = scanner.Bytes()
				m, _ = bgp.ParseRTR(buf)
				It("should receive End of Data PDU", func() {
					_, ok := m.(*bgp.RTREndOfData)
					Expect(ok).To(Equal, true)
				})
			})

			Context("When its Serial Number is not latest", func() {
				nextSN := uint32(time.Now().Unix())
				pROA.addValidInfo(nextSN, "AS65002", "172.16.0.0/24", 32)
				pROA.reload(pROAGroup)

				pdu := bgp.NewRTRSerialQuery(rtr.sessionId, sn)
				rtr.sendPDU(pdu)

				scanner.Scan()
				buf = scanner.Bytes()
				m, _ = bgp.ParseRTR(buf)
				It("should receive Cache Response PDU", func() {
					_, ok := m.(*bgp.RTRCacheResponse)
					Expect(ok).To(Equal, true)
				})

				scanner.Scan()
				buf = scanner.Bytes()
				m, _ = bgp.ParseRTR(buf)
				It("should receive End of Data PDU", func() {
					_, ok := m.(*bgp.RTREndOfData)
					Expect(ok).To(Equal, true)
				})
			})
		})

		Context("when sending PDU with unsupported version", func() {
			pdu := bgp.NewRTRResetQuery()
			pdu.Version = 1
			rtr.sendPDU(pdu)

			scanner.Scan()
			buf := scanner.Bytes()
			m, _ := bgp.ParseRTR(buf)
			It("should receive Error Report PDU with unsupported protocol version", func() {
				rtrMsg, ok := m.(*bgp.RTRErrorReport)
				Expect(ok).To(Equal, true)
				Expect(rtrMsg.ErrorCode).To(Equal, bgp.UNSUPPORTED_PROTOCOL_VERSION)
			})
		})
	})
}
