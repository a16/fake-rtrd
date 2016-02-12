package main

import (
	"bufio"
	"io/ioutil"
	"log"
	"net"
	"os"
	"testing"

	"github.com/osrg/gobgp/packet"
	. "github.com/r7kamura/gospel"
)

func TestMain(m *testing.M) {
	log.SetOutput(ioutil.Discard)
	code := m.Run()
	defer os.Exit(code)
}

func prepare(content []string) *os.File {
	rpslFile, _ := ioutil.TempFile(os.TempDir(), "rtr_test.db")
	addRPSL(rpslFile, content)

	go mainLoop([]string{rpslFile.Name()}, 42420, 2, false, true)
	return rpslFile
}

func addRPSL(f *os.File, content []string) {
	for _, text := range content {
		f.WriteString(text)
	}
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

		initContent := []string{
			"route:  192.168.0.0/24\n",
			"origin: AS65000\n",
			"source: TEST\n",
			"\n",
			"route6: 2001:db8::/32\n",
			"origin: AS65000\n",
			"source: TEST\n",
			"\n",
		}
		f := prepare(initContent)
		defer os.Remove(f.Name())
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
			Context("When its serial number is the latest", func() {
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

			Context("When its serial number is behind", func() {
				updateContent := []string{
					"route:  192.168.1.0/24\n",
					"origin: AS65001\n",
					"source: TEST\n",
					"\n",
				}
				addRPSL(f, updateContent)

				scanner.Scan()
				buf = scanner.Bytes()
				m, _ = bgp.ParseRTR(buf)
				It("should receive Serial Notify PDU", func() {
					_, ok := m.(*bgp.RTRSerialNotify)
					Expect(ok).To(Equal, true)
				})

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
				It("should receive IPv4 Prefix PDU", func() {
					rtrMsg, ok := m.(*bgp.RTRIPPrefix)
					Expect(ok).To(Equal, true)
					Expect(rtrMsg.Type).To(Equal, uint8(bgp.RTR_IPV4_PREFIX))
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
