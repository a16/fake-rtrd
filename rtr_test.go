package main

import (
	"bufio"
	"io/ioutil"
	"log"
	"net"
	"os"
	"testing"

	"github.com/osrg/gobgp/pkg/packet/bgp"
	"github.com/osrg/gobgp/pkg/packet/rtr"
	. "github.com/r7kamura/gospel"
)

func TestMain(m *testing.M) {
	log.SetOutput(ioutil.Discard)
	code := m.Run()
	defer os.Exit(code)
}

func prepare(content []string) (*ResourceManager, *os.File) {
	rpslFile, _ := ioutil.TempFile(os.TempDir(), "rtr_test.db")
	addRPSL(rpslFile, content)

	mgr := NewResourceManager(false)
	go mainLoop(mgr, []string{rpslFile.Name()}, 42420, 2, false, true, nil)
	return mgr, rpslFile
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
	r := &rtrConn{conn: conn}
	scanner := bufio.NewScanner(bufio.NewReader(r.conn))
	scanner.Split(rtr.SplitRTR)
	return r, scanner
}

func TestHandleRTR(t *testing.T) {
	var buf []byte
	var m rtr.RTRMessage
	var sn uint32
	var id uint16

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
	mgr, f := prepare(initContent)
	defer os.Remove(f.Name())
	r, scanner := connectRTRServer()

	Context("6.1. Start or Restart", func() {
		pdu := rtr.NewRTRResetQuery()
		r.sendPDU(pdu)

		scanner.Scan()
		buf = scanner.Bytes()
		m, _ = rtr.ParseRTR(buf)
		It("should receive Cache Response PDU", func() {
			_, ok := m.(*rtr.RTRCacheResponse)
			Expect(ok).To(Equal, true)
		})

		scanner.Scan()
		buf = scanner.Bytes()
		m, _ = rtr.ParseRTR(buf)
		It("should receive IPv4 Prefix PDU", func() {
			rtrMsg, ok := m.(*rtr.RTRIPPrefix)
			Expect(ok).To(Equal, true)
			Expect(rtrMsg.Type).To(Equal, uint8(rtr.RTR_IPV4_PREFIX))
		})

		scanner.Scan()
		buf = scanner.Bytes()
		m, _ = rtr.ParseRTR(buf)
		It("should receive IPv6 Prefix PDU", func() {
			rtrMsg, ok := m.(*rtr.RTRIPPrefix)
			Expect(ok).To(Equal, true)
			Expect(rtrMsg.Type).To(Equal, uint8(rtr.RTR_IPV6_PREFIX))
		})

		scanner.Scan()
		buf = scanner.Bytes()
		m, _ = rtr.ParseRTR(buf)
		It("should receive End of Data PDU", func() {
			rtrMsg, ok := m.(*rtr.RTREndOfData)
			id = rtrMsg.SessionID
			sn = rtrMsg.SerialNumber
			Expect(ok).To(Equal, true)
		})
	})

	Context("6.2. Typical Exchange", func() {
		Context("When its serial number is the latest", func() {
			pdu := rtr.NewRTRSerialQuery(r.sessionId, sn)
			r.sendPDU(pdu)

			scanner.Scan()
			buf = scanner.Bytes()
			m, _ = rtr.ParseRTR(buf)
			It("should receive Cache Response PDU", func() {
				_, ok := m.(*rtr.RTRCacheResponse)
				Expect(ok).To(Equal, true)
			})

			scanner.Scan()
			buf = scanner.Bytes()
			m, _ = rtr.ParseRTR(buf)
			It("should receive End of Data PDU", func() {
				_, ok := m.(*rtr.RTREndOfData)
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
			m, _ = rtr.ParseRTR(buf)
			It("should receive Serial Notify PDU", func() {
				_, ok := m.(*rtr.RTRSerialNotify)
				Expect(ok).To(Equal, true)
			})

			pdu := rtr.NewRTRSerialQuery(r.sessionId, sn)
			r.sendPDU(pdu)

			scanner.Scan()
			buf = scanner.Bytes()
			m, _ = rtr.ParseRTR(buf)
			It("should receive Cache Response PDU", func() {
				_, ok := m.(*rtr.RTRCacheResponse)
				Expect(ok).To(Equal, true)
			})

			scanner.Scan()
			buf = scanner.Bytes()
			m, _ = rtr.ParseRTR(buf)
			It("should receive IPv4 Prefix PDU", func() {
				rtrMsg, ok := m.(*rtr.RTRIPPrefix)
				Expect(ok).To(Equal, true)
				Expect(rtrMsg.Type).To(Equal, uint8(rtr.RTR_IPV4_PREFIX))
			})

			scanner.Scan()
			buf = scanner.Bytes()
			m, _ = rtr.ParseRTR(buf)
			It("should receive End of Data PDU", func() {
				rtrMsg, ok := m.(*rtr.RTREndOfData)
				Expect(ok).To(Equal, true)
				id = rtrMsg.SessionID
				sn = rtrMsg.SerialNumber
			})
		})
	})

	Context("6.3. No Incremental Update Available", func() {
		pdu := rtr.NewRTRSerialQuery(id, sn-60*60*24)
		r.sendPDU(pdu)

		scanner.Scan()
		buf = scanner.Bytes()
		m, _ = rtr.ParseRTR(buf)
		It("should receive Cache Reset PDU", func() {
			_, ok := m.(*rtr.RTRCacheReset)
			Expect(ok).To(Equal, true)
		})

		pdu2 := rtr.NewRTRResetQuery()
		r.sendPDU(pdu2)

		scanner.Scan()
		buf = scanner.Bytes()
		m, _ = rtr.ParseRTR(buf)
		It("should receive Cache Response PDU", func() {
			_, ok := m.(*rtr.RTRCacheResponse)
			Expect(ok).To(Equal, true)
		})

		scanner.Scan()
		buf = scanner.Bytes()
		m, _ = rtr.ParseRTR(buf)
		It("should receive IPv4 Prefix PDU", func() {
			rtrMsg, ok := m.(*rtr.RTRIPPrefix)
			Expect(ok).To(Equal, true)
			Expect(rtrMsg.Type).To(Equal, uint8(rtr.RTR_IPV4_PREFIX))
		})

		scanner.Scan()
		buf = scanner.Bytes()
		m, _ = rtr.ParseRTR(buf)
		It("should receive IPv4 Prefix PDU", func() {
			rtrMsg, ok := m.(*rtr.RTRIPPrefix)
			Expect(ok).To(Equal, true)
			Expect(rtrMsg.Type).To(Equal, uint8(rtr.RTR_IPV4_PREFIX))
		})

		scanner.Scan()
		buf = scanner.Bytes()
		m, _ = rtr.ParseRTR(buf)
		It("should receive IPv6 Prefix PDU", func() {
			rtrMsg, ok := m.(*rtr.RTRIPPrefix)
			Expect(ok).To(Equal, true)
			Expect(rtrMsg.Type).To(Equal, uint8(rtr.RTR_IPV6_PREFIX))
		})

		scanner.Scan()
		buf = scanner.Bytes()
		m, _ = rtr.ParseRTR(buf)
		It("should receive End of Data PDU", func() {
			rtrMsg, ok := m.(*rtr.RTREndOfData)
			Expect(ok).To(Equal, true)
			id = rtrMsg.SessionID
			sn = rtrMsg.SerialNumber
		})
	})

	Context("6.4. Cache Has No Data Available", func() {
		trans := mgr.BeginTransaction()
		defer trans.EndTransaction()

		Context("When a serial query is sent", func() {
			pdu := rtr.NewRTRSerialQuery(id, sn)
			r.sendPDU(pdu)

			scanner.Scan()
			buf = scanner.Bytes()
			m, _ = rtr.ParseRTR(buf)
			It("should receive Error Report PDU with no data available", func() {
				rtrMsg, ok := m.(*rtr.RTRErrorReport)
				Expect(ok).To(Equal, true)
				Expect(rtrMsg.ErrorCode).To(Equal, rtr.NO_DATA_AVAILABLE)
			})
		})

		Context("When a reset query is sent", func() {
			pdu := rtr.NewRTRResetQuery()
			r.sendPDU(pdu)

			scanner.Scan()
			buf = scanner.Bytes()
			m, _ = rtr.ParseRTR(buf)
			It("should receive Error Report PDU with no data available", func() {
				rtrMsg, ok := m.(*rtr.RTRErrorReport)
				Expect(ok).To(Equal, true)
				Expect(rtrMsg.ErrorCode).To(Equal, rtr.NO_DATA_AVAILABLE)
			})
		})
	})

	Context("Error handling", func() {
		pdu := rtr.NewRTRResetQuery()
		pdu.Version = 1
		r.sendPDU(pdu)

		scanner.Scan()
		buf := scanner.Bytes()
		m, _ := rtr.ParseRTR(buf)
		It("should receive Error Report PDU with unsupported protocol version", func() {
			rtrMsg, ok := m.(*rtr.RTRErrorReport)
			Expect(ok).To(Equal, true)
			Expect(rtrMsg.ErrorCode).To(Equal, rtr.UNSUPPORTED_PROTOCOL_VERSION)
		})
	})
}

func TestRFToIPVer(t *testing.T) {
	Context("with bgp.RF_IPv4_UC", func() {
		It("should convert to \"IPv4\"", func() {
			Expect(RFToIPVer(bgp.RF_IPv4_UC)).To(Equal, "IPv4")
		})
	})

	Context("with bgp.RF_IPv6_UC", func() {
		It("should convert to \"IPv6\"", func() {
			Expect(RFToIPVer(bgp.RF_IPv6_UC)).To(Equal, "IPv6")
		})
	})

	Context("with unsupported RouteFamily", func() {
		It("should convert to \"Unsupported\"", func() {
			Expect(RFToIPVer(bgp.RF_EVPN)).To(Equal, "Unsupported")
		})
	})
}
