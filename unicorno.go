package main

import (
	"bufio"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket/tcpassembly"
	"code.google.com/p/gopacket/tcpassembly/tcpreader"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

var iface = flag.String("i", "en0", "Interface to get packets from")
var snaplen = flag.Int("s", 1600, "SnapLen for pcap packet capture")
var filter = flag.String("f", "tcp and dst port 80", "BPF filter for pcap")

type httpStreamFactory struct {
	requests map[string]*HttpReq
	mtx      sync.Mutex
}

type HttpReq struct {
	r         *http.Request
	startTime time.Time
	endTime   time.Time
}

func NewHttpReq(req *http.Request) *HttpReq {
	return &HttpReq{
		r:         req,
		startTime: time.Now(),
	}
}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	factory        *httpStreamFactory
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
		factory:   h,
	}
	go hstream.run()
	return &hstream.r
}

func (factory *httpStreamFactory) tagStart(h *httpStream, req *http.Request) {
	factory.mtx.Lock()
	defer factory.mtx.Unlock()
	key := fmt.Sprintf("%s%s", h.net, h.transport)
	factory.requests[key] = NewHttpReq(req)
	log.Println("Starting request", req.Host, req.RequestURI)
}

func (factory *httpStreamFactory) tagStop(h *httpStream, bodyBytes int) {
	factory.mtx.Lock()
	defer factory.mtx.Unlock()
	key := fmt.Sprintf("%s%s", h.net, h.transport)
	req, ok := factory.requests[key]
	if !ok {
		return
	}
	log.Println("Finished request", req.r.Host, req.r.RequestURI)
	delete(factory.requests, key)
}

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	for {
		req, err := http.ReadRequest(buf)
		if err != nil {
			return
		}
		h.factory.tagStart(h, req)
		bodyBytes := tcpreader.DiscardBytesToEOF(req.Body)
		req.Body.Close()
		h.factory.tagStop(h, bodyBytes)
	}
}

func main() {
	flag.Parse()
	log.Printf("starting capture on interface %q", *iface)
	// Set up pcap packet capture
	handle, err := pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	if err := handle.SetBPFFilter(*filter); err != nil {
		panic(err)
	}

	// Set up assembly
	streamFactory := &httpStreamFactory{
		requests: make(map[string]*HttpReq),
	}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	// Every minute, flush connections that haven't seen activity in the past 2 minutes.
	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-packets:
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}
