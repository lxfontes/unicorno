package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket/tcpassembly"
	"code.google.com/p/gopacket/tcpassembly/tcpreader"
)

var iface = flag.String("i", "eth0", "Interface to get packets from")
var snaplen = flag.Int("l", 1600, "SnapLen for pcap packet capture")
var srcFilter = flag.String("s", "tcp and src port 80", "BPF filter for pcap")
var dstFilter = flag.String("d", "tcp and dst port 80", "BPF filter for pcap")

type inFlightRequest struct {
	req       *http.Request
	startTime time.Time
}

func (i *inFlightRequest) String() string {
	return fmt.Sprintf("[%s] http://%s%s", i.req.Method, i.req.Host, i.req.RequestURI)
}

type PortHash map[uint64]*inFlightRequest
type IpHash map[uint64]PortHash

type requestPool struct {
	inFlight IpHash
	mtx      sync.Mutex
}

func (p *requestPool) RemoveInFlight() {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	removeQueue := []uint64{}

	cutOff := time.Now().Add(-1 * time.Minute)
	for _, flowMap := range p.inFlight {
		for hash, req := range flowMap {
			if req.startTime.Before(cutOff) {
				removeQueue = append(removeQueue, hash)
			}
		}

		for _, hash := range removeQueue {
			delete(flowMap, hash)
		}
	}
}

func (p *requestPool) PutReq(net gopacket.Flow, transport gopacket.Flow, req *http.Request, when time.Time) {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	r := &inFlightRequest{
		req:       req,
		startTime: when,
	}

	netHash := net.FastHash()
	portHash := transport.FastHash()

	_, ok := p.inFlight[netHash]
	if !ok {
		p.inFlight[netHash] = make(PortHash)
	}
	p.inFlight[netHash][portHash] = r
}

func (p *requestPool) PutResp(net gopacket.Flow, transport gopacket.Flow, resp *http.Response, when time.Time) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	netHash := net.FastHash()
	portHash := transport.FastHash()

	flowMap, ok := p.inFlight[netHash]
	if !ok {
		return
	}

	req, ok := flowMap[portHash]
	if !ok {
		return
	}

	deltaTime := when.Sub(req.startTime).String()
	fmt.Println(req, "->", resp.Status, ":", deltaTime)
	delete(flowMap, portHash)
}

type srcStreamFactory struct {
	pool *requestPool
}

func (s *srcStreamFactory) New(net gopacket.Flow, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &tcpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go s.run(hstream)
	return &hstream.r
}

type dstStreamFactory struct {
	pool *requestPool
}

func (d *dstStreamFactory) New(net gopacket.Flow, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &tcpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go d.run(hstream)
	return &hstream.r
}

type tcpStream struct {
	net       gopacket.Flow
	transport gopacket.Flow
	r         tcpreader.ReaderStream
}

func (d *dstStreamFactory) run(h *tcpStream) {
	startTime := time.Now()
	buf := bufio.NewReader(&h.r)
	req, err := http.ReadRequest(buf)
	if err != nil {
		return
	}
	defer req.Body.Close()
	d.pool.PutReq(h.net, h.transport, req, startTime)
	tcpreader.DiscardBytesToFirstError(buf)
}

func (s *srcStreamFactory) run(h *tcpStream) {
	buf := bufio.NewReader(&h.r)
	req := &http.Request{}
	resp, err := http.ReadResponse(buf, req)
	if err != nil {
		return
	}
	tcpreader.DiscardBytesToFirstError(buf)
	s.pool.PutResp(h.net, h.transport, resp, time.Now())
}

func runFilter(factory tcpassembly.StreamFactory, iface string, snaplen int32, filter string, ch chan os.Signal) {
	handle, err := pcap.OpenLive(iface, snaplen, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	if err := handle.SetBPFFilter(filter); err != nil {
		panic(err)
	}

	streamPool := tcpassembly.NewStreamPool(factory)
	assembler := tcpassembly.NewAssembler(streamPool)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

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
			assembler.FlushOlderThan(time.Now().Add(-2 * time.Minute))
		case <-ch:
			return
		}
	}
}

func main() {
	flag.Parse()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, os.Kill)

	reqPool := &requestPool{
		inFlight: make(IpHash),
	}

	srcFactory := &srcStreamFactory{pool: reqPool}
	srcCh := make(chan os.Signal)
	go runFilter(srcFactory, *iface, int32(*snaplen), *srcFilter, srcCh)

	dstFactory := &dstStreamFactory{pool: reqPool}
	dstCh := make(chan os.Signal)
	go runFilter(dstFactory, *iface, int32(*snaplen), *dstFilter, dstCh)

	ticker := time.Tick(time.Second)
	for {
		select {
		case <-ticker:
			reqPool.RemoveInFlight()
		case sig := <-ch:
			srcCh <- sig
			dstCh <- sig
			return
		}
	}
}
